"""Host versions below the 2026 CVE minimums are warnings on every path and never fail a command:
an operator must always be able to run `./chronicle update`. The launcher cases run its preflight
step against compose_shim's fake `docker`; the update case runs the upgrade transaction."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import compose_shim

ROOT = Path(__file__).resolve().parents[2]
SERVER = '{{json .Server}}'
KERNEL = '{{.KernelVersion}}'
CURRENT = dict(engine='29.8.2', containerd='v2.2.10', runc='1.3.6', kernel='6.12.95')


def server(engine, containerd, runc):
    components = [{'Name': 'Engine', 'Version': engine}, {'Name': 'containerd', 'Version': containerd},
                  {'Name': 'runc', 'Version': runc}, {'Name': 'docker-init', 'Version': '0.19.0'}]
    return json.dumps({'Version': engine, 'Components': components})


class RuntimeVersionTests(unittest.TestCase):
    def preflight(self, **changes):
        host = dict(CURRENT, **changes)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            selfhost = root / 'selfhost'
            selfhost.mkdir()
            shutil.copy2(ROOT / 'selfhost/chronicle', selfhost / 'chronicle')
            (selfhost / 'chronicle_ops').symlink_to(ROOT / 'selfhost/chronicle_ops', target_is_directory=True)
            versions = {KERNEL: host['kernel']}
            if host['engine'] is not None:
                versions[SERVER] = server(host['engine'], host['containerd'], host['runc'])
            environment = dict(os.environ, **compose_shim.install(root / 'bin', versions=versions))
            result = subprocess.run(['bash', str(ROOT / 'tests/selfhost-py/chronicle_harness.sh'), str(selfhost),
                                     'runtime_versions'], env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(0, result.returncode, result.stderr)
        output = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout + result.stderr)
        return 'preflight-failed=1' in output, output

    def test_current_runtime_and_kernel_pass_without_a_warning(self):
        failed, output = self.preflight()
        self.assertFalse(failed, output)
        self.assertIn('Docker Engine 29.8.2', output)
        self.assertNotIn('warning', output)

    def test_newer_series_pass(self):
        failed, output = self.preflight(engine='30.0.1', containerd='2.5.0', runc='1.5.1', kernel='7.2.0')
        self.assertFalse(failed, output)
        self.assertNotIn('warning', output)

    def test_each_runtime_component_below_its_minimum_warns_and_never_fails(self):
        for changes, named, cve in ((dict(engine='29.8.1'), 'Docker Engine 29.8.1', 'CVE-2026-92543'),
                                    (dict(engine='27.5.1'), 'Docker Engine 27.5.1', 'CVE-2026-92543'),
                                    (dict(containerd='1.7.28'), 'containerd 1.7.28', 'CVE-2026-95837'),
                                    (dict(containerd='v2.3.6'), 'containerd v2.3.6', 'CVE-2026-95837'),
                                    (dict(containerd='2.1.4'), 'containerd 2.1.4', 'CVE-2026-95837'),
                                    (dict(runc='1.4.2'), 'runc 1.4.2', 'CVE-2026-41579'),
                                    (dict(runc='1.1.12'), 'runc 1.1.12', 'CVE-2026-41579')):
            with self.subTest(**changes):
                failed, output = self.preflight(**changes)
                self.assertFalse(failed, output)
                self.assertIn('warning: ' + named, output)
                self.assertIn(cve, output)
                self.assertIn('package manager', output)

    def test_containerd_message_says_the_old_line_has_no_fix(self):
        _, output = self.preflight(containerd='1.7.28')
        self.assertIn('2.2.10, 2.3.7 or 2.4.2', output)
        self.assertIn('1.7 line has no fix', output)

    def test_unreadable_runtime_versions_warn(self):
        failed, output = self.preflight(engine=None)
        self.assertFalse(failed, output)
        self.assertIn('could not read the Docker Engine version', output)

    def test_kernel_without_an_upstream_fix_warns_and_names_the_cves(self):
        for kernel in ('6.8.0-49-generic', '6.12.94', '6.1.176-1-cloud-amd64', '7.1.2'):
            with self.subTest(kernel=kernel):
                failed, output = self.preflight(kernel=kernel)
                self.assertFalse(failed, output)
                self.assertIn('warning', output)
                self.assertIn(kernel, output)
                self.assertIn('CVE-2026-31431', output)
                self.assertIn('CVE-2026-53362', output)
                self.assertIn('backport', output)

    def test_fixed_stable_kernels_pass(self):
        for kernel in ('6.1.177', '6.6.144-2.el9', '6.18.38', '7.1.3', '5.15.204'):
            with self.subTest(kernel=kernel):
                failed, output = self.preflight(kernel=kernel)
                self.assertFalse(failed, output)
                self.assertNotIn('warning', output)


if __name__ == '__main__':
    unittest.main()


class DocumentedMinimumTests(unittest.TestCase):
    """FB20: the minimums in host_versions.py are the ones the bundled README and the release notes state."""

    @staticmethod
    def dotted(versions):
        return ['.'.join(map(str, version)) for version in versions]

    def test_readme_requirements_state_every_minimum_in_the_code(self):
        from chronicle_ops import host_versions
        readme = (ROOT / 'selfhost/README.md').read_text()
        requirements = readme[readme.index('## Requirements'):readme.index('### Supported hosts')]
        for version in self.dotted(host_versions.ENGINE_FIXED + host_versions.CONTAINERD_FIXED
                                   + host_versions.RUNC_FIXED + host_versions.KERNEL_FIXED):
            with self.subTest(version=version):
                self.assertRegex(requirements, r'(?<![\d.])' + re.escape(version) + r'(?![\d])')
        for cve in re.findall(r'CVE-\d{4}-\d+', host_versions.KERNEL_CVES):
            self.assertIn(cve, requirements)

    def test_release_notes_state_the_runtime_minimums(self):
        from chronicle_ops import host_versions
        changelog = (ROOT / 'CHANGELOG.md').read_text()
        notes = changelog[changelog.index('## [2026.11.12]'):changelog.index('## [2026.11.2]')]
        for version in self.dotted(host_versions.ENGINE_FIXED + host_versions.CONTAINERD_FIXED + host_versions.RUNC_FIXED):
            with self.subTest(version=version):
                self.assertRegex(notes, r'(?<![\d.])' + re.escape(version) + r'(?![\d])')
        for cve in re.findall(r'CVE-\d{4}-\d+', host_versions.KERNEL_CVES):
            self.assertIn(cve, notes)
