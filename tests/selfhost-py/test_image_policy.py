"""scripts/check-image-policy.py: non-root USER, HEALTHCHECK, no setuid/setgid file and no build tool,
each unless config/image-policy.toml records why (container-infra checklist I1 and I3).

The fixtures are FROM scratch images, so the test needs a Docker daemon but no registry pull.
"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / 'scripts' / 'check-image-policy.py'


def docker_available():
    if not shutil.which('docker'):
        return False
    return subprocess.run(['docker', 'info'], capture_output=True, timeout=60).returncode == 0


class PolicyFileTests(unittest.TestCase):
    def test_every_shipped_image_has_a_policy_entry(self):
        sys.path.insert(0, str(ROOT / 'selfhost'))
        import tomllib
        from chronicle_ops.images import SOURCE_IMAGES, bundle_images
        policy = tomllib.loads((ROOT / 'config/image-policy.toml').read_text())['image']
        vendor = {image.split('@')[0].rsplit(':', 1)[0] for image in
                  bundle_images(ROOT / 'selfhost') - {source.placeholder for source in SOURCE_IMAGES}}
        expected = {source.component for source in SOURCE_IMAGES} | vendor
        self.assertEqual(expected, set(policy))
        for key, entry in policy.items():
            for field in ('root', 'healthcheck'):
                self.assertTrue(field not in entry or entry[field].strip(), (key, field))


@unittest.skipUnless(docker_available(), 'needs a running Docker daemon')
class ImagePolicyTests(unittest.TestCase):
    def image(self, dockerfile_lines, files=()):
        with tempfile.TemporaryDirectory(prefix='image-policy-') as folder:
            context = Path(folder)
            (context / 'payload').write_bytes(b'x')
            lines = ['FROM scratch', 'COPY --chmod=0755 payload /bin/service']
            lines += [f'COPY --chmod={mode} payload {path}' for path, mode in files]
            (context / 'Dockerfile').write_text('\n'.join(lines + list(dockerfile_lines)) + '\n')
            tag = 'chronicle-image-policy-test:' + uuid.uuid4().hex
            subprocess.run(['docker', 'build', '-q', '-t', tag, str(context)], check=True, capture_output=True, timeout=300)
        self.addCleanup(subprocess.run, ['docker', 'image', 'rm', '-f', tag], capture_output=True, timeout=120)
        return tag

    def check(self, policy, *pairs):
        with tempfile.TemporaryDirectory(prefix='image-policy-') as folder:
            path = Path(folder) / 'policy.toml'
            path.write_text(policy)
            return subprocess.run([sys.executable, str(CHECK), '--policy', str(path), *pairs],
                                  capture_output=True, text=True, timeout=300)

    GOOD = ['USER 10001:10001', 'HEALTHCHECK CMD ["/bin/service"]']

    def test_hardened_image_passes_with_an_empty_entry(self):
        result = self.check('[image.app]\n', 'app=' + self.image(self.GOOD))
        self.assertEqual(0, result.returncode, result.stderr)

    def test_root_without_a_reason_fails_and_with_one_passes(self):
        for user in ([], ['USER 0'], ['USER root:root']):
            with self.subTest(user=user):
                image = self.image(user + ['HEALTHCHECK CMD ["/bin/service"]'])
                result = self.check('[image.app]\n', 'app=' + image)
                self.assertEqual(1, result.returncode)
                self.assertIn('runs as root', result.stderr)
                self.assertEqual(0, self.check('[image.app]\nroot = "needs the docker socket"\n', 'app=' + image).returncode)

    def test_missing_healthcheck_needs_a_reason(self):
        image = self.image(['USER 10001'])
        self.assertIn('no HEALTHCHECK', self.check('[image.app]\n', 'app=' + image).stderr)
        self.assertEqual(0, self.check('[image.app]\nhealthcheck = "compose probes it"\n', 'app=' + image).returncode)

    def test_setid_files_and_build_tools_fail_unless_listed(self):
        image = self.image(self.GOOD, files=(('/usr/bin/su', '4755'), ('/usr/bin/write', '2755'), ('/usr/bin/make', '0755')))
        result = self.check('[image.app]\n', 'app=' + image)
        self.assertEqual(1, result.returncode)
        for path in ('usr/bin/su', 'usr/bin/write'):
            self.assertIn(f'setuid/setgid file {path}', result.stderr)
        self.assertIn('build tool usr/bin/make', result.stderr)
        allowed = ('[image.app]\n[image.app.setid]\n"usr/bin/su" = "r"\n"usr/bin/write" = "r"\n'
                   '[image.app.tools]\n"usr/bin/make" = "r"\n')
        self.assertEqual(0, self.check(allowed, 'app=' + image).returncode)

    def test_an_allowance_the_image_no_longer_needs_is_stale(self):
        image = self.image(self.GOOD)
        for policy in ('[image.app]\nroot = "r"\n', '[image.app]\nhealthcheck = "r"\n',
                       '[image.app]\n[image.app.setid]\n"usr/bin/su" = "r"\n',
                       '[image.app]\n[image.app.tools]\n"usr/bin/make" = "r"\n'):
            with self.subTest(policy=policy):
                result = self.check(policy, 'app=' + image)
                self.assertEqual(1, result.returncode)
                self.assertIn('stale', result.stderr)

    def test_unknown_policy_key_fails(self):
        self.assertIn('no entry', self.check('[image.other]\n', 'app=' + self.image(self.GOOD)).stderr)


if __name__ == '__main__':
    unittest.main()
