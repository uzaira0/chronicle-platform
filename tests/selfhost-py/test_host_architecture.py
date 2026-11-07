"""Chronicle's release images are linux/amd64 only; on another daemon the launcher checks whether they run.

On a non-amd64 Docker daemon the launcher runs the bundled, digest-pinned Caddy image with
`--platform linux/amd64 --network none` and a no-op command. When it runs (Docker Desktop or OrbStack
on Apple silicon, or a Linux host with amd64 binfmt emulation), every command proceeds with a
warning that performance is emulated. Only when the daemon cannot run amd64 code at all (exec format
error) does a fresh `./chronicle setup` refuse and `./chronicle check` fail; `up` and `update` still
only warn, so an existing deployment is never stopped by this check. The architecture is the Docker
daemon's (`docker info --format {{.Architecture}}`), which is where the images run.
"""
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import test_host_memory
from chronicle_ops.common import run
from test_secret_generation import SelfhostSetupFixture

ROOT = Path(__file__).resolve().parents[2]
PROBE_IMAGE = 'ghcr.io/uzaira0/chronicle-selfhost-caddy:2026.11.6@sha256:' + '1' * 64
# Inserted into the bash docker fake of tests/security/lib/selfhost-fixtures.sh.
ARCHITECTURE_ANSWER = r'''elif [[ "$*" == 'info --format {{.Architecture}}' ]]; then
  printf '%s\n' "${DOCKER_FIXTURE_ARCH:-}"
elif [[ "${1:-}" == run && " $* " == *" --platform linux/amd64 "* ]]; then
  printf '%s\n' "$*" >>"${DOCKER_FIXTURE_PROBES:-/dev/null}"
  case "${DOCKER_FIXTURE_AMD64:-runs}" in
    runs) exit 0 ;;
    exec-format) echo 'exec /bin/true: exec format error' >&2; exit 255 ;;
    *) echo 'Error response from daemon: pull access denied' >&2; exit 125 ;;
  esac
'''
# Inserted into the Python docker fake of test_host_memory.LauncherMemoryTests.
PYTHON_ARCHITECTURE_ANSWER = '''elif args == ['info', '--format', '{{.Architecture}}']:
    print(os.environ['DOCKER_FIXTURE_ARCH'])
elif args[:1] == ['run'] and '--platform' in args:
    if os.environ['DOCKER_FIXTURE_AMD64'] != 'runs':
        sys.stderr.write('exec /bin/true: exec format error\\n')
        sys.exit(255)
'''


class ArchitectureProblemTests(unittest.TestCase):
    def test_only_a_known_non_amd64_daemon_is_a_problem(self):
        from chronicle_ops.host_versions import architecture_problem
        for arch in ('aarch64', 'arm64', 'armv7l', 'ppc64le', 's390x', 'riscv64'):
            with self.subTest(arch=arch):
                problem = architecture_problem(arch)
                self.assertIn(arch, problem)
                self.assertIn('linux/amd64', problem)
        for arch in ('x86_64', 'amd64', '', '/var/lib/docker', 'unknown'):
            with self.subTest(arch=arch):
                self.assertIsNone(architecture_problem(arch))


class AssessmentTests(unittest.TestCase):
    """host_versions.architecture_assessment with a recorded docker runner (docker is the seam)."""

    def assess(self, arch, probe_returncode=0, probe_stderr='', image=PROBE_IMAGE):
        from chronicle_ops import host_versions
        calls = []

        def runner(command, **_kwargs):
            calls.append(command)
            if command[:2] == ['docker', 'info']:
                return subprocess.CompletedProcess(command, 0, arch + '\n', '')
            return subprocess.CompletedProcess(command, probe_returncode, '', probe_stderr)
        with patch.dict(os.environ, CADDY_IMAGE=image):
            return host_versions.architecture_assessment(runner), calls

    def test_amd64_is_not_probed(self):
        assessment, calls = self.assess('x86_64')
        self.assertEqual((None, None), assessment)
        self.assertEqual(1, len(calls))

    def test_an_emulating_daemon_is_a_warning_naming_emulation(self):
        (level, message), calls = self.assess('aarch64')
        self.assertEqual('warn', level)
        self.assertIn('emulat', message)
        self.assertEqual(['docker', 'run', '--rm', '--pull', 'missing', '--platform', 'linux/amd64', '--network', 'none'],
                         calls[1][:9])
        self.assertEqual(PROBE_IMAGE, calls[1][-1])

    def test_only_an_exec_format_error_refuses(self):
        (level, message), _ = self.assess('aarch64', 255, 'exec /bin/true: exec format error')
        self.assertEqual('refuse', level)
        self.assertIn('cannot run linux/amd64', message)
        for returncode, stderr in ((125, 'pull access denied'), (125, 'Cannot connect to the Docker daemon')):
            with self.subTest(stderr=stderr):
                (level, message), _ = self.assess('aarch64', returncode, stderr)
                self.assertEqual('warn', level)
                self.assertIn('could not check', message)

    def test_no_pinned_image_is_a_warning_without_a_probe(self):
        (level, _), calls = self.assess('aarch64', image='__CHRONICLE_SELFHOST_CADDY_IMAGE__')
        self.assertEqual('warn', level)
        self.assertEqual(1, len(calls))


class ShippedReadmeTests(unittest.TestCase):
    def test_the_bundled_readme_states_the_amd64_images_and_the_emulation_rule(self):
        # The bundle ships selfhost/README.md, not the repository README (build-selfhost-release.py).
        readme = (ROOT / 'selfhost/README.md').read_text()
        requirements = readme[readme.index('## Requirements'):readme.index('### Supported hosts')]
        self.assertIn('published for `linux/amd64` only', requirements)
        self.assertIn('emulat', requirements)
        self.assertIn('cannot run amd64 images at all', requirements)


class SetupArchitectureTests(SelfhostSetupFixture):
    def setUp(self):
        super().setUp()
        docker = self.host.parent / 'bin/docker'
        text = docker.read_text()
        anchor = 'elif [[ "${1:-}" == run ]]; then'
        self.assertIn(anchor, text)
        docker.write_text(text.replace(anchor, ARCHITECTURE_ANSWER + anchor, 1))
        self.probes = self.host.parent / 'probes'

    def setup_on(self, arch, rerun=False, amd64='runs'):
        return run(['bash', str(ROOT / 'tests/security/lib/selfhost-fixtures.sh'), 'run-setup', str(self.host), str(rerun).lower()],
                   env=dict(self.environment, DOCKER_FIXTURE_ARCH=arch, DOCKER_FIXTURE_AMD64=amd64, CADDY_IMAGE=PROBE_IMAGE,
                            DOCKER_FIXTURE_PROBES=str(self.probes)),
                   capture=True, stderr=subprocess.PIPE, timeout=20)

    def test_fresh_setup_refuses_a_daemon_that_cannot_run_amd64_before_writing_anything(self):
        result = self.setup_on('aarch64', amd64='exec-format')
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('aarch64', result.stderr)
        self.assertIn('cannot run linux/amd64', result.stderr)
        self.assertFalse((self.host / '.env').exists())

    def test_fresh_setup_on_an_emulating_daemon_proceeds_with_a_warning(self):
        # Docker Desktop and OrbStack on Apple silicon run amd64 images under emulation; our drills did.
        result = self.setup_on('aarch64')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('emulat', result.stderr)
        self.assertTrue((self.host / '.env').exists())
        self.assertIn('--network none', self.probes.read_text())

    def test_fresh_setup_on_amd64_proceeds_without_a_probe(self):
        result = self.setup_on('x86_64')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn('linux/amd64', result.stderr)
        self.assertFalse(self.probes.exists())

    def test_resetup_of_an_existing_deployment_only_warns(self):
        self.assertEqual(0, self.setup_on('x86_64').returncode)
        result = self.setup_on('aarch64', rerun=True, amd64='exec-format')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('warning:', result.stderr)
        self.assertIn('aarch64', result.stderr)


class CheckArchitectureTests(SelfhostSetupFixture):
    def check_on(self, arch, amd64='runs'):
        meminfo = self.host.parent / 'meminfo'
        meminfo.write_text('MemTotal: 8000000 kB\n')
        test_host_memory.LauncherMemoryTests.install_host_tools(self, meminfo)
        docker = self.host.parent / 'bin/docker'
        text = docker.read_text()
        anchor = "elif args[:1] == ['info'] and '--format' in args:"
        self.assertIn(anchor, text)
        docker.write_text(text.replace(anchor, PYTHON_ARCHITECTURE_ANSWER + anchor, 1))
        # check runs on a written .env, whose pinned image the launcher exports over the environment.
        from chronicle_ops.envfile import set_env_values
        settings = self.host / '.env'
        settings.write_text(set_env_values(settings.read_text(), {'CADDY_IMAGE': PROBE_IMAGE}, require_existing=True))
        return run(['bash', str(self.host / 'chronicle'), 'check'],
                   env=dict(self.environment, DOCKER_FIXTURE_ARCH=arch, DOCKER_FIXTURE_AMD64=amd64, CADDY_IMAGE=PROBE_IMAGE),
                   capture=True, stderr=subprocess.PIPE, timeout=30)

    def test_check_fails_on_a_daemon_that_cannot_run_amd64_and_names_it(self):
        result = self.check_on('aarch64', amd64='exec-format')
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r'FAIL.*aarch64.*cannot run linux/amd64')

    def test_check_passes_with_a_warning_on_an_emulating_daemon(self):
        result = self.check_on('aarch64')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('emulat', result.stderr)

    def test_check_passes_on_amd64(self):
        result = self.check_on('x86_64')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


class UpArchitectureTests(unittest.TestCase):
    def test_up_preflight_only_warns_even_when_amd64_cannot_run(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            tools = Path(folder)
            (tools / 'docker').write_text('#!/bin/sh\n[ "$*" = "info --format {{.Architecture}}" ] && echo aarch64 && exit 0\n'
                                          'echo "exec /bin/true: exec format error" >&2\nexit 255\n')
            (tools / 'docker').chmod(0o755)
            script = (f'source {ROOT / "selfhost/chronicle"}\nPREFLIGHT_FAILED=0\n'
                      'preflight_architecture up; echo "status=$? failed=$PREFLIGHT_FAILED"\n')
            result = subprocess.run(['bash', '-c', script], cwd=ROOT / 'selfhost', capture_output=True, text=True, timeout=30,
                                    env=dict(os.environ, PATH=f'{tools}{os.pathsep}{os.environ["PATH"]}', CADDY_IMAGE=PROBE_IMAGE),
                                    check=False)
        self.assertIn('status=0 failed=0', result.stdout, result.stderr)
        self.assertIn('warning:', result.stderr)
        self.assertIn('aarch64', result.stderr)


if __name__ == '__main__':
    unittest.main()
