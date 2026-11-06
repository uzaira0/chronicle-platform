"""scripts/check-image-no-ssh-server.sh rejects images that carry an SSH server.

The fixtures are FROM scratch images, so the test needs a Docker daemon but no registry pull.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / 'scripts' / 'check-image-no-ssh-server.sh'


def docker_available():
    if not shutil.which('docker'):
        return False
    return subprocess.run(['docker', 'info'], capture_output=True, timeout=60).returncode == 0


@unittest.skipUnless(docker_available(), 'needs a running Docker daemon')
class ImageSshGuardTests(unittest.TestCase):
    def image_with(self, *paths):
        """Build a scratch image containing an empty file at each path; removed after the test."""
        with tempfile.TemporaryDirectory(prefix='ssh-guard-') as folder:
            context = Path(folder)
            for path in paths:
                (context / 'root' / path).parent.mkdir(parents=True, exist_ok=True)
                (context / 'root' / path).write_bytes(b'')
            (context / 'Dockerfile').write_text('FROM scratch\nCOPY root/ /\n')
            tag = 'chronicle-ssh-guard-test:' + uuid.uuid4().hex
            subprocess.run(['docker', 'build', '-q', '-t', tag, str(context)],
                           check=True, capture_output=True, timeout=300)
        self.addCleanup(subprocess.run, ['docker', 'image', 'rm', '-f', tag], capture_output=True, timeout=120)
        return tag

    def check(self, *images):
        return subprocess.run(['bash', str(CHECK), *images], capture_output=True, text=True, timeout=300)

    def test_image_without_ssh_server_passes(self):
        # An sshd_config or an ssh client alone is not a server.
        image = self.image_with('usr/bin/env', 'etc/ssh/sshd_config', 'usr/bin/ssh')
        result = self.check(image)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_ssh_server_binary_fails(self):
        for path in ('usr/sbin/sshd', 'usr/lib/ssh/sshd-session', 'usr/libexec/sshd-auth',
                     'usr/sbin/dropbear', 'usr/bin/dropbearmulti'):
            with self.subTest(path=path):
                image = self.image_with('usr/bin/env', path)
                result = self.check(image)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(path, result.stderr)

    def test_one_bad_image_fails_the_whole_run(self):
        clean, dirty = self.image_with('usr/bin/env'), self.image_with('usr/sbin/sshd')
        result = self.check(clean, dirty)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('no SSH server in ' + clean, result.stderr)

    def test_publish_checks_every_built_image_before_any_push(self):
        from chronicle_ops.images import SOURCE_IMAGES
        plan = subprocess.run(['bash', str(ROOT / 'scripts' / 'publish-images.sh'), '1.2.3', '--dry-run'],
                              check=True, capture_output=True, text=True, timeout=300).stdout.splitlines()
        checks = [index for index, line in enumerate(plan) if 'check-image-no-ssh-server.sh' in line]
        pushes = [index for index, line in enumerate(plan) if line.startswith('docker push ')]
        self.assertEqual(len(checks), len(SOURCE_IMAGES))
        self.assertLess(max(checks), min(pushes))


if __name__ == '__main__':
    unittest.main()
