"""scripts/check-image-listeners.sh starts each image on --network none and refuses undeclared listeners.

check-image-no-ssh-server.sh finds an SSH server by file name; a Go binary embedding one has no such
name. The fixtures are FROM scratch images holding one static Go program that listens where told
(and doubles as `cat`, so the check reads /proc/net/tcp with docker exec), so no registry pull.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / 'scripts' / 'check-image-listeners.sh'

PROGRAM = '''package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if filepath.Base(os.Args[0]) == "cat" {
		for _, name := range os.Args[1:] {
			if file, err := os.Open(name); err == nil {
				io.Copy(os.Stdout, file)
				file.Close()
			}
		}
		return
	}
	if len(os.Args) < 2 {
		return // exits at once, like an image that needs configuration
	}
	listener, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	defer listener.Close()
	time.Sleep(time.Hour)
}
'''


def docker_available():
    if not shutil.which('docker'):
        return False
    return subprocess.run(['docker', 'info'], capture_output=True, timeout=60).returncode == 0


@unittest.skipUnless(docker_available(), 'needs a running Docker daemon')
class ImageListenerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = Path(tempfile.mkdtemp(prefix='listener-guard-'))
        (cls.folder / 'main.go').write_text(PROGRAM)
        (cls.folder / 'go.mod').write_text('module listener\n\ngo 1.27.3\n')
        machine = subprocess.run(['docker', 'info', '--format', '{{.Architecture}}'], capture_output=True, text=True,
                                 check=True, timeout=60).stdout.strip()
        architecture = {'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine, 'amd64')
        subprocess.run(['go', 'build', '-o', str(cls.folder / 'listen'), '.'], cwd=cls.folder, check=True,
                       env=dict(os.environ, GOOS='linux', GOARCH=architecture, CGO_ENABLED='0'),
                       capture_output=True, timeout=600)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.folder, ignore_errors=True)

    def image(self, entrypoint, expose=()):
        context = self.folder / uuid.uuid4().hex
        context.mkdir()
        shutil.copy2(self.folder / 'listen', context / 'listen')
        lines = ['FROM scratch', 'COPY listen /listen', 'COPY listen /bin/cat',
                 *[f'EXPOSE {port}' for port in expose], 'ENTRYPOINT ' + str(entrypoint).replace("'", '"')]
        (context / 'Dockerfile').write_text('\n'.join(lines) + '\n')
        tag = 'chronicle-listener-guard-test:' + uuid.uuid4().hex
        subprocess.run(['docker', 'build', '-q', '-t', tag, str(context)], check=True, capture_output=True, timeout=300)
        self.addCleanup(subprocess.run, ['docker', 'image', 'rm', '-f', tag], capture_output=True, timeout=120)
        return tag

    def check(self, *images):
        return subprocess.run(['bash', str(CHECK), *images], capture_output=True, text=True, timeout=300,
                              env=dict(os.environ, CHRONICLE_LISTEN_WATCH='4'))

    def test_an_undeclared_listener_fails(self):
        image = self.image(['/listen', '0.0.0.0:2222'], expose=[8080])
        result = self.check(image)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn('listens on undeclared TCP port(s) 2222', result.stderr)

    def test_an_ipv6_wildcard_listener_counts_too(self):
        result = self.check(self.image(['/listen', '[::]:2222']))
        self.assertEqual(1, result.returncode, result.stderr)

    def test_a_declared_listener_passes(self):
        result = self.check(self.image(['/listen', '0.0.0.0:8080'], expose=[8080]))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('declared: 8080', result.stderr)

    def test_a_loopback_listener_is_reported_not_refused(self):
        result = self.check(self.image(['/listen', '127.0.0.1:2222']))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('loopback only: 2222', result.stderr)

    def test_an_image_that_exits_at_once_passes_and_says_so(self):
        result = self.check(self.image(['/listen']))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('exited before the watch ended', result.stderr)

    def test_one_bad_image_fails_the_whole_run(self):
        clean, dirty = self.image(['/listen']), self.image(['/listen', '0.0.0.0:2222'])
        result = self.check(clean, dirty)
        self.assertEqual(1, result.returncode, result.stderr)

    def test_the_image_gates_run_it_on_every_built_image_before_any_push(self):
        from chronicle_ops.images import SOURCE_IMAGES
        plan = subprocess.run(['bash', str(ROOT / 'scripts' / 'publish-images.sh'), '1.2.3', '--dry-run'],
                              check=True, capture_output=True, text=True, timeout=300).stdout.splitlines()
        checks = [index for index, line in enumerate(plan) if 'check-image-listeners.sh' in line]
        pushes = [index for index, line in enumerate(plan) if line.startswith('docker push ')]
        self.assertEqual(len(SOURCE_IMAGES), len(checks))
        self.assertLess(max(checks), min(pushes))
        gate = (ROOT / 'scripts/local-ci.sh').read_text()
        body = gate[gate.index('check-image-no-ssh-server.sh" "$tag"'):]
        self.assertIn('check-image-listeners.sh" "$tag" || image_failed=1', body.split('\n', 2)[1])


if __name__ == '__main__':
    unittest.main()
