"""Runtime proof: a real self-host project, started from this checkout, cannot send data out.

Starts a disposable project (egress_stack.py), runs tests/security/selfhost-egress.sh against
it, and removes the project and its volumes. Runs whenever Docker answers; the first run
builds the first-party images it needs (tagged :egress-test-<input digest>).

CaddyStaplingTests runs the release Caddy image with each mode's Caddyfile against a real OCSP
responder: own-tls staples, the other modes do not.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock
import uuid

import egress_stack

ROOT = Path(__file__).resolve().parents[2]


def docker_available():
    try:
        return subprocess.run(['docker', 'info'], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class EgressImageBuildTests(unittest.TestCase):
    """The proof runs the images a release ships: built for toolchain-manifest.yaml's release_platform
    (the backend builder's apt pins exist only in the amd64 snapshot; Dockerfile.fluentbit unpacks amd64
    libraries), and rebuilt when anything the Dockerfile reads changes, a bind-mounted helper included."""

    def test_every_build_is_for_the_release_platform(self):
        commands = []

        def run(command, **_kwargs):
            if command[:2] == ['docker', 'build']:
                commands.append(command)
            return subprocess.CompletedProcess(command, 0, b'', b'')

        with unittest.mock.patch.object(egress_stack, 'image_exists', lambda _tag: False), \
                unittest.mock.patch.object(egress_stack.subprocess, 'run', run):
            egress_stack.images(ROOT, only=('backend', 'caddy', 'fluentbit'))
        self.assertEqual(['backend', 'frontend', 'caddy', 'fluentbit'],
                         [c[c.index('-t') + 1].split(':')[0].removeprefix('chronicle-selfhost-') for c in commands])
        for command in commands:
            self.assertEqual('linux/amd64', command[command.index('--platform') + 1], command)

    def test_a_changed_os_package_helper_changes_the_tag(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)
            for relative in ('selfhost/Dockerfile.grafana', 'selfhost/os-packages/apk-install-aged.sh', 'toolchain-manifest.yaml'):
                (source / relative).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, source / relative)
            before = egress_stack.inputs_digest(source, 'grafana')
            helper = source / 'selfhost/os-packages/apk-install-aged.sh'
            helper.write_text(helper.read_text() + '# changed\n')
            self.assertNotEqual(before, egress_stack.inputs_digest(source, 'grafana'))


@unittest.skipUnless(docker_available(), 'Docker is not available')
class EgressRuntimeTests(unittest.TestCase):
    def test_running_project_has_no_route_out_and_its_internal_paths_work(self):
        project = 'chronicle-egress-proof-' + uuid.uuid4().hex[:10]
        run_dir = ROOT / 'build/operator-test-runs/egress' / project
        run_dir.mkdir(parents=True)
        log_path = run_dir / 'stack.log'
        try:
            with log_path.open('a') as log:
                status = egress_stack.up(run_dir, ROOT, project, log=log)
            self.assertEqual(0, status, 'stack did not start; see ' + str(log_path))
            proof = subprocess.run(['bash', str(ROOT / 'tests/security/selfhost-egress.sh'), project],
                                   capture_output=True, text=True, timeout=900)
            (run_dir / 'proof.txt').write_text(proof.stdout + proof.stderr)
            self.assertEqual(0, proof.returncode, proof.stdout + proof.stderr)
            self.assertIn('egress proof: PASS', proof.stdout)
        finally:
            with log_path.open('a') as log:
                egress_stack.down(run_dir, project, log=log)
            # Volumes are gone with the project; the bundle copy holds the synthetic .env.
            shutil.rmtree(run_dir / 'selfhost', ignore_errors=True)


CERTIFICATES = r'''set -eu
cd /work
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=fixture-ca -days 2 \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign,digitalSignature \
  -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=chronicle.example.org \
  -keyout key.pem -out leaf.csr 2>/dev/null
printf '%s\n' 'subjectAltName=DNS:chronicle.example.org' 'extendedKeyUsage=serverAuth' \
  'authorityInfoAccess=OCSP;URI:http://ocsp.chronicle.test:8888' > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile leaf.ext -out leaf.pem 2>/dev/null
cat leaf.pem ca.pem > cert.pem
cp cert.pem internal-cert.pem
cp key.pem internal-key.pem
serial="$(openssl x509 -in leaf.pem -noout -serial | cut -d= -f2)"
printf 'V\t991231235959Z\t\t%s\tunknown\t/CN=chronicle.example.org\n' "$serial" > index.txt
chmod 0644 ./*
'''


@unittest.skipUnless(docker_available(), 'Docker is not available')
class CaddyStaplingTests(unittest.TestCase):
    """web has no route to the CA in any mode and staples nothing, even with an OCSP responder on its
    network (docs/NETWORK-EGRESS.md, "Web"): Caddyfile.split.tls turns stapling off."""

    @classmethod
    def setUpClass(cls):
        cls.images = egress_stack.images(ROOT, only=('caddy', 'postgres'))
        cls.name = 'chronicle-ocsp-' + uuid.uuid4().hex[:10]
        cls.work = ROOT / 'build/operator-test-runs/ocsp' / cls.name
        cls.work.mkdir(parents=True)
        (cls.work / 'make.sh').write_text(CERTIFICATES)
        cls.docker('network', 'create', cls.name)
        cls.docker('run', '--rm', '--network', 'none', '--user', f'{os.getuid()}:{os.getgid()}', '-v', f'{cls.work}:/work',
                   '--entrypoint', 'bash', cls.images['POSTGRES_IMAGE'], '/work/make.sh')
        cls.docker('run', '-d', '--name', cls.name + '-ocsp', '--network', cls.name, '--network-alias', 'ocsp.chronicle.test',
                   '--user', f'{os.getuid()}:{os.getgid()}', '-v', f'{cls.work}:/work:ro', '--entrypoint', 'openssl',
                   cls.images['POSTGRES_IMAGE'], 'ocsp', '-index', '/work/index.txt', '-port', '8888',
                   '-rsigner', '/work/ca.pem', '-rkey', '/work/ca.key', '-CA', '/work/ca.pem')

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['docker', 'rm', '-f', cls.name + '-ocsp', cls.name + '-caddy'], capture_output=True, timeout=60)
        subprocess.run(['docker', 'network', 'rm', cls.name], capture_output=True, timeout=60)
        shutil.rmtree(cls.work, ignore_errors=True)

    @staticmethod
    def docker(*arguments, check=True):
        return subprocess.run(['docker', *arguments], capture_output=True, text=True, timeout=300, check=check)

    def staple(self, mode, caddyfile, port, **settings):
        """The `openssl s_client -status` verdict for port after Caddy has loaded the certificate."""
        import test_egress
        environment = test_egress.render(mode)['services']['web']['environment']
        environment.update(settings)
        self.docker('rm', '-f', self.name + '-caddy', check=False)
        self.docker('run', '-d', '--name', self.name + '-caddy', '--network', self.name, '--network-alias', 'web',
                    '--read-only', '--tmpfs', '/data:mode=1777', '--tmpfs', '/config:mode=1777', '--tmpfs', '/tmp:mode=1777',
                    *[part for key, value in environment.items() for part in ('-e', f'{key}={value}')],
                    '-v', f'{ROOT / "selfhost" / caddyfile}:/etc/caddy/Caddyfile:ro',
                    '-v', f'{ROOT / "selfhost/caddy/snippets.caddy"}:/etc/caddy/snippets.caddy:ro',
                    '-v', f'{self.work}:/etc/caddy/certs:ro',
                    # The backend trust anchor web's reverse_proxy loads; no backend runs here.
                    '-v', f'{self.work / "ca.pem"}:/etc/caddy/backend-tls/backend.crt:ro', self.images['CADDY_IMAGE'])
        verdict, answered = '', 0
        # Caddy fetches the response when it loads the certificate; a mode that staples shows it
        # within seconds, and one that does not keeps answering without it.
        for _ in range(30):
            result = self.docker('run', '--rm', '--network', self.name, '--entrypoint', 'bash', self.images['POSTGRES_IMAGE'],
                                 '-c', f'openssl s_client -connect web:{port} -servername chronicle.example.org -status '
                                       '</dev/null 2>&1', check=False)
            verdict = next((line.strip() for line in result.stdout.splitlines()
                            if 'OCSP Response Status' in line or 'OCSP response: no response sent' in line), '')
            answered += bool(verdict)
            if 'successful' in verdict or answered >= 6:
                break
            time.sleep(2)
        logs = self.docker('logs', self.name + '-caddy', check=False)
        return verdict, logs.stdout + logs.stderr

    def test_no_mode_staples(self):
        # The test network routes to the OCSP responder, so own-TLS staples nothing only because
        # Caddyfile.split.tls says so, not because the fetch failed.
        for mode, caddyfile, port, settings in (
                ('overlays/mode-own-tls-internal.yml', 'Caddyfile.split.tls', 443, {}),
                ('overlays/mode-behind-proxy-internal.yml', 'Caddyfile.split', 8080, {'POOL_LISTENER_TLS': 'true'}),
                ('overlays/mode-local-https.yml', 'Caddyfile.split.local', 8081, {'POOL_LISTENER_TLS': 'true'})):
            with self.subTest(mode=mode):
                verdict, logs = self.staple(mode, caddyfile, port, **settings)
                self.assertEqual('OCSP response: no response sent', verdict, logs[-3000:])


if __name__ == '__main__':
    unittest.main()
