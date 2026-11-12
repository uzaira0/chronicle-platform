"""k6 steps must trust the per-run fixture CA on every host.

k6 is a Go program, and Go reads SSL_CERT_FILE only on Linux and the other Unix ports; on macOS it
verifies with the platform verifier and ignores the file. The 2026.11.12 release smoke ran on a Mac and its
upload race step failed every request with "x509: certificate is not trusted", while curl and Python, given
the same CA file, passed. tests/security/lib/k6-fixture-trust.sh runs the pinned Linux k6 on macOS; these
tests prove it trusts the fixture CA, still refuses a certificate from another CA, and that the race step
uses it with every variable the race script reads."""
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PKI = ROOT / 'tests/security/lib/fixture-pki.sh'
HELPER = ROOT / 'tests/security/lib/k6-fixture-trust.sh'
RUNNER = ROOT / 'tests/security/run-all-security.sh'
PROBE = '''import http from 'k6/http';
export const options = { iterations: 1, vus: 1 };
export default function () {
  const response = http.get(__ENV.PROBE_URL, { timeout: '20s' });
  console.log(`probe-status=${response.status} probe-error=${response.error}`);
}
'''


class TlsServer:
    """HTTPS server on 127.0.0.1 presenting directory/lb.crt for localhost; answers every request with 200."""

    def __init__(self, directory):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(directory / 'lb.crt', directory / 'lb.key')
        self.listener = socket.create_server(('127.0.0.1', 0))
        self.listener.settimeout(1)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except OSError:
                continue
            try:
                with self.context.wrap_socket(connection, server_side=True) as tls:
                    tls.settimeout(10)
                    tls.recv(65536)
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
            except (ssl.SSLError, OSError):
                pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stopped.set()
        self.thread.join(timeout=10)
        self.listener.close()


def issue(directory, name):
    subprocess.run(['bash', '-c', 'source "$1"; fixture_ca "$2" "$3" && fixture_leaf "$2" lb localhost',
                    'fixture-pki', str(PKI), str(directory), name], check=True, capture_output=True, timeout=60)


def run_probe(folder, ca, port, function=True):
    """k6 GET of the server through the helper (or plain `k6 run` when function is False); returns its output."""
    script = folder / 'probe.js'
    script.write_text(PROBE)
    call = 'k6_run_trusting_fixture_ca PROBE_URL -- -q "$2"' if function else 'k6 run -q "$2"'
    environment = dict(os.environ, SSL_CERT_FILE=str(ca), ROOT_DIR=str(folder), REPORT_DIR=str(folder),
                       PROBE_URL=f'https://localhost:{port}/')
    run = subprocess.run(['bash', '-c', 'source "$1"; ' + call, 'k6-probe', str(HELPER), str(script)],
                         check=False, env=environment, capture_output=True, text=True, timeout=600)
    return run.stdout + run.stderr


@unittest.skipUnless(shutil.which('k6'), 'k6 is required by the release smoke and local-ci; install it')
class K6FixtureTrustTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name).resolve()
        issue(self.folder, 'fixture-CA')
        self.other = self.folder / 'other'
        self.other.mkdir()
        issue(self.other, 'other-CA')

    def tearDown(self):
        self.temporary.cleanup()

    def probe(self, ca, function=True):
        with TlsServer(self.folder) as server:
            return run_probe(self.folder, ca, server.port, function)

    def test_k6_trusts_the_fixture_ca(self):
        output = self.probe(self.folder / 'ca.crt')
        self.assertIn('probe-status=200', output, output)

    def test_k6_refuses_a_certificate_from_another_ca(self):
        # Negative control: the helper adds the fixture CA; it does not turn verification off.
        output = self.probe(self.other / 'ca.crt')
        self.assertIn('probe-status=0', output, output)
        self.assertRegex(output, r'x509|certificate', output)

    @unittest.skipUnless(platform.system() == 'Darwin', 'the platform verifier that ignores SSL_CERT_FILE is macOS-only')
    def test_plain_k6_ignores_ssl_cert_file_on_macos(self):
        # Why the helper exists: what the race step ran before refuses the fixture CA here.
        output = self.probe(self.folder / 'ca.crt', function=False)
        self.assertIn('probe-status=0', output, output)
        self.assertIn('not trusted', output, output)

    def test_race_step_uses_the_helper_and_forwards_every_variable_the_script_reads(self):
        runner = RUNNER.read_text()
        step = runner[runner.index('"upload.races"'):]
        step = step[:step.index('\n}')]
        self.assertIn('k6_run_trusting_fixture_ca', step)
        self.assertNotRegex(step, r'(?m)^\s*k6 run\b')
        forwarded = set(re.search(r'k6_run_trusting_fixture_ca \\\n\s*"([^"]+)"', step).group(1).split())
        read = set()
        for script in ('tests/security/k6-race-conditions.js', 'tests/load/mobile-client.js'):
            read |= set(re.findall(r'__ENV\.([A-Z_][A-Z0-9_]*)', (ROOT / script).read_text()))
        self.assertEqual(set(), read - forwarded, 'the race script reads variables the container would not receive')


if __name__ == '__main__':
    unittest.main()
