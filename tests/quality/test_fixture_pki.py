"""Test certificates must pass strict X.509 verification.

Python 3.13+ verifies with ssl.VERIFY_X509_STRICT by default and refuses a CA-signed leaf without an
Authority Key Identifier. The 2026.11.12 release smoke failed on exactly that: its load-balancer fixture
leaf was signed by `openssl x509 -req -extfile` with only subjectAltName, so the smoke's own client
(tests/deployment/selfhost-client.py) refused it. tests/security/lib/fixture-pki.sh issues those fixtures now,
and every other place that signs a certificate must set the identifier itself."""
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'tests/security/lib/fixture-pki.sh'
HOST = 'fixture.example.test'


def issue(directory, without_identifiers=False):
    """CA and server leaf for HOST in directory through the helper; optionally the pre-fix leaf."""
    script = 'source "$1"; fixture_ca "$2" fixture-CA && fixture_leaf "$2" lb "$3"'
    if without_identifiers:  # the extension file the smoke used before the fix
        script += ' && printf "subjectAltName=DNS:%s\\n" "$3" >"$2/old.ext" && openssl x509 -req -in "$2/lb.csr" ' \
                  '-CA "$2/ca.crt" -CAkey "$2/ca.key" -CAcreateserial -days 2 -extfile "$2/old.ext" -out "$2/lb.crt"'
    subprocess.run(['bash', '-c', script, 'fixture-pki', str(HELPER), str(directory), HOST],
                   check=True, capture_output=True, timeout=60)


def strict_handshake(directory):
    """TLS handshake of a strict client against a server presenting directory/lb.crt; returns the error or None."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(directory / 'lb.crt', directory / 'lb.key')
    client = ssl.create_default_context(cafile=str(directory / 'ca.crt'))
    client.verify_flags |= ssl.VERIFY_X509_STRICT
    with socket.create_server(('127.0.0.1', 0)) as listener:
        def serve():
            connection, _ = listener.accept()
            try:
                with server.wrap_socket(connection, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with socket.create_connection(listener.getsockname(), timeout=10) as raw, \
                 client.wrap_socket(raw, server_hostname=HOST):
                return None
        except ssl.SSLCertVerificationError as error:
            return error.verify_message
        finally:
            thread.join(timeout=10)


class FixturePkiTests(unittest.TestCase):
    def test_fixture_leaf_passes_a_strict_handshake(self):
        with tempfile.TemporaryDirectory() as folder:
            issue(Path(folder))
            self.assertIsNone(strict_handshake(Path(folder)))

    def test_a_leaf_without_an_authority_key_identifier_is_refused(self):
        # Negative control: the strict check is active, and the pre-fix fixture is what it refuses.
        with tempfile.TemporaryDirectory() as folder:
            issue(Path(folder), without_identifiers=True)
            self.assertIn('Authority Key Identifier', strict_handshake(Path(folder)) or '')

    def test_every_certificate_signing_site_sets_an_authority_key_identifier(self):
        tracked = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--', '*.sh', '*.py', '*.cfg', '*.cnf'],
                                 capture_output=True, text=True, check=True).stdout.split('\0')
        missing = []
        for name in filter(None, tracked):
            if name == 'tests/quality/test_fixture_pki.py':
                continue
            path = ROOT / name
            if not path.is_file():
                continue
            text = path.read_text(errors='replace')
            if ('x509 -req' in text or 'openssl ca ' in text) and 'authorityKeyIdentifier' not in text:
                missing.append(name)
        self.assertEqual([], missing, 'these files sign certificates without authorityKeyIdentifier')


if __name__ == '__main__':
    unittest.main()
