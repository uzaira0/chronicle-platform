"""Fresh dashboard certificates work with the deployment client's strict TLS validation."""
import http.server
import importlib.util
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

from selfhost_fixture import run_cert_init

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('selfhost_client', ROOT / 'tests/deployment/selfhost-client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class ClientTlsTests(unittest.TestCase):
    def test_fresh_dashboard_chain_passes_strict_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            tls = Path(folder) / 'tls'
            tls.mkdir()
            result = run_cert_init(tls, timeout=30)
            self.assertEqual(0, result.returncode, result.stderr)
            older_default = ssl.create_default_context(cafile=tls / 'internal-ca.crt')
            older_default.verify_flags &= ~ssl.VERIFY_X509_STRICT
            with patch.object(client.ssl, 'create_default_context', return_value=older_default):
                context = client.tls_context(tls / 'internal-ca.crt')
            self.assertTrue(context.verify_flags & ssl.VERIFY_X509_STRICT)
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(tls / 'internal-cert.pem', tls / 'internal-key.pem')
            server.socket = server_context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            import socket
            with socket.create_connection(server.server_address) as connection:
                with context.wrap_socket(connection, server_hostname='localhost') as secured:
                    self.assertIsNotNone(secured.getpeercert())
                    secured.sendall(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                    self.assertIn(b'501', secured.recv(4096))
