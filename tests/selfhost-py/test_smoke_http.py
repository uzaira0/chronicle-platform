"""Run the shipped smoke suite against HTTP replies without a deployment."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SmokeHttpTests(unittest.TestCase):
    def test_route_denials_keep_http_status_and_transport_errors_fail(self):
        class Handler(BaseHTTPRequestHandler):
            denial = 403

            def do_GET(self):
                code = self.denial if self.path in ('/datastore/', '/chronicle/datastore/', '/prometheus/') else 200
                self.send_response(code)
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as folder:
            commands = Path(folder)
            docker = commands / 'docker'
            docker.write_text('#!/bin/bash\nif [[ "$1" == ps ]]; then echo smoke-fixture; else exit 1; fi\n')
            docker.chmod(0o755)
            for status in (403, 404, 200):
                Handler.denial = status
                with self.subTest(status=status):
                    result = subprocess.run(['bash', str(ROOT / 'tests/security/smoke-tests.sh')],
                        env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                                 DOMAIN='127.0.0.1:' + str(server.server_port)),
                        capture_output=True, text=True, timeout=15)
                    self.assertEqual(1, result.returncode, result.stderr)
                    for route in ('/datastore/', '/chronicle/datastore/'):
                        if status in (403, 404):
                            self.assertIn(f'Blocked route {route} returns {status}', result.stdout)
                        else:
                            self.assertIn(f'Blocked route {route} is unproved', result.stdout)
            server.shutdown()
            server.server_close()
            result = subprocess.run(['bash', str(ROOT / 'tests/security/smoke-tests.sh')],
                env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                         DOMAIN='127.0.0.1:' + str(server.server_port)),
                capture_output=True, text=True, timeout=15)
            self.assertEqual(1, result.returncode, result.stderr)
            self.assertIn('Blocked route /datastore/ is unproved (HTTP 000)', result.stdout)
            self.assertIn('Backend metrics probe failed', result.stdout)
