"""The verifier capability stays on the configured origin and out of argv."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from chronicle_ops.ingress import VERIFY_HEADER, VERIFY_SCHEME, close_ingress, open_ingress
from chronicle_ops.verify import curl


class UpdateIngressTests(unittest.TestCase):
    def test_closed_fence_allows_internal_verification_without_leaking_redirect_credentials(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get(VERIFY_HEADER))
                self.send_response(302 if self.path == '/redirect' else 200)
                if self.path == '/redirect':
                    self.send_header('Location', destination)
                self.end_headers()
            def log_message(self, *_args):
                pass
        servers = [ThreadingHTTPServer(('127.0.0.1', 0), Handler) for _ in range(2)]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        origin = 'http://127.0.0.1:' + str(servers[0].server_port)
        destination = 'http://127.0.0.1:' + str(servers[1].server_port) + '/destination'
        initial = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / '.env').write_text('CHRONICLE_INTERNAL_WEB_SECRET=synthetic-private-verifier\n')
            try:
                os.chdir(state)
                with patch.dict(os.environ, CHRONICLE_OPS_STATE=str(state)):
                    self.assertEqual(0, curl(origin + '/open')[0])
                    self.assertEqual([None], received)
                    close_ingress(state)
                    self.assertEqual(0, curl(origin + '/redirect', '-L')[0])
                    self.assertEqual([None, VERIFY_SCHEME + ' synthetic-private-verifier', None], received)
                    with patch('chronicle_ops.verify.run', return_value=subprocess.CompletedProcess([], 0, 'ok')) as command:
                        curl(origin + '/internal')
                    self.assertNotIn('synthetic-private-verifier', str(command.call_args.args))
                    self.assertIn('synthetic-private-verifier', command.call_args.kwargs['input'])
                    open_ingress(state)
                    self.assertEqual(0, curl(origin + '/open')[0])
                    self.assertIsNone(received[-1])
            finally:
                os.chdir(initial)
