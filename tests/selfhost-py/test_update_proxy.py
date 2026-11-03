"""Release downloads ignore inherited proxy routing, using the real curl transport."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from chronicle_ops.update import curl


class UpdateProxyIsolationTests(unittest.TestCase):
    def test_release_download_bypasses_a_working_inherited_proxy(self):
        class Endpoint(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.requests.append(self.path)
                self.send_response(200)
                self.send_header('Content-Length', str(len(self.server.payload)))
                self.end_headers()
                self.wfile.write(self.server.payload)

            def log_message(self, *_args):
                pass

        def endpoint(payload):
            server = ThreadingHTTPServer(('127.0.0.1', 0), Endpoint)
            server.payload, server.requests = payload, []
            self.addCleanup(server.server_close)
            threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True).start()
            self.addCleanup(server.shutdown)
            return server, 'http://127.0.0.1:' + str(server.server_port)

        target, target_url = endpoint(b'direct-catalog')
        proxy, proxy_url = endpoint(b'proxy-catalog')
        real_curl = shutil.which('curl')
        self.assertIsNotNone(real_curl, 'curl is required by the release downloader')
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            'HOME': folder, 'CURL_HOME': folder, 'XDG_CONFIG_HOME': folder,
            'http_proxy': proxy_url, 'https_proxy': proxy_url, 'all_proxy': proxy_url,
            'HTTP_PROXY': proxy_url, 'HTTPS_PROXY': proxy_url, 'ALL_PROXY': proxy_url,
            'NO_PROXY': '', 'no_proxy': '',
        }):
            control = subprocess.run([real_curl, '-q', '--noproxy', '', '--proxy', proxy_url,
                                      '--max-time', '5', '--silent', '--show-error', target_url + '/catalog'],
                                     capture_output=True, check=True, timeout=10)
            self.assertEqual(b'proxy-catalog', control.stdout)
            self.assertEqual([target_url + '/catalog'], proxy.requests)
            proxy.requests.clear()
            self.assertEqual(b'direct-catalog', curl(target_url + '/catalog'))
            self.assertEqual(['/catalog'], target.requests)
            self.assertEqual([], proxy.requests)


if __name__ == '__main__':
    unittest.main()
