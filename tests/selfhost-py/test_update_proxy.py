"""Release downloads use the operator's inherited proxy and its no_proxy list, through the real curl."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from chronicle_ops.update import curl


class UpdateProxyIsolationTests(unittest.TestCase):
    def test_release_download_goes_through_the_inherited_proxy_and_honours_no_proxy(self):
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
        proxied = {'http_proxy': proxy_url, 'https_proxy': proxy_url, 'HTTPS_PROXY': proxy_url}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            'HOME': folder, 'CURL_HOME': folder, 'XDG_CONFIG_HOME': folder, **proxied,
            'all_proxy': '', 'ALL_PROXY': '', 'NO_PROXY': '', 'no_proxy': ''}):
            # A plain-HTTP fixture stands in for HTTPS: curl reads http_proxy for it as it reads
            # https_proxy/HTTPS_PROXY for the real https:// release URLs.
            self.assertEqual(b'proxy-catalog', curl(target_url + '/catalog'))
            self.assertEqual([target_url + '/catalog'], proxy.requests)
            self.assertEqual([], target.requests)
            proxy.requests.clear()
            with patch.dict(os.environ, {'no_proxy': '127.0.0.1'}):
                self.assertEqual(b'direct-catalog', curl(target_url + '/catalog'))
            self.assertEqual(['/catalog'], target.requests)
            self.assertEqual([], proxy.requests)


if __name__ == '__main__':
    unittest.main()
