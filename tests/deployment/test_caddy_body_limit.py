"""Exercise the shipped edge with an upstream that rejects declared oversize early.

Run with SELFHOST_CADDY_TEST_IMAGE set to the candidate digest and
CADDY_BODY_TEST_LOG_DIR set to a private evidence directory.
"""

import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import threading
import time
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]

UPLOAD_CONTRACT = yaml.safe_load((ROOT / "ontology/chronicle.linkml.yaml").read_text())["constants"]
BODY_LIMIT = UPLOAD_CONTRACT["MAX_REQUEST_SIZE_BYTES"]["value"]
BODY_DEADLINE_SECONDS = UPLOAD_CONTRACT["UPLOAD_BODY_TIMEOUT_SECONDS"]["value"]


def request_body_limits(config):
    if isinstance(config, list):
        return [limit for entry in config for limit in request_body_limits(entry)]
    if isinstance(config, dict):
        if config.get('handler') == 'request_body':
            return [config['max_size']]
        return [limit for entry in config.values() for limit in request_body_limits(entry)]
    return []


def adapt_caddy_config(config, snippets, image):
    result = subprocess.run(['docker', 'run', '--rm', '--read-only', '--network', 'none',
        '-e', 'DOMAIN=chronicle.example.test',
        '-v', f'{config}:/etc/caddy/Caddyfile:ro',
        '-v', f'{snippets}:/etc/caddy/snippets.caddy:ro', '--entrypoint', 'caddy', image,
        'adapt', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'],
        check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


class DuplicateLengthProxy(socketserver.StreamRequestHandler):
    """Append an HPACK literal: curl coalesces repeated Content-Length options.

    RFC 7541 §6.2.2 permits literals without indexing after curl's encoded fields.
    Responses pass through so curl still validates and decodes the HTTP/2 exchange.
    """

    def handle(self):
        with socket.create_connection(('127.0.0.1', self.server.upstream_port), timeout=15) as upstream:
            upstream.sendall(self.rfile.read(24))  # HTTP/2 client connection preface.
            threading.Thread(target=self.forward_frames, args=(upstream,), daemon=True).start()
            while data := upstream.recv(65536):
                self.request.sendall(data)

    def forward_frames(self, upstream):
        try:
            while header := self.rfile.read(9):
                payload = self.rfile.read(int.from_bytes(header[:3], 'big'))
                if header[3] == 1:  # HEADERS; these small requests fit a single header block.
                    if not header[4] & 4:
                        raise AssertionError('fixture requires END_HEADERS')
                    value = self.server.length.encode('ascii')
                    payload += b'\x00\x0econtent-length' + bytes([len(value)]) + value
                    header = len(payload).to_bytes(3, 'big') + header[3:]
                upstream.sendall(header + payload)
        finally:
            upstream.shutdown(socket.SHUT_WR)


class EarlyRejectingUpstream(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.reply(200)

    def do_POST(self):
        if self.path == '/disconnect':
            self.close_connection = True
            return
        length = int(self.headers.get('Content-Length', 0))
        received = 0
        status = 413 if length > BODY_LIMIT else 200
        try:
            if self.headers.get('Transfer-Encoding') == 'chunked':
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return  # The edge closes the upstream stream at its byte ceiling.
                    size = int(line.strip(), 16)
                    if not size:
                        break
                    received += len(self.rfile.read(size))
                    self.rfile.read(2)
                self.rfile.readline()
            elif status == 200:
                received = len(self.rfile.read(length))
        finally:
            self.server.received.append((self.path, received))
        self.reply(status)

    def reply(self, status):
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    def log_message(self, *args):
        pass


@unittest.skipUnless(os.environ.get('SELFHOST_CADDY_TEST_IMAGE'), 'set SELFHOST_CADDY_TEST_IMAGE')
class CaddyBodyLimitTests(unittest.TestCase):
    def setUp(self):
        self.evidence = Path(os.environ['CADDY_BODY_TEST_LOG_DIR'])
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.evidence.chmod(0o755)
        shutil.copy2(ROOT / 'selfhost/caddy/snippets.caddy', self.evidence / 'snippets.caddy')
        self.upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), EarlyRejectingUpstream)
        self.upstream.received = []
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            self.port = reservation.getsockname()[1]
        (self.evidence / 'Caddyfile').write_text(f'''import /fixture/snippets.caddy
{{
    admin off
    auto_https off
    order rate_limit before basic_auth
    servers {{
        protocols h1 h2c
    }}
}}
http://127.0.0.1:{self.port} {{
    # Exercise the matcher's joined representation even when the transport coalesces duplicates.
    @joinedLength path /joined-*
    request_header @joinedLength +Content-Length {{http.request.header.Content-Length}}
    import chronicle_common
    route {{
        reverse_proxy 127.0.0.1:{self.upstream.server_port}
    }}
}}
''')
        (self.evidence / 'Caddyfile').chmod(0o644)
        self.container = f'chronicle-ah-body-{os.getpid()}'
        subprocess.run(['docker', 'run', '-d', '--name', self.container, '--network', 'host',
                        '--read-only', '--tmpfs', '/config', '--tmpfs', '/data',
                        '-v', f'{self.evidence}:/fixture:ro', '--entrypoint', 'caddy',
                        os.environ['SELFHOST_CADDY_TEST_IMAGE'], 'run', '--config', '/fixture/Caddyfile'],
                       check=True, capture_output=True)
        self.addCleanup(self.stop_caddy)
        for _ in range(50):
            probe = subprocess.run(['curl', '-fsS', '--max-time', '1',
                                    f'http://127.0.0.1:{self.port}/health'], capture_output=True)
            if probe.returncode == 0:
                break
            time.sleep(.1)
        else:
            self.fail('Caddy did not become ready')

    def stop_caddy(self):
        logs = subprocess.run(['docker', 'logs', self.container], check=True, capture_output=True, text=True)
        (self.evidence / 'caddy.log').write_text(logs.stdout + logs.stderr)
        (self.evidence / 'upstream.txt').write_text(repr(self.upstream.received) + '\n')
        subprocess.run(['docker', 'rm', '-fv', self.container], check=True, capture_output=True)
        self.assertNotIn('type conversion error', logs.stdout + logs.stderr)

    def upload(self, case, size, *, framing='length', expect=False):
        payload = self.evidence / 'payload'
        payload.write_bytes(b'x' * size)
        headers = ['-H', 'Expect: 100-continue' if expect else 'Expect:']
        if framing == 'chunked':
            headers += ['-H', 'Transfer-Encoding: chunked']
        result = subprocess.run(['curl', '-sS', '--max-time', '15', '-o', '/dev/null',
                                 '-w', '%{http_code}', *headers, '--data-binary', f'@{payload}',
                                 f'http://127.0.0.1:{self.port}/{case}'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        print(f'{case}: status={result.stdout}', flush=True)
        return int(result.stdout)

    def assert_listener_deadlines(self):
        configs = sorted((ROOT / 'selfhost').glob('Caddyfile*'))
        self.assertTrue(configs, 'no shipped Caddy listeners found')
        for config in configs:
            with self.subTest(config=config.name):
                adapted = adapt_caddy_config(config, self.evidence / 'snippets.caddy',
                                             os.environ['SELFHOST_CADDY_TEST_IMAGE'])
                (self.evidence / (config.name + '.json')).write_text(json.dumps(adapted, indent=2))
                sizes = request_body_limits(adapted)
                self.assertTrue(sizes, 'listener has no request_body limit')
                self.assertTrue(all(size == BODY_LIMIT for size in sizes), sizes)
                servers = adapted['apps']['http']['servers']
                self.assertTrue(servers)
                for name, server in servers.items():
                    deadline = server.get('read_timeout', 0) / 1_000_000_000
                    self.assertGreater(deadline, 0, name)
                    self.assertEqual(deadline, BODY_DEADLINE_SECONDS,
                                     'listeners must apply the shared whole-body deadline')

    def test_declared_and_streaming_limits(self):
        self.assert_listener_deadlines()
        for attempt in range(20):
            with self.subTest(no_expect=attempt + 1):
                self.assertEqual(self.upload(f'declared-{attempt}', BODY_LIMIT + 1), 413)
        self.assertEqual(self.upload('expect', BODY_LIMIT + 1, expect=True), 413)
        self.assertEqual(self.upload('chunked-oversize', BODY_LIMIT + 1, framing='chunked'), 413)
        deadline = time.monotonic() + 3
        while not any(path == '/chunked-oversize' for path, _ in self.upstream.received):
            self.assertLess(time.monotonic(), deadline, 'upstream did not record the bounded chunked stream')
            time.sleep(.01)
        for framing in ('length', 'chunked'):
            self.assertEqual(self.upload(f'{framing}-at-limit', BODY_LIMIT, framing=framing), 200)
            self.assertEqual(self.upload(f'{framing}-small', 2, framing=framing), 200)
        self.assertEqual(self.upload('disconnect', 2), 502)
        self.assertFalse(any(path.startswith('/declared-') or path == '/expect'
                             for path, _ in self.upstream.received), 'declared oversize reached upstream')
        self.assertTrue(all(size <= BODY_LIMIT for _, size in self.upstream.received),
                        'oversized body reached upstream')

    def test_http2_content_lengths(self):
        proxy = socketserver.ThreadingTCPServer(('127.0.0.1', 0), DuplicateLengthProxy)
        proxy.daemon_threads = True
        proxy.upstream_port = self.port
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        self.addCleanup(proxy.server_close)
        self.addCleanup(proxy.shutdown)
        for case, length, copies, expected in (
                ('duplicate-oversize', BODY_LIMIT + 1, 2, 413),
                ('single-oversize', BODY_LIMIT + 1, 1, 413),
                ('small', 2, 1, 200),
                ('duplicate-small', 2, 2, 200),
                ('joined-oversize', BODY_LIMIT + 1, 2, 413),
                ('joined-small', 2, 2, 200),
                ('overflow', 10**19, 1, 413)):
            with self.subTest(case=case):
                proxy.length = str(length)
                port = proxy.server_address[1] if copies == 2 else self.port
                headers = ['-H', f'Content-Length: {length}', '-H', 'Expect: 100-continue']
                result = subprocess.run(['curl', '--http2-prior-knowledge', '-sS', '--max-time', '15',
                    '--trace-ascii', str(self.evidence / (case + '.trace')),
                    '-o', '/dev/null', '-w', '%{http_code} %{http_version}', *headers,
                    '--data-binary', 'xx', f'http://127.0.0.1:{port}/{case}'],
                    check=True, capture_output=True, text=True)
                print(f'h2 {case}: {result.stdout}', flush=True)
                self.assertEqual(f'{expected} 2', result.stdout)


if __name__ == '__main__':
    unittest.main()
