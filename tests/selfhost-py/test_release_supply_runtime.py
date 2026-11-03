"""Release containment, monitoring startup and real sanitizer/cache regressions."""

import json
import signal
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.error import URLError
from urllib.request import urlopen

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ReleaseSupplyRuntimeTests(unittest.TestCase):
    def test_monitoring_certificates_start_without_application_dependencies(self):
        base = yaml.safe_load((ROOT / 'selfhost/docker-compose.yml').read_text())['services']
        overlay = yaml.safe_load((ROOT / 'selfhost/overlays/monitoring.yml').read_text())['services']
        services = {name: dict(service) for name, service in base.items()}
        for name, service in overlay.items():
            previous = services.get(name, {})
            services[name] = dict(previous, **service)
            services[name]['depends_on'] = dict(previous.get('depends_on', {}), **service.get('depends_on', {}))
        pending = ['grafana', 'victoriametrics', 'victorialogs', 'fluent-bit']
        dependencies = set()
        while pending:
            name = pending.pop()
            if name not in dependencies:
                dependencies.add(name)
                pending.extend(services[name].get('depends_on', {}))
        self.assertNotIn('config-guard', dependencies)
        self.assertNotIn('cert-init', dependencies)
        initializer = services['monitoring-cert-init']
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); tls = root / 'tls'; tls.mkdir()
            (tls / 'cert.pem').write_text('unusable public certificate')
            (tls / 'key.pem').write_text('unrelated public key')
            bin_dir = root / 'bin'; bin_dir.mkdir()
            chown = bin_dir / 'chown'; chown.write_text('#!/bin/sh\nexit 0\n'); chown.chmod(0o700)
            env = dict(os.environ, TLS_MODE='own-tls', DASHBOARD_EXPOSURE='internal',
                       DASHBOARD_SESSION_MINUTES='0')
            env.update(initializer['environment'])
            env.update(PATH=f"{bin_dir}:{os.environ['PATH']}", TLS_DIR=str(tls),
                       BACKEND_TLS_DIR=str(root / 'backend-tls'), MONITORING_TLS_DIR=str(root / 'monitoring-tls'),
                       SERVICE_CERTIFICATE_DIGEST_FILE=str(tls / 'monitoring-certificates.sha256'), GRAFANA_BIND='127.0.0.1', POSTGRES_TLS_DIR='')
            entrypoint = [part.replace('/selfhost/', str(ROOT / 'selfhost') + '/') for part in initializer['entrypoint']]
            result = subprocess.run(entrypoint, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            for directory, name in ((root / 'monitoring-tls', 'monitoring'), (root / 'backend-tls', 'backend')):
                cert = subprocess.check_output(['openssl', 'x509', '-in', str(directory / f'{name}.crt'), '-noout', '-pubkey'])
                key = subprocess.check_output(['openssl', 'pkey', '-in', str(directory / f'{name}.key'), '-pubout'])
                self.assertEqual(cert, key)
            self.assertEqual((tls / 'key.pem').read_text(), 'unrelated public key')
            self.assertEqual((tls / 'monitoring.crt').read_bytes(), (root / 'monitoring-tls/monitoring.crt').read_bytes())
            self.assertFalse((tls / 'monitoring.key').exists())

    def test_real_lua_sanitizer_preserves_audit_action_and_false(self):
        lua = next((shutil.which(name) for name in ('lua', 'lua5.4', 'lua5.3', 'luajit', 'texlua') if shutil.which(name)), None)
        if lua is None:
            self.skipTest('Lua interpreter unavailable')
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / 'audit.lua'
            script.write_text('''dofile(arg[1])
for _, event in ipairs({{action="LOGIN_FAILED", success=false}, {action="ACCESS_DENIED", success=false}, {action="EXPORT", success=true}}) do
  event.timestamp = "2026-10-12T00:00:00Z"
  event.userId = "private-user"
  event.ipAddress = "10.20.0.5"
  event.errorMessage = "private-error"
  local code, timestamp, out = sanitize("chronicle.audit", 123, event)
  assert(code == 1 and timestamp == 123)
  assert(out.operation == event.action, "audit action lost")
  assert(out.result == tostring(event.success), "audit outcome lost")
  assert(out.stream == "audit" and out.service == "audit")
  assert(out.timestamp == event.timestamp)
  assert(string.find(out.message, out.operation, 1, true))
  assert(string.find(out.message, out.result, 1, true))
  for _, value in pairs(out) do
    assert(not string.find(tostring(value), "private", 1, true))
    assert(value ~= event.ipAddress)
  end
end
local _, _, empty = sanitize("chronicle.backend", 123, {})
assert(empty.result == "" and empty.operation == "")
''')
            result = subprocess.run([lua, str(script), str(ROOT / 'selfhost/monitoring/sanitize.lua')],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_changed_css_is_revalidated_while_js_and_fonts_remain_immutable(self):
        # The shipped Caddy runtime image, pinned by the final FROM of Dockerfile.caddy; no host binary needed.
        image = [line.split()[1] for line in (ROOT / 'selfhost/Dockerfile.caddy').read_text().splitlines()
                 if line.startswith('FROM caddy:')][-1]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            snippets = ROOT / 'selfhost/caddy'
            caddy = ['docker', 'run', '--rm', '--network', 'host', '--memory=512m', '--memory-swap=512m', '--pull=never',
                     '-v', f'{root}:{root}', '-v', f'{snippets}:{snippets}:ro', image, 'caddy']
            name = 'chronicle-cache-test-' + root.name.lower().replace('_', '-')
            css = root / 'chunk-style9.css'; css.write_text('body {color: red}')
            (root / 'chunk-app123.js').write_text('console.log(1)')
            (root / 'fonts').mkdir(); (root / 'fonts/font-12345678.woff2').write_bytes(b'font')
            (root / 'index.html').write_text('shell')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
            config = root / 'Caddyfile'
            config.write_text(f'''{{
  admin off
  auto_https off
}}
import {ROOT / 'selfhost/caddy/snippets.caddy'}
http://127.0.0.1:{port} {{
  import chronicle_spa
}}
''')
            adapted = subprocess.run([*caddy, 'adapt', '--config', str(config)], check=True,
                                     capture_output=True, text=True, timeout=60)
            runtime = root / 'caddy.json'; runtime.write_text(adapted.stdout.replace('"/srv"', json.dumps(str(root))))
            with (root / 'caddy.log').open('w+') as log:
                caddy[2:2] = ['--name', name]
                process = subprocess.Popen([*caddy, 'run', '--config', str(runtime)], stdout=log, stderr=log)
                try:
                    origin = f'http://127.0.0.1:{port}/chronicle/'
                    for attempt in range(50):
                        try:
                            with urlopen(origin + css.name, timeout=1) as response:
                                self.assertEqual(response.headers['Cache-Control'], 'no-cache')
                                self.assertEqual(response.read(), css.read_bytes())
                            break
                        except URLError:
                            if process.poll() is not None or attempt == 49:
                                log.seek(0); self.fail(log.read())
                            time.sleep(0.1)
                    css.write_text('body {color: blue}')
                    with urlopen(origin + css.name, timeout=2) as response:
                        self.assertEqual(response.headers['Cache-Control'], 'no-cache')
                        self.assertEqual(response.read(), css.read_bytes())
                    for path in ('chunk-app123.js', 'fonts/font-12345678.woff2'):
                        with urlopen(origin + path, timeout=2) as response:
                            self.assertIn('immutable', response.headers['Cache-Control'])
                    with urlopen(origin + 'chunk-missing.js', timeout=2) as response:
                        self.assertEqual(response.headers['Cache-Control'], 'no-cache')
                finally:
                    subprocess.run(['docker', 'stop', '--time', '5', name], capture_output=True, timeout=30)
                    self.assertIn(process.wait(timeout=30), (0, -signal.SIGTERM))
