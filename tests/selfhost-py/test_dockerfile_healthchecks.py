"""Release-image HEALTHCHECKs: exec (JSON) form, and Grafana's probes the protocol the server serves.

hadolint 2.15 (DL3025) refuses the shell form the 2026.11.12 Dockerfiles used. Grafana's image probed
http:// while the monitoring overlay serves HTTPS (GF_SERVER_PROTOCOL=https), so the image's own check
failed wherever the Compose override was absent (audit AF-S8).
"""
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RELEASE_DOCKERFILES = sorted((ROOT / 'selfhost').glob('Dockerfile.*')) + [ROOT / 'docker/Dockerfile.backend']


def instructions(dockerfile):
    """Dockerfile instructions with continuation lines joined and comment lines dropped."""
    joined, current = [], ''
    for line in dockerfile.read_text().splitlines():
        if line.lstrip().startswith('#') and current:
            continue
        current += line.rstrip('\\').strip() + ' ' if line.rstrip().endswith('\\') else line.strip()
        if not line.rstrip().endswith('\\'):
            if current and not current.startswith('#'):
                joined.append(current)
            current = ''
    return joined


def healthcheck(dockerfile):
    found = [line for line in instructions(dockerfile) if line.upper().startswith('HEALTHCHECK ')]
    if not found:
        return None
    command = re.search(r'\bCMD\s+(.*)$', found[-1])
    return command[1] if command else 'NONE'


class DockerfileHealthcheckTests(unittest.TestCase):
    def test_every_healthcheck_uses_exec_form(self):
        for dockerfile in RELEASE_DOCKERFILES:
            command = healthcheck(dockerfile)
            if command is None:
                continue
            with self.subTest(dockerfile=dockerfile.name):
                self.assertTrue(command.startswith('['), command)
                self.assertIsInstance(json.loads(command), list)

    def run_grafana_check(self, environment):
        argv = json.loads(healthcheck(ROOT / 'selfhost/Dockerfile.grafana'))
        with tempfile.TemporaryDirectory(prefix='grafana-health-') as folder:
            bin_dir = Path(folder)
            log = bin_dir / 'curl.log'
            curl = bin_dir / 'curl'
            curl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CURL_LOG"\n')
            curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
            env = {'PATH': f'{bin_dir}:/usr/bin:/bin', 'CURL_LOG': str(log), **environment}
            result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stderr)
            return log.read_text().splitlines()

    def test_grafana_probes_http_without_the_monitoring_overlay(self):
        self.assertEqual(['-fsS -o /dev/null http://127.0.0.1:3000/api/health'], self.run_grafana_check({}))

    def test_grafana_probes_https_with_the_served_certificate(self):
        # The monitoring overlay's settings (selfhost/overlays/monitoring.yml).
        calls = self.run_grafana_check({'GF_SERVER_PROTOCOL': 'https',
                                        'GF_SERVER_CERT_FILE': '/etc/grafana/tls/monitoring.crt'})
        self.assertEqual(['-fsS -o /dev/null --cacert /etc/grafana/tls/monitoring.crt https://127.0.0.1:3000/api/health'],
                         calls)
        overlay = (ROOT / 'selfhost/overlays/monitoring.yml').read_text()
        self.assertIn('GF_SERVER_PROTOCOL: https', overlay)
        self.assertIn('GF_SERVER_CERT_FILE: /etc/grafana/tls/monitoring.crt', overlay)

    def test_backup_probe_reads_the_configured_port(self):
        argv = json.loads(healthcheck(ROOT / 'selfhost/Dockerfile.backup'))
        self.assertEqual(['/bin/sh', '-c'], argv[:2])
        self.assertIn('http://127.0.0.1:${HEALTHCHECK_PORT}/', argv[2])
        self.assertIn('python3 /selfcheck.py health', argv[2])


if __name__ == '__main__':
    unittest.main()
