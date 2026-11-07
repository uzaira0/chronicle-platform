"""PR-O3 / PR-O11: firing alerts reach the host's system log with no configuration.

A default install has no alert webhook, so Grafana's contact point delivers to a discard port.
The scheduled reconciliation (host cron, every 15 minutes) runs doctor, which reads the firing
alerts from Grafana's Alertmanager API and writes each one to syslog with `logger`, the path
reconcile already uses for its own failures. doctor and status list them too.

The first alert in fixtures/grafana_alertmanager_alerts.json is the response Grafana 13.2.5 (the
shipped image) gave for an always-firing rule; the second, suppressed one is written by hand."""

import datetime
import http.server
import io
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

from chronicle_ops import alerts
from chronicle_ops.__main__ import run_cli

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RESPONSE = json.loads((HERE / 'fixtures/grafana_alertmanager_alerts.json').read_text())
NOW = datetime.datetime(2026, 11, 6, 23, 15, tzinfo=datetime.timezone.utc)


def fake_logger(folder):
    """A `logger` on PATH that appends its arguments to folder/syslog."""
    tool = Path(folder) / 'bin/logger'
    tool.parent.mkdir()
    tool.write_text('#!/bin/sh\nprintf "%s|" "$@" >>"$SYSLOG_RECORD"\necho >>"$SYSLOG_RECORD"\n')
    tool.chmod(0o755)
    return {'PATH': f"{tool.parent}:{os.environ['PATH']}", 'SYSLOG_RECORD': str(Path(folder) / 'syslog')}


class FiringAlertTests(unittest.TestCase):
    def test_only_active_alerts_are_reported_with_name_severity_and_summary(self):
        self.assertEqual([alerts.Alert('76bcbd33825c000f', 'DiskAlmostFull', 'critical', 'Free disk is below the reserve')],
                         alerts.firing(RESPONSE))

    def test_doctor_row_names_firing_alerts_and_is_a_warning(self):
        self.assertEqual(('alerts-firing', 'ok', 'No alert is firing', 'none'), alerts.doctor_row([]))
        ident, status, summary, action = alerts.doctor_row(alerts.firing(RESPONSE))
        self.assertEqual(('alerts-firing', 'warn'), (ident, status))
        self.assertIn('DiskAlmostFull (critical)', summary)
        self.assertIn('runbook', action)


class SyslogTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder)
        active = patch.dict(os.environ, fake_logger(self.folder))
        active.start()
        self.addCleanup(active.stop)
        self.record = Path(self.folder) / 'syslog'

    def lines(self):
        return self.record.read_text().splitlines() if self.record.exists() else []

    def test_a_firing_alert_is_logged_once_a_day_and_its_resolution_once(self):
        state = Path(self.folder)
        firing = alerts.firing(RESPONSE)
        alerts.log_to_syslog(firing, state, NOW)
        self.assertEqual([('-p|user.crit|-t|chronicle|Chronicle alert firing: DiskAlmostFull (critical): '
                           'Free disk is below the reserve. Run ./chronicle doctor|')], self.lines())
        alerts.log_to_syslog(firing, state, NOW + datetime.timedelta(minutes=15))
        self.assertEqual(1, len(self.lines()))  # the next scheduled run does not repeat it
        alerts.log_to_syslog(firing, state, NOW + datetime.timedelta(hours=24, minutes=1))
        self.assertEqual(2, len(self.lines()))  # Grafana's own repeat interval is 24 h
        alerts.log_to_syslog([], state, NOW + datetime.timedelta(hours=25))
        self.assertEqual('-p|user.notice|-t|chronicle|Chronicle alert resolved: DiskAlmostFull|', self.lines()[-1])
        alerts.log_to_syslog([], state, NOW + datetime.timedelta(hours=26))
        self.assertEqual(3, len(self.lines()))

    def test_a_damaged_record_logs_again_instead_of_failing(self):
        state = Path(self.folder)
        (state / alerts.SYSLOG_RECORD).write_text('{not json')
        alerts.log_to_syslog(alerts.firing(RESPONSE), state, NOW)
        self.assertEqual(1, len(self.lines()))


class GrafanaHandler(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list] = []

    def do_GET(self):
        GrafanaHandler.seen.append((self.path, self.headers.get('Authorization')))
        if self.headers.get('Authorization') != 'Basic YWRtaW46Zml4dHVyZS1hZG1pbi1wYXNzd29yZA==':
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps(RESPONSE).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class CommandTests(unittest.TestCase):
    """`python3 -m chronicle_ops alerts [--syslog]` against a local HTTPS server standing in for Grafana."""

    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.folder)
        state = self.folder / 'state'
        (state / 'tls').mkdir(parents=True)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=127.0.0.1',
                        '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', str(self.folder / 'key.pem'),
                        '-out', str(state / 'tls/monitoring.crt')], check=True, capture_output=True, timeout=60)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(state / 'tls/monitoring.crt', self.folder / 'key.pem')
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), GrafanaHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.host = self.folder / 'selfhost'
        self.host.mkdir()
        self.settings = (f"COMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml:overlays/monitoring.yml\n"
                         f"GRAFANA_ADMIN_PASSWORD=fixture-admin-password\nGRAFANA_BIND=127.0.0.1\n"
                         f"GRAFANA_PORT={server.server_address[1]}\n")
        (self.host / '.env').write_text(self.settings)
        origin = Path.cwd()
        self.addCleanup(os.chdir, origin)
        os.chdir(self.host)
        environment = dict(fake_logger(self.folder), CHRONICLE_OPS_STATE=str(state), HTTPS_PROXY='http://127.0.0.1:9')
        active = patch.dict(os.environ, environment)
        active.start()
        self.addCleanup(active.stop)
        GrafanaHandler.seen = []

    def cli(self, *args):
        with patch('chronicle_ops.__main__.signal.signal'), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(0, run_cli(['alerts', *args]))
        return output.getvalue()

    def test_doctor_row_reads_grafana_with_the_admin_password_and_no_proxy(self):
        row = self.cli().rstrip('\n').split('\x1f')
        self.assertEqual(['alerts-firing', 'warn'], row[:2])
        self.assertEqual([('/api/alertmanager/grafana/api/v2/alerts?active=true&silenced=false&inhibited=false',
                           'Basic YWRtaW46Zml4dHVyZS1hZG1pbi1wYXNzd29yZA==')], GrafanaHandler.seen)
        self.assertFalse((self.folder / 'syslog').exists())  # only --syslog writes to the system log

    def test_syslog_flag_writes_the_firing_alert(self):
        self.cli('--syslog')
        self.assertIn('Chronicle alert firing: DiskAlmostFull', (self.folder / 'syslog').read_text())

    def test_nothing_without_the_monitoring_overlay(self):
        (self.host / '.env').write_text(self.settings.replace(':overlays/monitoring.yml', ''))
        self.assertEqual('', self.cli('--syslog'))
        self.assertEqual([], GrafanaHandler.seen)

    def test_an_unreachable_grafana_is_a_warning_row(self):
        (self.host / '.env').write_text(self.settings.rsplit('GRAFANA_PORT=', 1)[0] + 'GRAFANA_PORT=9\n')
        row = self.cli('--syslog').rstrip('\n').split('\x1f')
        self.assertEqual(['alerts-firing', 'warn'], row[:2])
        self.assertIn('Could not read alerts from Grafana', row[2])


class ScheduleTests(unittest.TestCase):
    def test_the_scheduled_doctor_writes_firing_alerts_to_syslog(self):
        from chronicle_ops import reconcile
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            launcher = root / 'selfhost/chronicle'
            launcher.parent.mkdir()
            launcher.write_text('')
            state = root / 'state'
            state.mkdir()
            with patch('chronicle_ops.reconcile.schedule_blocker', return_value=None), \
                 patch('chronicle_ops.reconcile.crontab_without_project', return_value=([], '# m', True)), \
                 patch('chronicle_ops.reconcile.write_crontab'), patch('chronicle_ops.release.set_current_owner'), \
                 patch.dict(os.environ, CHRONICLE_RECONCILE_ENABLED='true'):
                reconcile.install(launcher, state, 'fixture')
            self.assertIn(f'{alerts.SYSLOG_ENV}=true ./chronicle doctor', (state / 'reconcile.sh').read_text())

    def test_doctor_asks_for_syslog_only_from_the_schedule(self):
        script = ('calls="$2"; source "$1"; ops_python() { printf "%s " "$@" >>"$calls"; }; doctor_add() { :; }; '
                  'doctor_add_rows() { :; }; COMPOSE_FILE=overlays/monitoring.yml; doctor_check_alerts')
        for scheduled, expected in (('true', 'alerts --syslog '), ('', 'alerts ')):
            with self.subTest(scheduled=scheduled), tempfile.TemporaryDirectory() as folder:
                calls = Path(folder) / 'calls'
                result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'selfhost/doctor.sh'), str(calls)],
                                        capture_output=True, text=True, timeout=10, check=False,
                                        env=dict(os.environ, **{alerts.SYSLOG_ENV: scheduled}))
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(expected, calls.read_text())


if __name__ == '__main__':
    unittest.main()
