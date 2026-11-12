"""Focused regressions for the operator batch; no live services required."""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import ssl
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "selfhost"))
from selfhost_fixture import copy_selfhost_fixture
from chronicle_ops.common import WRITABLE_ROOT_REASON_LABEL
from chronicle_ops.reconcile import ENABLED_ENV, install, STOP_MARKER
from chronicle_ops.release import certificate_digest
from chronicle_ops.envfile import read_env, set_env_values, value
import test_secret_generation as setup_fixture
from chronicle_ops.verify import verify_backup_storage, verify_database_storage



PUBLIC_CHECK_FIXTURE = '''public_check() {
  PYTHONPATH="$OPS_PACKAGE" python3 -c '
import os
from unittest.mock import patch
from chronicle_ops.verify import verify_public_origin
with patch("chronicle_ops.verify.curl", side_effect=[(0, os.environ["HEALTH_CODE"]), (0, "200")]):
    raise SystemExit(verify_public_origin("https://example.test"))'
}
'''


DOCTOR_PYTHON_STUB = r'''import os
import sys
args = sys.argv[1:]
if args[:1] == ['-c'] and 'DATABASE_PRIVILEGES_VIOLATION' in args[1] and os.environ['PRODUCER'] == 'contract':
    raise SystemExit(int(os.environ['PRODUCER_STATUS']))
if args[:2] == ['-m', 'chronicle_ops']:
    command = args[2]
    if command == 'backup-storage':
        raise SystemExit(int(os.environ.get('BACKUP_STORAGE_STATUS', '0')))
    if command == 'database-storage':
        raise SystemExit(int(os.environ.get('DATABASE_STORAGE_STATUS', '0')))
    if command == 'reconcile':
        if args[3] == 'check' and os.environ.get('RECONCILE_CHECK_ERROR'):
            print('error: ' + os.environ['RECONCILE_CHECK_ERROR'], file=sys.stderr)
            raise SystemExit(1)
        raise SystemExit(int(args[3] == 'stopped'))
    if command == 'public-check':
        if os.environ['HEALTH_CODE'] != '204':
            print('Chronicle is not ready')
            raise SystemExit(1)
    elif command == 'database-privileges':
        from types import SimpleNamespace
        from unittest.mock import patch
        from chronicle_ops.__main__ import main
        answer = os.environ['PRIVILEGES_ANSWER']
        with patch('chronicle_ops.verify.compose', return_value=SimpleNamespace(stdout='' if answer == 'missing' else 'postgres')), \
             patch('chronicle_ops.verify.postgres_sql', return_value=answer) as query:
            if answer == 'query-failed':
                query.side_effect = OSError('database unavailable')
            raise SystemExit(main(['database-privileges']))
    raise SystemExit(0)
if args == ['-']:
    script = sys.stdin.read()
    if 'verify_backup' in script:
        raise SystemExit(0)
    for producer in ('disk_rows', 'capacity_checks', 'monitoring_checks'):
        if producer in script:
            if os.environ['PRODUCER'] == producer:
                raise SystemExit(int(os.environ['PRODUCER_STATUS']))
            print('fixture-' + producer + '\x1fok\x1fProbe passed\x1fnone')
            raise SystemExit(0)
    exec(compile(script, '<stdin>', 'exec'))
else:
    os.execv(sys.executable, [sys.executable, *args])
'''


# The launcher returns before dispatch when sourced, so tests run its real functions and stub the rest.
SOURCE_LAUNCHER = f'source {ROOT / "selfhost/chronicle"}\n'


def source_launcher_in(folder):
    """Source a copy of the launcher placed in folder, which it then treats as its install directory."""
    launcher = Path(folder) / 'chronicle'
    shutil.copyfile(ROOT / 'selfhost/chronicle', launcher)
    launcher.chmod(0o755)
    return f'source {launcher}\n'


class OpsBatchTests(unittest.TestCase):
    def setUp(self):
        disabled = patch.dict(os.environ, {ENABLED_ENV: "false"})
        disabled.start()
        self.addCleanup(disabled.stop)

    def doctor_fixture(self):
        fixture = self.setup_host_fixture()
        fixture.run_setup()
        settings = fixture.host / '.env'
        settings.write_text(set_env_values(settings.read_text(), {
            'COMPOSE_FILE': 'docker-compose.yml:overlays/backups.yml:overlays/monitoring.yml',
            'CHRONICLE_ALERT_WEBHOOK_URL': 'https://alerts.example.test/fixture',
        }, require_existing=True))
        commands = Path(fixture.folder.name) / 'bin'
        python = commands / 'python3'
        python.write_text('#!' + sys.executable + '\n' + DOCTOR_PYTHON_STUB)
        python.chmod(0o755)
        docker = commands / 'docker'
        docker.write_text("""#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  inspect*) [[ "$CONTAINER_STATE" != inspect-failed ]] || exit 1; printf '%s' "$CONTAINER_STATE" ;;
  *'ps --status running --services') printf '%s\\n' postgres backend web victoriametrics victorialogs fluent-bit grafana operational-probe ;;
  *'ps -a -q '*) [[ -z "$CONTAINER_STATE" ]] || printf '%s\\n' "${@: -1}" ;;
esac
""")
        fixture.environment.update(CONTAINER_STATE='running healthy', PRIVILEGES_ANSWER='t', HEALTH_CODE='204',
                                   PRODUCER='', PRODUCER_STATUS='0')
        return fixture

    def run_doctor(self, fixture, **overrides):
        return subprocess.run(['bash', str(fixture.host / 'chronicle'), 'doctor', '--json'],
                              env=dict(fixture.environment, **overrides), capture_output=True, text=True, timeout=20)

    def test_doctor_warns_without_a_monitoring_alert_destination_and_exits_zero(self):
        """AF-P2: a default install has no alert recipient. A failing row there made doctor exit 1
        and reconciliation record a failure every 15 minutes, hiding every real failure."""
        fixture = self.doctor_fixture()
        settings = fixture.host / '.env'
        settings.write_text(set_env_values(settings.read_text(), {'CHRONICLE_ALERT_WEBHOOK_URL': ''}, require_existing=True))
        result = self.run_doctor(fixture)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        checks = {row['check']: row for row in json.loads(result.stdout)['checks']}
        self.assertEqual('warn', checks['alert-route']['status'])
        self.assertIn('CHRONICLE_ALERT_WEBHOOK_URL', checks['alert-route']['recoveryCommand'])
        self.assertIn('.env', checks['alert-route']['recoveryCommand'])
        self.assertEqual('ok', json.loads(result.stdout)['overall'])

    def test_doctor_reports_a_configured_alert_destination_as_ok(self):
        result = self.run_doctor(self.doctor_fixture())
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        checks = {row['check']: row for row in json.loads(result.stdout)['checks']}
        self.assertEqual('ok', checks['alert-route']['status'])

    def test_doctor_reports_db_backup_which_update_no_longer_waits_for(self):
        """O10d: update and rollback start db-backup without waiting for its first dump, so doctor
        is where its state shows: healthy is ok, a first dump in progress warns, anything else fails."""
        fixture = self.doctor_fixture()
        for state, expected in (('running healthy', 'ok'), ('running starting', 'warn'),
                                ('running unhealthy', 'fail'), ('exited ', 'fail')):
            with self.subTest(state=state):
                result = self.run_doctor(fixture, CONTAINER_STATE=state)
                checks = {row['check']: row for row in json.loads(result.stdout)['checks']}
                self.assertEqual(expected, checks['service-db-backup']['status'], result.stdout)

    def test_doctor_does_not_send_the_operator_to_the_logs_of_a_missing_container(self):
        """A service whose container was never created has no logs: `./chronicle logs` prints
        nothing for it. Doctor names `./chronicle up`, which prints why Compose cannot create it."""
        fixture = self.doctor_fixture()
        services = ('service-postgres', 'service-backend', 'service-web', 'service-db-backup')
        result = self.run_doctor(fixture, CONTAINER_STATE='')
        checks = {row['check']: row for row in json.loads(result.stdout)['checks']}
        for check in services:
            with self.subTest(check, container='missing'):
                self.assertEqual('fail', checks[check]['status'], result.stdout)
                self.assertNotIn('./chronicle logs', checks[check]['recoveryCommand'])
                self.assertIn('./chronicle up', checks[check]['recoveryCommand'])
        result = self.run_doctor(fixture, CONTAINER_STATE='running unhealthy')
        checks = {row['check']: row for row in json.loads(result.stdout)['checks']}
        for check in services:
            with self.subTest(check, container='unhealthy'):
                self.assertIn('./chronicle logs ' + check.removeprefix('service-'), checks[check]['recoveryCommand'])

    def test_low_free_percentage_warns_and_only_the_startup_reserve_fails(self):
        # A 1-TiB host filesystem with 100 GiB available is below 15% free yet far above the reserve.
        from chronicle_ops import verify
        gib = 1024 ** 3
        disk = SimpleNamespace(f_frsize=4096, f_blocks=1024 * gib // 4096, f_bfree=100 * gib // 4096,
                               f_bavail=100 * gib // 4096)
        for enough, reserve in ((True, 'ok'), (False, 'fail')):
            with self.subTest(enough=enough), \
                 patch('chronicle_ops.verify.storage_report', return_value=[('state', enough, 100 * gib, 10 ** 6, 5 * gib)]), \
                 patch('chronicle_ops.verify.os.statvfs', return_value=disk):
                rows = {row[0]: row[1] for row in verify.disk_rows({}, '/state')}
            self.assertEqual({'disk': 'warn', 'state-reserve': reserve}, rows)

    def test_host_filesystem_row_survives_an_unreachable_docker_daemon(self):
        from chronicle_ops import verify
        gib = 1024 ** 3
        disk = SimpleNamespace(f_frsize=4096, f_blocks=1024 * gib // 4096, f_bfree=500 * gib // 4096, f_bavail=500 * gib // 4096)
        refused = subprocess.CalledProcessError(1, ['docker', 'info'])
        with patch('chronicle_ops.verify.storage_report', side_effect=refused), \
             patch('chronicle_ops.verify.os.statvfs', return_value=disk):
            rows = verify.disk_rows({}, '/state')
        self.assertEqual(('disk', 'ok'), rows[0][:2])
        self.assertEqual([('storage-reserve', 'fail')], [row[:2] for row in rows[1:]])
        self.assertIn('Docker', rows[1][3])

    def test_a_filesystem_without_block_counts_reports_unreadable_capacity(self):
        # df prints "-" for Use% when a filesystem reports no blocks; doctor must say so, not crash.
        from chronicle_ops import verify
        empty = SimpleNamespace(f_frsize=4096, f_blocks=0, f_bfree=0, f_bavail=0)
        with patch('chronicle_ops.verify.storage_report', return_value=[('state', True, 0, 10 ** 6, 0)]), \
             patch('chronicle_ops.verify.os.statvfs', return_value=empty):
            rows = {row[0]: row[1:3] for row in verify.disk_rows({}, '/state')}
        self.assertEqual(('warn', 'Host filesystem capacity could not be read'), rows['disk'])
        df = 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfuse 0 0 0 - /var/lib/postgresql\n'
        answer = df + json.dumps({'database_bytes': 1, 'wal_bytes': 0, 'max_wal_bytes': 1})
        with patch('chronicle_ops.verify.compose', return_value=SimpleNamespace(stdout=answer)):
            rows = {row[0]: row[1:3] for row in verify.capacity_checks({'COMPOSE_FILE': ''}, '/backups')}
        self.assertEqual(('warn', 'Database volume capacity could not be read'), rows['database-disk'])

    def test_doctor_names_the_recovery_command_of_an_incomplete_operation(self):
        fixture = self.doctor_fixture()
        message = 'incomplete operation at /state/.chronicle-upgrade.lock; run ./chronicle update from /old/selfhost'
        result = self.run_doctor(fixture, RECONCILE_CHECK_ERROR=message)
        checks = {check['check']: check for check in json.loads(result.stdout)['checks']}
        self.assertEqual(('warn', message), (checks['operation-lock']['status'], checks['operation-lock']['recoveryCommand']))

    def test_doctor_reports_observed_container_and_database_privilege_states(self):
        fixture = self.doctor_fixture()
        cases = [('running healthy', answer, '204') for answer in ('t', 'f', 'missing', 'query-failed', 'malformed')]
        cases += [(state, 't', '204') for state in ('running unhealthy', 'running starting', 'exited unhealthy', '', 'inspect-failed')]
        cases += [('running healthy', 't', '503')]
        for state, answer, health in cases:
            with self.subTest(state=state, answer=answer, health=health):
                result = self.run_doctor(fixture, CONTAINER_STATE=state, PRIVILEGES_ANSWER=answer, HEALTH_CODE=health)
                self.assertEqual(result.returncode, int(state != 'running healthy' or answer != 't' or health != '204'), result.stderr + result.stdout)
                checks = {row['check']: row for row in json.loads(result.stdout)['checks']}
                self.assertEqual('fail' if answer != 't' else 'ok', checks['database-privileges']['status'])
                privileges = checks['database-privileges']
                if answer == 'f':
                    self.assertIn('preserves ACLs', privileges['recoveryCommand'])
                elif answer != 't':
                    self.assertIn('Could not check database privileges', privileges['likelyCause'])
                    self.assertEqual('Restore database connectivity and rerun doctor', privileges['recoveryCommand'])
                for service in ('postgres', 'backend', 'web'):
                    shown = checks['service-' + service]['likelyCause']
                    if state.startswith('running '):
                        self.assertIn(state.split()[1], shown)
                    elif state == 'inspect-failed':
                        self.assertIn('Could not check', shown)
                    else:
                        self.assertIn('not running', shown)
                if health == '503':
                    self.assertIn('Chronicle is not ready', checks['public-readiness']['likelyCause'])

    def test_doctor_fails_when_diagnostic_producer_crashes_or_is_empty(self):
        fixture = self.doctor_fixture()
        for producer, row in (('disk_rows', 'disk'), ('capacity_checks', 'backup-capacity'), ('monitoring_checks', 'monitoring-pipeline'),
                              ('contract', 'database-privileges')):
            for status in ('0', '9'):
                with self.subTest(producer=producer, status=status):
                    result = self.run_doctor(fixture, PRODUCER=producer, PRODUCER_STATUS=status)
                    self.assertEqual(1, result.returncode, result.stderr + result.stdout)
                    self.assertTrue(result.stdout, result.stderr)
                    checks = {row['check']: row for row in json.loads(result.stdout)['checks']}
                    self.assertEqual('fail', checks[row]['status'])
        self.assertEqual(0, self.run_doctor(fixture).returncode)

    def test_grafana_password_change_causes_apply_to_rotation_and_recovery(self):
        script = '''set -Eeuo pipefail
source "$1"
ROTATION_ACTION=rotate
COMPOSE_FILE=overlays/monitoring.yml
GRAFANA_ADMIN_PASSWORD=synthetic-old
ROTATION_DIR=synthetic-transaction
SAVED_ROTATION_KIND=grafana
NEW_SECRET= OLD_SECRET= RECEIPT_DETAIL=
for name in service_running confirm configure_apply begin_transaction env_update write_phase apply_configuration ensure_recovery_service_running restore_old_env log; do
  eval "$name() { :; }"
done
complete_transaction() { printf committed; }
complete_recovery() { printf committed; }
fail() { echo "$*" >&2; exit 1; }
openssl() { printf synthetic-new; }
grafana_base_url() { printf https://grafana.example.test; }
curl_basic_code() { printf 200; }
env_value_from_file() { if [[ "$1" == .env ]]; then printf synthetic-new; else printf synthetic-old; fi; }
grafana_can_auth() {
  [[ "$1" == synthetic-old && "$RECOVERY_DIRECTION" == forward || "$1" == synthetic-new && "$RECOVERY_DIRECTION" == rollback || "$CURL_CODE" == 200 && "$CURL_STATUS" == 0 ]]
}
curl() { cat >/dev/null; printf '%s' "$CURL_CODE"; return "$CURL_STATUS"; }
if [[ "$TEST_ACTION" == rotate ]]; then rotate_grafana; else recover_grafana_rotation; fi
'''
        for action in ('rotate', 'forward', 'rollback'):
            for code, curl_status, message in (
                ('200', 0, ''), ('401', 0, 'refused password-change authentication'),
                ('403', 0, 'refused password-change authentication'), ('500', 0, 'server error'),
                ('400', 0, 'unexpected password-change response'), ('000', 60, 'outcome could not be confirmed'),
                ('000', 28, 'outcome could not be confirmed'), ('200', 28, 'outcome could not be confirmed'),
            ):
                with self.subTest(action=action, code=code, curl_status=curl_status):
                    result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'selfhost/rotation-http.sh')], capture_output=True, text=True, timeout=10,
                        env=dict(os.environ, TEST_ACTION=action, RECOVERY_DIRECTION=action,
                                 CURL_CODE=code, CURL_STATUS=str(curl_status), STATE_ROOT=str(Path(__file__).parent)))
                    expected = int(code != '200' or curl_status != 0)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertEqual('committed' in result.stdout, expected == 0)
                    if expected:
                        self.assertIn('rotation recovery', result.stderr)
                        self.assertNotIn('Grafana rejected', result.stderr)
                    if curl_status:
                        self.assertNotIn('refused', result.stderr)
                    self.assertNotIn('synthetic-old', result.stdout + result.stderr)
                    self.assertNotIn('synthetic-new', result.stdout + result.stderr)

    def test_expiry_probe_requires_identical_signed_claims_and_rejects_missing_inputs_and_throttling(self):
        from session_probe_fixture import run_session_probe
        for mode, key, succeeds in (('secure', 'synthetic-secret', True),
                                   ('valid-throttled', 'synthetic-secret', False),
                                   ('expiry-throttled', 'synthetic-secret', False),
                                   ('expiry-accepted', 'synthetic-secret', False),
                                   ('secure', '', False)):
            with self.subTest(mode=mode, missing_key=not key):
                result = run_session_probe(mode, key)
                self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)
                if not succeeds:
                    self.assertNotIn('[PASS]  Test 1:', re.sub(r'\x1b\[[0-9;]*m', '', result.stdout))

    def test_study_isolation_requires_same_token_positive_control_on_real_participant_routes(self):
        with tempfile.TemporaryDirectory() as folder:
            curl = Path(folder) / 'curl'
            curl.write_text('''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
assert all('Authorization:' not in argument for argument in args), 'bearer header leaked in curl argv'
headers = []
if '--config' in args:
    assert args[args.index('--config') + 1] == '-'
    for line in sys.stdin:
        name, separator, encoded = line.partition('=')
        assert separator and name.strip() == 'header'
        headers.append(json.loads(encoded))
route = args[-1].removeprefix(os.environ['BASE_URL'] + '/chronicle/v3/')
if route.endswith('/participants'):
    assert 'Authorization: Bearer A-only' in headers
    print(os.environ['STATUS_A'] if route.startswith('study/study-a/') else os.environ['STATUS_B'], end='')
elif route in ('study/study-b/participants/data?dataType=UsageEvents&participantId=participant-b&responseType=csv',
               'study/study-b/participants/purge'):
    if 'Authorization: Bearer A-only' not in headers:
        print('401', end='')
    elif route.endswith('/purge'):
        assert '{"participantId":"participant-b","confirmationToken":"probe"}' in args
        print(os.environ['STATUS_PURGE'], end='')
    else:
        print(os.environ['STATUS_B'], end='')
else:
    print({'': '200', 'admin/event-storage': '403', 'admin/reload/cache': '403'}.get(route, '401'), end='')
''')
            curl.chmod(0o755)
            fixtures = dict(AUTH_TOKEN='A-only', STUDY_A='study-a', STUDY_B='study-b', PARTICIPANT_ID='participant-b')
            for allowed, denied, purge, missing, succeeds in ((200, 403, 403, None, True), (403, 403, 403, None, False),
                                                              (200, 404, 403, None, False), (200, 429, 403, None, False),
                                                              (200, 403, 200, None, False), (200, 403, 403, 'PARTICIPANT_ID', False)):
                environment = dict(os.environ, PATH=folder+os.pathsep+os.environ['PATH'], BASE_URL='https://fixture.invalid',
                                   STATUS_A=str(allowed), STATUS_B=str(denied), STATUS_PURGE=str(purge), **fixtures)
                environment.pop(missing, None)
                result = subprocess.run(['bash', str(ROOT / 'tests/security/business-logic-tests.sh')], capture_output=True, text=True, timeout=10,
                                        env=environment)
                self.assertEqual(result.returncode == 0, succeeds, result.stdout + result.stderr)
                self.assertIn('Test 1b', result.stdout)
                self.assertNotIn('SKIP', result.stdout)

    def test_permission_scan_and_repair_preserve_private_runtime_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); root.chmod(0o755)
            private_files = []
            for name in ('.chronicle-secret-rotation', 'upgrade-receipts'):
                private = root / name; private.mkdir(mode=0o700)
                saved = private / 'old.env'; saved.write_text('synthetic-secret'); saved.chmod(0o600)
                private_files.append(saved)
            lock = root / '.reconcile.lock'; lock.touch(mode=0o600)
            for name in ('.chronicle-stopped', 'reconcile.sh', 'reconcile.log'):
                path = root / name; path.touch(mode=0o600)
            shipped = root / 'entrypoint.sh'; shipped.write_text('# fixture'); shipped.chmod(0o644)
            script = source_launcher_in(root) + '''dc() { :; }; foreign_project() { :; }; ok() { :; }; warn() { :; }
bad() { [[ -z "${permission_repair:-}" ]] || printf "%s" "$permission_repair"; }
preflight_environment
'''
            result = subprocess.run(['bash', '-c', script], cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, '')
            shipped.chmod(0o600)
            result = subprocess.run(['bash', '-c', script], cwd=root, capture_output=True, text=True, check=True, timeout=10)
            self.assertTrue(result.stdout.startswith('find '))
            subprocess.run(['bash', '-eu', '-c', result.stdout], cwd=root, check=True, timeout=10)
            self.assertEqual(shipped.stat().st_mode & 0o777, 0o644)
            for saved in private_files:
                self.assertEqual(saved.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_uninstall_removes_only_its_schedule_and_keeps_reconciliation_paused(self):
        from chronicle_ops.reconcile import uninstall
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder); (state / 'reconcile.sh').write_text('old launcher')
            current = '0 1 * * * other-job\n@reboot old # chronicle-reconcile:fixture\n@reboot other # chronicle-reconcile:other\n'
            with patch.dict(os.environ, HOME=folder), \
                 patch('chronicle_ops.reconcile.shutil.which', return_value='/fixture/crontab'), \
                 patch('chronicle_ops.reconcile.run', return_value=SimpleNamespace(returncode=0, stdout=current, stderr='')) as run:
                uninstall(state, 'fixture')
            self.assertTrue((state / STOP_MARKER).exists())
            self.assertFalse((state / 'reconcile.sh').exists())
            self.assertEqual(run.call_args.kwargs['input'], '0 1 * * * other-job\n@reboot other # chronicle-reconcile:other\n')

    def test_reconciliation_shell_override_wins_over_saved_setting(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '.env'
            script = source_launcher_in(folder) + '''set -eu
die() { exit 1; }
stat_mode() { echo 600; }
ops_python() { :; }
validate_legacy_mobile_values() { :; }
derive_mode() { :; }
need_env
printf "%s" "$CHRONICLE_RECONCILE_ENABLED"
'''
            for override, saved, expected in ((None, 'false', 'false'), ('false', 'true', 'false'), ('true', 'false', 'true')):
                path.write_text('CHRONICLE_RECONCILE_ENABLED=' + saved + '\n'); path.chmod(0o600)
                environment = dict(os.environ)
                environment.pop(ENABLED_ENV, None)
                if override is not None: environment[ENABLED_ENV] = override
                result = subprocess.run(['bash', '-c', script], cwd=folder, env=environment,
                                        capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual(result.stdout, expected)

    def setup_host_fixture(self):
        fixture = setup_fixture.SelfhostSetupFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_remote_lb_requires_explicit_source_cidrs(self):
        fixture = self.setup_host_fixture()
        fixture.environment['HTTP_BIND'] = '0.0.0.0'
        fixture.environment.pop('CADDY_TRUSTED_PROXIES', None)
        with self.assertRaises(AssertionError):
            fixture.run_setup()
        fixture.environment['CADDY_TRUSTED_PROXIES'] = '10.20.0.0/24'
        fixture.run_setup()
        settings = read_env(fixture.host / '.env')
        self.assertEqual(value(settings, 'CADDY_TRUSTED_PROXIES'), fixture.environment['CADDY_TRUSTED_PROXIES'])
        self.assertEqual(value(settings, 'POOL_ALLOWED_IPS'), fixture.environment['CADDY_TRUSTED_PROXIES'])

    def test_setup_dashboard_default_tracks_the_selected_docker_gateway(self):
        fixture = self.setup_host_fixture()
        ip = Path(fixture.folder.name) / 'bin/ip'
        ip.write_text('''#!/usr/bin/env bash
case "$*" in
  '-4 -o addr show') printf '%s\\n' '1: lo inet 127.0.0.1/8 scope host lo' ;;
  '-4 -j route show table all') printf '%s\\n' '[{"dst":"172.16.0.0/12","dev":"vpn"},{"dst":"10.253.0.0/24","dev":"vpn"}]' ;;
  '-6 -j route show table all') printf '[]\\n' ;;
  *) exit 92 ;;
esac
''')
        for key in ('DASHBOARD_ALLOWED_IPS', 'CADDY_TRUSTED_PROXIES'):
            fixture.environment.pop(key, None)
        fixture.environment['POOL_ALLOWED_IPS'] = '172.28.0.1/32'
        fixture.run_setup()
        settings = read_env(fixture.host / '.env')
        self.assertEqual(value(settings, 'CHRONICLE_SUBNET'), '10.253.1.0/24')
        self.assertEqual(value(settings, 'DASHBOARD_ALLOWED_IPS'), '10.253.1.1/32 127.0.0.1/32 ::1/128')
        self.assertEqual(value(settings, 'CADDY_TRUSTED_PROXIES'), '10.253.1.1/32')
        self.assertEqual(value(settings, 'POOL_ALLOWED_IPS'), '10.253.1.1/32')

    def test_dashboard_rotation_verifies_tls_bypasses_proxies_and_retains_acl_denied_rotation(self):
        result = subprocess.run(['bash', str(ROOT / 'tests/security/selfhost-secret-rotation.sh'), '--dashboard-transport'],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        self.assertIn('dashboard transport and module loading checks passed', result.stdout)

    def test_secret_rotation_updates_exported_assignment_and_rejects_duplicates(self):
        # Sourcing defines the functions without rotating; it changes into selfhost/, so return to the fixture.
        script = 'source "$1"; cd "$2"; env_update JWT_SECRET synthetic-new-secret\n'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '.env'
            command = ['bash', '-c', script, 'fixture', str(ROOT / 'selfhost/rotate-secret.sh'), folder]
            for prefix in ('', 'export ', '  export\t'):
                path.write_text(prefix + "JWT_SECRET='synthetic-old-secret'\nOTHER=keep\n")
                result = subprocess.run(command, cwd=folder, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(path.read_text(), "JWT_SECRET='synthetic-new-secret'\nOTHER=keep\n")
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            duplicate = 'JWT_SECRET=first\nexport JWT_SECRET=second\n'
            path.write_text(duplicate)
            result = subprocess.run(command, cwd=folder, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_text(), duplicate)

    def test_certificate_renewal_failure_retry_and_monitoring_removal(self):
        script = SOURCE_LAUNCHER + PUBLIC_CHECK_FIXTURE + '''set -eu
BLD= RST= GRN= COMPOSE_FILE=docker-compose.yml PROJECT=fixture
STATE_ROOT="$1"
for name in need_env lock_operation assert_no_incomplete_mutation begin_operation ensure_images preflight operation_succeeded; do
  eval "$name() { :; }"
done
die() { echo "$*" >&2; exit 1; }
ops_python() {
  case "$1" in
    certificates) PYTHONPATH="$OPS_PACKAGE" CHRONICLE_OPS_STATE="$STATE_ROOT" python3 -m chronicle_ops "$@" ;;
    public-check) public_check ;;
    *) [[ "$*" != 'reconcile stopped' ]] ;;
  esac
}
dc() {
  case "$*" in
    'run --rm --no-deps cert-init') printf renewed >"$STATE_ROOT/tls/internal-cert.pem" ;;
    'config --services') [[ "$FAIL_DISCOVERY" == false ]] || return 1; printf 'postgres\\nbackend\\nweb\\ndb-init\\ndb-backup\\n' ;;
    '--progress '*) printf '%s\\n' "$*" ;;
    'down '*) printf '%s\\n' "$*" ;;
  esac
}
cmd_up up
cmd_down down
'''
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder); (state / 'tls').mkdir()
            marker = state / 'tls/.applied-certificates'; marker.write_text('previous')
            # A public origin that is not reachable yet must not make every reconcile `up` recreate the stack:
            # services that started healthy loaded these certificates, so the marker records them first.
            for failure, force, health in (('true', True, '204'), ('false', True, '503'), ('false', False, '503'), ('false', False, '204')):
                result = subprocess.run(['bash', '-c', script, 'fixture', str(state)], capture_output=True, text=True,
                    env=dict(os.environ, FAIL_DISCOVERY=failure, HEALTH_CODE=health, CHRONICLE_RECONCILE_ENABLED='true', CHRONICLE_RECONCILE_RUN='true', OPS_PACKAGE=str(ROOT / 'selfhost')), timeout=10)
                self.assertEqual(result.returncode, int(failure == 'true' or health == '503'), result.stderr)
                if failure == 'true':
                    self.assertEqual(marker.read_text(), 'previous')
                elif health == '503':
                    self.assertEqual('--force-recreate' in result.stdout, force)
                    self.assertEqual(marker.read_text(), certificate_digest(state))
                    self.assertIn('HTTPS responded, but Chronicle is not ready', result.stderr)
                    self.assertIn('resolve the failed check above', result.stderr)
                    self.assertNotIn('DNS', result.stderr)
                    self.assertNotIn('Started.', result.stdout)
                else:
                    self.assertEqual('--force-recreate' in result.stdout, force)
                    self.assertEqual('--no-recreate' in result.stdout, not force)
                    self.assertIn('--remove-orphans', result.stdout)
                    self.assertIn('down --remove-orphans', result.stdout)
                    self.assertEqual(marker.read_text(), certificate_digest(state))
                    self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def test_abandoned_reviewed_restore_copy_obeys_backup_retention(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stale = root / '.reviewed-restore.stale.sql.gz'; stale.write_bytes(b'fixture')
            fresh = root / '.reviewed-restore.fresh.sql.gz'; fresh.write_bytes(b'fixture')
            from datetime import datetime, timedelta
            expired = (datetime.now() - timedelta(days=3)).timestamp()
            os.utime(stale, (expired, expired))
            subprocess.run(['bash', str(ROOT / 'selfhost/backup-prune-hook.sh'), 'post-backup'],
                env=dict(os.environ, BACKUP_DIR=folder, PRE_OP_BACKUP_KEEP_DAYS='1'),
                capture_output=True, check=True, timeout=10)
            self.assertFalse(stale.exists())
            self.assertTrue(fresh.exists())

    def test_backup_storage_encryption_and_reviewed_waiver(self):
        for devices, waiver, expected in (
            ([{"type": "crypt", "children": [{"type": "disk"}]}], "", 0),
            ([{"type": "disk"}], "", 1),
            ([{"type": "disk"}], "OPS-reviewed-2026-10-07", 0),
            ([{"type": "disk"}], "CHANGE_ME", 1),
            ([{"type": "raid", "children": [{"type": "crypt"}, {"type": "disk"}]}], "", 1),
        ):
            results = [SimpleNamespace(returncode=0, stdout="/dev/mapper/fixture"),
                       SimpleNamespace(returncode=0, stdout=json.dumps({"blockdevices": devices}))]
            with self.subTest(devices=devices, waiver=waiver), \
                 patch("chronicle_ops.verify.sys.platform", "linux"), \
                 patch("chronicle_ops.verify.run", side_effect=results) as runtime, patch("sys.stdout", io.StringIO()) as output:
                self.assertEqual(verify_backup_storage("/tmp", waiver), expected)
                self.assertIn("--tree", runtime.call_args_list[1].args[0])
                self.assertNotIn("FAIL", output.getvalue())
                if expected:
                    self.assertIn("warn", output.getvalue())
        with patch("chronicle_ops.verify.run", side_effect=OSError()), patch("sys.stdout", io.StringIO()):
            self.assertEqual(verify_backup_storage("/tmp"), 1)
        fixture = self.doctor_fixture()
        result = self.run_doctor(fixture, BACKUP_STORAGE_STATUS='1')
        self.assertEqual(1, result.returncode, result.stderr + result.stdout)
        checks = {row['check']: row for row in json.loads(result.stdout)['checks']}
        self.assertEqual('fail', checks['backup-encryption']['status'])

    def test_database_volume_encryption_is_probed_on_the_postgres_volume(self):
        mountpoint = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, mountpoint)
        volume = [{"Mountpoint": mountpoint, "Options": None}]
        for devices, waiver, expected in (([{"type": "crypt", "children": [{"type": "disk"}]}], "", 0),
                                          ([{"type": "disk"}], "", 1),
                                          ([{"type": "disk"}], "OPS-reviewed-2026-10-07", 0)):
            discovery = [SimpleNamespace(stdout=""), SimpleNamespace(stdout="fixture_postgres_data"),
                         SimpleNamespace(stdout=json.dumps(volume))]
            probe = [SimpleNamespace(returncode=0, stdout="/dev/mapper/fixture"),
                     SimpleNamespace(returncode=0, stdout=json.dumps({"blockdevices": devices}))]
            with self.subTest(devices=devices, waiver=waiver), \
                 patch("chronicle_ops.common.run", side_effect=discovery), \
                 patch("chronicle_ops.verify.sys.platform", "linux"), \
                 patch("chronicle_ops.verify.run", side_effect=probe) as runtime, \
                 patch("sys.stdout", io.StringIO()) as output:
                self.assertEqual(verify_database_storage("fixture", waiver), expected)
                self.assertEqual(str(Path(mountpoint).resolve()), runtime.call_args_list[0].args[0][-1])
                self.assertIn("database volume", output.getvalue())
        with patch("chronicle_ops.common.run", side_effect=[SimpleNamespace(stdout="")] * 2), \
             patch("chronicle_ops.verify.run", return_value=SimpleNamespace(stdout="")), \
             patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(verify_database_storage("fixture"), 1)
        docker_root = Path('/fixture/docker')
        for status in (0, 1):
            with patch("chronicle_ops.verify.database_volume_path", return_value=None), \
                 patch("chronicle_ops.verify.run", return_value=SimpleNamespace(stdout=str(docker_root))), \
                 patch("chronicle_ops.verify.verify_backup_storage", return_value=status) as probe:
                self.assertEqual(status, verify_database_storage("new-install"))
                probe.assert_called_once_with(docker_root, '', 'database volume')
        fixture = self.doctor_fixture()
        for status, row in (('1', 'fail'), ('0', None)):
            result = self.run_doctor(fixture, DATABASE_STORAGE_STATUS=status)
            self.assertEqual(int(status), result.returncode, result.stderr + result.stdout)
            checks = {check['check']: check for check in json.loads(result.stdout)['checks']}
            self.assertEqual(row, checks.get('database-encryption', {}).get('status'))

    def test_verify_treats_unconfirmed_backup_encryption_as_failure(self):
        from chronicle_ops.verify import verify_configured_backups
        with tempfile.TemporaryDirectory() as folder, \
             patch.dict(os.environ, CHRONICLE_OPS_BACKUPS=str(Path(folder) / 'not-created')), \
             patch('chronicle_ops.verify.verify_backup_storage', return_value=1), \
             patch('chronicle_ops.verify.verify_backup', return_value=0):
            rows = []
            verify_configured_backups({'COMPOSE_FILE': 'docker-compose.yml:overlays/backups.yml'},
                                      lambda ok, message, **kwargs: rows.append((ok, message, kwargs)))
            self.assertEqual((False, {}), (rows[0][0], rows[0][2]))

    def test_reconciliation_opt_out_and_scheduled_up_preserve_host_state(self):
        from chronicle_ops.__main__ import main
        from chronicle_ops.release import OWNER_FILE
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as operator_home, \
             patch.dict(os.environ, HOME=operator_home), \
             patch("chronicle_ops.reconcile.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as crontab, \
             patch.dict(os.environ, CHRONICLE_OPS_STATE=folder, CHRONICLE_OPS_PROJECT="fixture"):
            for update_only in (False, True):
                install(Path(folder) / "chronicle", folder, "fixture", update_only=update_only)
            for action in ("install", "stop", "resume"):
                self.assertEqual(main(["reconcile", action]), 0)
            self.assertTrue(any(call.args[0] == ["crontab", "-"] for call in crontab.call_args_list))
            self.assertEqual([path.name for path in Path(folder).iterdir()], [OWNER_FILE])

    def test_reconciliation_preserves_cron_and_tracks_bundle(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            launcher = state / "bundle" / "chronicle"
            launcher.parent.mkdir()
            launcher.write_text("")
            (state / 'release-manifest.json').write_text('{}')
            old = "3 2 * * * other-job\n@reboot old # chronicle-reconcile:fixture\n"
            with patch("chronicle_ops.reconcile.platform.system", return_value="Linux"), \
                 patch.dict(os.environ, {ENABLED_ENV: "true", "HOME": folder}), \
                 patch("chronicle_ops.reconcile.shutil.which", return_value="/fixture/tool"), \
                 patch("chronicle_ops.reconcile.run", return_value=SimpleNamespace(returncode=0, stdout=old, stderr="")) as run:
                install(launcher, state, "fixture")
                cron = run.call_args.kwargs["input"]
                self.assertIn("3 2 * * * other-job", cron)
                self.assertNotIn("@reboot old", cron)
                self.assertEqual(cron.count("# chronicle-reconcile:fixture"), 3)
                self.assertIn('--check-updates # chronicle-reconcile:fixture', cron)
                script = state / "reconcile.sh"
                self.assertEqual(script.stat().st_mode & 0o777, 0o700)
                self.assertIn("CHRONICLE_RECONCILE_RUN=true ./chronicle up || up_status=$?", script.read_text())
                self.assertIn("./chronicle doctor && ((up_status == 0))", script.read_text())
                self.assertIn(".chronicle-stopped", script.read_text())
                next_launcher = state / "new" / "chronicle"
                next_launcher.parent.mkdir()
                next_launcher.write_text("")
                install(next_launcher, state, "fixture", update_only=True)
                self.assertIn(str(next_launcher.parent), script.read_text())

    def test_scheduled_reconciliation_respects_manual_shutdown(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            launcher = state / "chronicle"
            copy_selfhost_fixture(state)
            (state / ".env").write_text(ENABLED_ENV + "=true\n")
            calls = state / "calls"
            launcher.write_text('#!/usr/bin/env bash\nprintf "%s %s\\n" "$1" "${CHRONICLE_RECONCILE_RUN:-false}" >>"$CALLS"\n[[ "$1" != up || "${UP_FAILURE_FIXTURE:-false}" != true ]]\n')
            launcher.chmod(0o700)
            tools = state / "bin"
            tools.mkdir()
            (tools / "logger").write_text("#!/usr/bin/env bash\nexit 0\n")
            (tools / "logger").chmod(0o700)
            with patch("chronicle_ops.reconcile.platform.system", return_value="Linux"), \
                 patch.dict(os.environ, {ENABLED_ENV: "true", "HOME": folder}), \
                 patch("chronicle_ops.reconcile.shutil.which", return_value="/fixture/tool"), \
                 patch.dict(os.environ, PATH=str(tools) + ":" + os.environ["PATH"]), \
                 patch("chronicle_ops.reconcile.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
                install(launcher, state, "fixture")
            script = state / "reconcile.sh"
            environment = dict(os.environ, CALLS=str(calls))
            subprocess.run(["bash", str(script)], env=environment, check=True, timeout=10)
            expected_calls = "up true\ndoctor false\n"
            self.assertEqual(calls.read_text(), expected_calls)
            calls.unlink()
            failure = subprocess.run(["bash", str(script)], env=dict(environment, UP_FAILURE_FIXTURE="true"), timeout=10)
            self.assertNotEqual(failure.returncode, 0)
            self.assertEqual(calls.read_text(), expected_calls)
            calls.unlink()
            (state / STOP_MARKER).touch()
            subprocess.run(["bash", str(script)], env=environment, check=True, timeout=10)
            self.assertFalse(calls.exists())
            source = script.read_text()
            self.assertLess(source.index("operation-lock"), source.index(STOP_MARKER))

    def test_monitoring_daemon_ownership_and_docker_api_boundary(self):
        import yaml
        services = yaml.safe_load((ROOT / "selfhost/overlays/monitoring.yml").read_text())["services"]
        for daemon in ("victoriametrics", "victorialogs", "fluent-bit", "grafana"):
            with self.subTest(daemon=daemon):
                self.assertNotEqual(services[daemon]["user"].split(":")[0], "0")
                self.assertTrue(services[daemon]["read_only"])
        for daemon in ("victoriametrics", "victorialogs", "fluent-bit"):
            self.assertIn("monitoring-config", services[daemon]["depends_on"])
        proxy = services["docker-socket-proxy"]
        self.assertTrue(proxy["read_only"])
        self.assertEqual(proxy["entrypoint"], ["haproxy"])
        self.assertEqual(proxy["networks"], ["docker-api"])
        config = (ROOT / "selfhost/monitoring/docker-api.cfg").read_text()
        pattern = next(line.split("path_reg ", 1)[1] for line in config.splitlines() if "path_reg " in line)
        self.assertIn("acl read_method method GET", config)
        self.assertIn("deny_status 403 unless read_method allowed_path", config)
        for path, allowed in (("/version", True), ("/v1.45/containers/abc123/stats", True),
                              ("/containers/abc123/archive", False), ("/containers/create", False),
                              ("/images/json", False), ("/volumes", False)):
            self.assertEqual(bool(re.fullmatch(pattern, path)), allowed, path)

    def test_grafana_credentials_require_verified_https(self):
        from urllib.error import URLError
        client = ROOT / "selfhost/monitoring/grafana-user.py"
        context = ssl.create_default_context()
        for base, transport_failure in (("https://grafana", False), ("http://grafana", False), ("https://grafana", True)):
            inputs = io.BytesIO(b"\0".join(value.encode() for value in (base, "fixture-admin-password", "remove", "observer", "")) + b"\0")
            response = unittest.mock.MagicMock()
            response.__enter__.return_value.status = 200
            response.__enter__.return_value.read.side_effect = [b'{"id":1}', b'{}']
            with self.subTest(base=base, transport_failure=transport_failure), \
                 patch("sys.stdin", SimpleNamespace(buffer=inputs)), patch("sys.stdout", io.StringIO()), \
                 patch.dict(os.environ, GRAFANA_CA_FILE="fixture-ca.crt"), \
                 patch("ssl.create_default_context", return_value=context) as tls, \
                 patch("urllib.request.ProxyHandler") as proxies, patch("urllib.request.HTTPSHandler") as handler, \
                 patch("urllib.request.build_opener") as opener:
                request = opener.return_value.open
                request.return_value = response
                if transport_failure:
                    request.side_effect = URLError("certificate verification failed")
                if base.startswith("http:") or transport_failure:
                    with self.assertRaises(SystemExit):
                        runpy.run_path(str(client))
                else:
                    runpy.run_path(str(client))
                    tls.assert_called_once_with(cafile="fixture-ca.crt")
                    # Verified TLS to the private listener, never through an inherited proxy.
                    handler.assert_called_once_with(context=context)
                    self.assertTrue(context.check_hostname)
                    self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
                    proxies.assert_called_once_with({})
                    opener.assert_called_once_with(proxies.return_value, handler.return_value)
                    self.assertEqual([call.args[0].method for call in request.call_args_list], ["GET", "DELETE"])
                if base.startswith("http:"):
                    request.assert_not_called()

    def test_grafana_viewer_changes_report_their_outcome_or_the_refusal(self):
        from urllib.error import HTTPError
        client = ROOT / "selfhost/monitoring/grafana-user.py"
        lookup = "/api/users/lookup?loginOrEmail=ana.p%C3%A9rez%2Bpiloto%40estudio.cl"
        password = "fixture-viewer-password"

        class Answer:
            def __init__(self, status, body):
                self.status, self.body = status, body
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def read(self):
                return self.body

        def viewer(operation, answers, fields=None):
            sent = []
            def open_request(request, timeout):
                path = request.full_url.removeprefix("https://grafana:3000")
                sent.append((request.method, path, json.loads(request.data) if request.data else None))
                status, body = answers[(request.method, path)]
                if status >= 400:
                    raise HTTPError(request.full_url, status, "error", {}, io.BytesIO(body))
                return Answer(status, body)
            values = fields or ("https://grafana:3000/", "fixture-admin-password", operation,
                                "ana.p\u00e9rez+piloto@estudio.cl", password)
            stdin = SimpleNamespace(buffer=io.BytesIO(b"\0".join(value.encode() for value in values) + b"\0"))
            with patch("sys.stdin", stdin), patch("sys.stdout", new_callable=io.StringIO) as output, \
                 patch.dict(os.environ, GRAFANA_CA_FILE="fixture-ca.crt"), \
                 patch("ssl.create_default_context", return_value=ssl.create_default_context()), \
                 patch("urllib.request.build_opener", return_value=SimpleNamespace(open=open_request)):
                try:
                    runpy.run_path(str(client))
                    return output.getvalue(), sent
                except SystemExit as exit:
                    return str(exit), sent

        missing = (404, b'{"message":"user not found"}')
        created = {("GET", lookup): missing, ("POST", "/api/admin/users"): (200, b'{"id":7}'), ("PATCH", "/api/org/users/7"): (200, b"")}
        output, sent = viewer("add", created)
        self.assertEqual("Grafana Viewer 'ana.p\u00e9rez+piloto@estudio.cl' created.\n", output)
        self.assertEqual([("GET", lookup, None),
                          ("POST", "/api/admin/users", {"name": "ana.p\u00e9rez+piloto@estudio.cl",
                                                        "login": "ana.p\u00e9rez+piloto@estudio.cl", "password": password}),
                          ("PATCH", "/api/org/users/7", {"role": "Viewer"})], sent)
        output, sent = viewer("reset", {("GET", lookup): (200, b'{"id":9}'), ("PUT", "/api/admin/users/9/password"): (200, b"{}")})
        self.assertEqual("Grafana Viewer 'ana.p\u00e9rez+piloto@estudio.cl' updated.\n", output)
        self.assertEqual(("PUT", "/api/admin/users/9/password", {"password": password}), sent[-1])
        for operation, answers, message, requests in (
                ("add", {("GET", lookup): (200, b'{"id":3}')}, "that login already exists", 1),
                ("add", {("GET", lookup): (500, b'{"message":"database is locked"}')}, "Grafana returned HTTP 500: database is locked", 1),
                ("add", {**created, ("POST", "/api/admin/users"): (200, b'{"message":"User created"}')},
                 "Grafana created the user without returning an id", 2),
                ("add", {**created, ("POST", "/api/admin/users"): (412, b"<html>password policy</html>")},
                 "Grafana returned HTTP 412", 2),
                ("add", {**created, ("POST", "/api/admin/users"): (202, b"{}")}, "Grafana returned HTTP 202", 2),
                ("remove", {("GET", lookup): (200, b'{"login":"other"}')}, "Grafana lookup did not return an id", 1),
                ("reset", {("GET", lookup): (200, b"{}")}, "Grafana lookup did not return an id", 1)):
            with self.subTest(operation=operation, message=message):
                output, sent = viewer(operation, answers)
                self.assertEqual("monitoring viewer: " + message, output)
                self.assertEqual(requests, len(sent))
                self.assertNotIn("fixture-admin-password", output)
        for fields, message in ((("https://grafana:3000", "admin", "add", "ana"), "invalid credential input"),
                                (("https://grafana:3000", "admin", "promote", "ana", ""), "unsupported operation")):
            with self.subTest(message=message):
                self.assertEqual(("monitoring viewer: " + message, []), viewer(None, {}, fields))

    def test_jmh_malformed_and_incompatible_results_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            base, result = Path(folder) / "base.json", Path(folder) / "result.json"
            valid = [{"benchmark": "fixture", "primaryMetric": {"score": 100}}]
            base.write_text(json.dumps(valid))
            for contents, expected in (("{", 1), ('{"not":"JMH"}', 1), ('[{"benchmark":"fixture"}]', 1), (json.dumps(valid), 0)):
                result.write_text(contents)
                run = subprocess.run(["bash", str(ROOT / "scripts/jmh-regression-gate.sh"), str(base), str(result)], capture_output=True, timeout=10)
                self.assertEqual(int(run.returncode != 0), expected, run.stdout + run.stderr)

    def test_dogfood_help_and_optional_report_work_without_study(self):
        environment = dict(os.environ)
        environment.pop("CHRONICLE_STUDY_ID", None)
        for name in ("android-debug-bundle.sh", "chronicle-long-run-dogfood.sh"):
            run = subprocess.run(["bash", str(ROOT / "scripts" / name), "--help"], env=environment, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
        with tempfile.TemporaryDirectory() as folder:
            adb = Path(folder) / "adb"
            adb.write_text("#!/usr/bin/env bash\nexit 0\n")
            adb.chmod(0o700)
            environment["ADB"] = str(adb)
            for extra in (["--no-db-report"], ["--study-id", "fixture"]):
                run = subprocess.run(["bash", str(ROOT / "scripts/android-debug-bundle.sh"), "--serial", "fixture", "--output-dir", folder, *extra], env=environment, capture_output=True, timeout=10)
                self.assertEqual(run.returncode, 0, run.stderr)

    def test_path_java_selects_native_smoke(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "scripts").mkdir()
            shutil.copy(ROOT / "scripts/chronicle-server-auth-smoke.sh", root / "scripts")
            commands = root / "bin"
            commands.mkdir()
            work = root / "work"
            work.mkdir()
            (work / "gradlew").write_text('#!/usr/bin/env bash\nprintf "native executed\\n"\n')
            (work / "gradlew").chmod(0o700)
            for name in ("java", "rsync"):
                (commands / name).write_text("#!/usr/bin/env bash\nexit 0\n")
                (commands / name).chmod(0o700)
            env = dict(os.environ, PATH=str(commands) + ":/usr/bin:/bin",
                       CHRONICLE_SERVER_SMOKE_WORKDIR=str(work), GRADLE_USER_HOME=str(root / "gradle"))
            env.pop("JAVA_HOME", None)
            env.pop("JAVA_BIN", None)
            run = subprocess.run(["bash", str(root / "scripts/chronicle-server-auth-smoke.sh")], env=env, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn(b"native executed", run.stdout)

    def test_rollback_checks_requested_namespace(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "scripts").mkdir()
            shutil.copy(ROOT / "scripts/chronicle-rollback-smoke.sh", root / "scripts")
            child = root / "scripts/chronicle-post-deploy-smoke.sh"
            child.write_text("#!/usr/bin/env bash\nexit 0\n")
            child.chmod(0o700)
            kubectl = root / "kubectl"
            kubectl.write_text('#!/usr/bin/env bash\nif [[ "$2" == staging ]]; then echo fixture:wrong; else echo fixture:expected; fi\n')
            kubectl.chmod(0o700)
            env = dict(os.environ, KUBECTL_BIN=str(kubectl), CHRONICLE_EXPECTED_BACKEND_IMAGE="fixture:expected")
            run = subprocess.run(["bash", str(root / "scripts/chronicle-rollback-smoke.sh"), "--namespace", "staging"], env=env, capture_output=True, timeout=10)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn(b"actual=fixture:wrong", run.stdout)

    def test_kotlin_shorthand_plugin_drift_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "scripts").mkdir()
            (root / "module").mkdir()
            shutil.copy(ROOT / "scripts/plugin-drift-detect.sh", root / "scripts")
            (root / "settings.gradle.kts").write_text('kotlin("jvm") version "2.3.0"')
            (root / "module/build.gradle.kts").write_text('kotlin("jvm") version "2.2.0"')
            run = subprocess.run(["bash", str(root / "scripts/plugin-drift-detect.sh")], env=dict(os.environ, EVENT_NAME="pull_request", PR_NUMBER=""), capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertIn(b"org.jetbrains.kotlin.jvm is at 2.2.0", run.stdout)

    def test_diagnostic_drift_in_each_consumer_fails(self):
        import yaml
        module = importlib.util.spec_from_file_location("drift", ROOT / "tests/security/contract-drift-diff.py")
        drift = importlib.util.module_from_spec(module)
        module.loader.exec_module(drift)
        spec = yaml.safe_load((ROOT / "chronicle-api/chronicle.yaml").read_text())["components"]["schemas"]
        drift.check_upload_diagnostics(ROOT, spec)
        self.assertEqual(drift.failures, [])
        original = Path.read_text
        # Each consumer loses a recognized code in its own syntax. The wire field accepts future codes;
        # the generated web catalog describes the codes this server recognizes.
        removals = {"AndroidUploadIssueCode.kt": "COLLECTION_ACCESS_MISSING", "V1__fresh_schema.sql": "'COLLECTION_ACCESS_MISSING',",
                    "LocalUploadDiagnosticsStore.kt": "COLLECTION_ACCESS_MISSING", "chronicle-contracts.ts": "  'COLLECTION_ACCESS_MISSING',"}
        mutations = [(target, old, "", "missing ['COLLECTION_ACCESS_MISSING']") for target, old in removals.items()]
        mutations += [
            ("LocalUploadDiagnosticsStore.kt", "HTTP_SERVER_ERROR", "", "missing ['HTTP_SERVER_ERROR']"),
            # A server-assigned code is not in the phone's catalog; once unmarked, the phone must carry it.
            ("chronicle.linkml.yaml", "serverAssigned:\n            value: true", "serverAssigned:\n            value: false",
             "upload diagnostics Android issueCode: missing ['UNRECOGNIZED_ISSUE']"),
            ("LocalUploadDiagnosticsStore.kt", "HTTP_SERVER_ERROR", "HTTP_SERVER_ERROR, UNRECOGNIZED_ISSUE",
             "upload diagnostics Android issueCode: missing [], extra ['UNRECOGNIZED_ISSUE']"),
        ]
        for target, old, new, expected in mutations:
            def changed(path, *args, **kwargs):
                text = original(path, *args, **kwargs)
                return text.replace(old, new) if path.name == target else text
            drift.failures.clear()
            with self.subTest(target=target, old=old, new=new), patch.object(Path, "read_text", changed):
                drift.check_upload_diagnostics(ROOT, copy.deepcopy(spec))
            self.assertIn(expected, "\n".join(drift.failures))

    def test_writable_container_root_requires_justified_exemption(self):
        from host_tools import modern_bash
        with tempfile.TemporaryDirectory() as folder:
            docker = Path(folder) / "docker"
            docker.write_text('#!/usr/bin/env bash\nif [[ "$1" == ps ]]; then echo fixture; else printf "%s\\n" "$INSPECT_FIXTURE"; fi\n')
            docker.chmod(0o700)
            (Path(folder) / 'bash').symlink_to(modern_bash())
            for readonly, reason, expected in ((False, "", 1), (False, "Required cache path; approved test exception", 0), (True, "", 0)):
                fixture = [{"Name": "/fixture", "Config": {"User": "1001", "Labels": {WRITABLE_ROOT_REASON_LABEL: reason}},
                            "HostConfig": {"ReadonlyRootfs": readonly, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "Memory": 1048576}, "Mounts": []}]
                env = dict(os.environ, PATH=folder + ":/usr/bin:/bin", INSPECT_FIXTURE=json.dumps(fixture))
                run = subprocess.run(["bash", str(ROOT / "tests/security/container-security-tests.sh")], env=env, capture_output=True, timeout=10)
                self.assertEqual(run.returncode, expected, run.stdout + run.stderr)

    def test_nonweb_writable_service_fails_configuration_contract(self):
        import yaml
        from chronicle_ops.verify import service_contract_violations
        with tempfile.TemporaryDirectory() as folder:
            compose = Path(folder) / "docker-compose.yml"
            service = {"image": "fixture", "logging": {}, "security_opt": ["no-new-privileges:true"],
                       "cap_drop": ["ALL"], "pids_limit": 64, "mem_limit": "64m", "network_mode": "none"}
            for readonly, reason, passes in ((False, "", False), (False, "Reviewed writable cache requirement", True), (True, "", True)):
                service.update(read_only=readonly, labels={WRITABLE_ROOT_REASON_LABEL: reason})
                compose.write_text(yaml.safe_dump({"services": {"queue": service}}))
                violations = service_contract_violations([str(compose)])
                self.assertEqual(violations == "", passes, violations)
                if not passes:
                    self.assertIn("queue root filesystem is writable without a justified exemption", violations)

    def test_default_database_disk_warning_without_monitoring(self):
        from chronicle_ops.verify import capacity_checks
        for free, expected in ((0, "warn"), (14, "warn"), (15, "ok"), (50, "ok")):
            result = SimpleNamespace(stdout=f'Filesystem blocks used available percent mount\ndisk 100 90 10 {100-free}% /db\n' + json.dumps({'database_bytes': 1, 'wal_bytes': 0, 'max_wal_bytes': 1}))
            with patch("chronicle_ops.verify.compose", return_value=result) as compose, \
                 patch("chronicle_ops.verify.storage_report", return_value=[]):
                rows = capacity_checks({}, "/unused")
            self.assertEqual(rows[0][:2], ("database-disk", expected))
            compose.assert_called_once()

    def test_pilot_load_runner_refuses_a_k6_older_than_the_documented_baseline(self):
        # k6 v0.50.0 cannot parse the load script and exits before any request; the README names the baseline.
        documented = re.search(r"Install k6 v(\d+\.\d+\.\d+) or newer", (ROOT / "tests/load/README.md").read_text())
        self.assertIsNotNone(documented, "tests/load/README.md must name the oldest supported k6")
        major, minor, patch_level = map(int, documented[1].split("."))
        with tempfile.TemporaryDirectory() as folder:
            tools, calls = Path(folder) / "bin", Path(folder) / "calls"
            tools.mkdir()
            for tool in ("docker", "k6"):
                (tools / tool).write_text(f'#!/bin/sh\n[ "$1" = version ] && [ {tool} = k6 ] && '
                                          f'echo "$K6_FIXTURE_VERSION_OUTPUT (commit/fixture)" && exit 0\n'
                                          f'echo "{tool} $*" >> "{calls}"\n')
                (tools / tool).chmod(0o755)
            for version, prefix, accepted in ((f"{major}.{minor - 1}.9", "", False), ("0.50.0", "", False), (documented[1], "", True),
                                              (f"{major}.{minor}.{patch_level + 1}", "", True), (f"{major + 1}.0.0", "", True),
                                              (documented[1], "version ", True), ("1.0.0", "version ", True),
                                              ("0.50.0", "version ", False), ("unknown", "", False)):
                report = Path(folder) / ("report-" + prefix.strip() + version)
                calls.unlink(missing_ok=True)
                with self.subTest(version=version, prefix=prefix):
                    run = subprocess.run(["bash", str(ROOT / "scripts/chronicle-pilot-load.sh")], capture_output=True, text=True, timeout=20,
                                         env=dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}",
                                                  K6_FIXTURE_VERSION_OUTPUT=f"k6 {prefix}v{version}",
                                                  BASE_URL="https://synthetic.example.test", DEVICE_FIXTURES_FILE="/unused/devices.json",
                                                  STUDY_ID="00000000-0000-0000-0000-000000000001", COMPOSE_PROJECT_NAME="synthetic-load",
                                                  CHRONICLE_LOAD_REPORT_DIR=str(report)))
                    self.assertEqual(accepted, run.returncode == 0, run.stderr)
                    invoked = calls.read_text() if calls.exists() else ""
                    self.assertEqual(accepted, "k6 run " in invoked, invoked)
                    if not accepted:
                        self.assertIn(f"older than the required v{documented[1]}", run.stderr)
                        self.assertEqual("", invoked)
                        self.assertFalse(report.exists())

    def test_unmeasured_load_baseline_cannot_pass_release_gate(self):
        run = subprocess.run(["bash", str(ROOT / "scripts/k6-regression-gate.sh"),
                              str(ROOT / "tests/perf/k6-baselines.json"), str(ROOT / "tests/perf/k6-baselines.json")],
                             env=dict(os.environ, K6_ALLOW_UNMEASURED_BUDGET="false"), capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 1)
        self.assertIn(b"unmeasured", run.stderr)
        with tempfile.TemporaryDirectory() as folder:
            current = Path(folder) / "current.json"
            for contents, valid in (("{", False), ('{"metrics":{}}', False),
                                    ((ROOT / "tests/perf/k6-baselines.json").read_text(), True)):
                current.write_text(contents)
                run = subprocess.run(["bash", str(ROOT / "scripts/k6-regression-gate.sh"),
                                      str(ROOT / "tests/perf/k6-baselines.json"), str(current)],
                                     env=dict(os.environ, K6_ALLOW_UNMEASURED_BUDGET="true"), capture_output=True, timeout=10)
                self.assertEqual(run.returncode == 0, valid, run.stdout + run.stderr)

            measured = json.loads((ROOT / "tests/perf/k6-baselines.json").read_text())
            measured["measurement"] = dict(verified=True, runs=2, source_revision="0" * 40,
                                           environment={}, fixtures={})
            baseline = Path(folder) / "measured.json"
            baseline.write_text(json.dumps(measured))
            run = subprocess.run(["bash", str(ROOT / "scripts/k6-regression-gate.sh"), str(baseline), str(current)],
                                 env=dict(os.environ, K6_ALLOW_UNMEASURED_BUDGET="false"), capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)



    def test_missing_fk_index_fails_schema_gate(self):
        script = (ROOT / "scripts/verify-schema-postconditions.sh").read_text()
        block = script[script.index('MISSING_FK_INDEXES='):script.index('echo "== 7.')]
        for output, expected in (("", 0), ("study_participants.fixture_fk", 7)):
            commands = 'psql_scalar() { printf %s "$MISSING_FIXTURE"; }; ok() { :; }; fail() { exit 7; };\n'
            run = subprocess.run(["bash", "-eu", "-c", commands + block],
                                 env=dict(os.environ, MISSING_FIXTURE=output), capture_output=True, timeout=10)
            self.assertEqual(run.returncode, expected, run.stderr)

    def test_runbooks_require_retention_purge_and_update_deadlines(self):
        deletion = (ROOT / "selfhost/docs/UNINSTALL-DATA-DELETION.md").read_text()
        for text in ("protocol retention deadline", "Delete Study", "approved retention schedule", "superuser", "indefinitely", "controlled"):
            self.assertIn(text, deletion)
        guide = (ROOT / "selfhost/README.md").read_text()
        for text in ("48 hours", "7 days", "30 days", "90 days", "default-branch", "latest"):
            self.assertIn(text, guide)

    def test_nonstandard_https_redirect_uses_canonical_origin(self):
        line = next(line.strip() for line in (ROOT / "selfhost/Caddyfile.split.tls").read_text().splitlines() if 'redir {$CHRONICLE_PUBLIC_BASE_URL}' in line)
        expanded = line.replace("{$CHRONICLE_PUBLIC_BASE_URL}", "https://fixture.example:8443").replace("{uri}", "/health")
        self.assertEqual(expanded, "redir https://fixture.example:8443/health permanent")
