"""Operator runtime guards (incident isolation, up ownership, locks, update check, rotation recovery, pruning); synthetic settings, no live services."""

import fcntl
import io
import os
from pathlib import Path
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'selfhost'))
from selfhost_fixture import copy_selfhost_fixture
from test_secret_generation import SelfhostSetupFixture
from chronicle_ops import envfile, common, reconcile, release


def crontab_fixture(root, readers=1):
    """A file-backed `crontab` whose -l waits (bounded) until `readers` processes have read, so two
    installs that do not exclude each other both read before either writes."""
    commands = root / 'bin'; commands.mkdir(exist_ok=True)
    # These fixtures exercise Linux cron without changing the Mac trial's explicit refusal.
    hooks = root / 'linux-cron-fixture'; hooks.mkdir(exist_ok=True)
    mock_platform = 'import platform\nplatform.system = lambda: "Linux"\n'
    (hooks / 'sitecustomize.py').write_text(mock_platform)
    if (root / 'selfhost').is_dir():
        (root / 'selfhost/sitecustomize.py').write_text(mock_platform)
    (commands / 'crontab').write_text('''#!/usr/bin/env python3
import os, sys, time
from pathlib import Path
store = Path(os.environ['CRONTAB_STORE'])
if sys.argv[1:] == ['-l']:
    snapshot = store.read_text() if store.exists() else None
    barrier = Path(os.environ['CRONTAB_BARRIER']); barrier.mkdir(exist_ok=True)
    (barrier / str(os.getpid())).touch()
    deadline = time.monotonic() + 2
    while len(list(barrier.iterdir())) < int(os.environ['CRONTAB_READERS']) and time.monotonic() < deadline:
        time.sleep(0.02)
    if snapshot is None:
        sys.exit('no crontab for fixture')
    sys.stdout.write(snapshot)
elif sys.argv[1:] == ['-']:
    if os.environ.get('CRONTAB_REFUSE_WRITE'):
        sys.exit('crontab: fixture refused the write')
    data = sys.stdin.read()
    store.with_name('crontab.' + str(os.getpid()) + '.new').write_text(data)
    os.replace(store.with_name('crontab.' + str(os.getpid()) + '.new'), store)
else:
    sys.exit('unexpected crontab arguments')
''')
    (commands / 'logger').write_text('#!/bin/sh\nexit 0\n')
    for name in ('crontab', 'logger'):
        (commands / name).chmod(0o755)
    store = root / 'crontab'
    environment = dict(os.environ, HOME=str(root), PYTHONPATH=str(hooks) + os.pathsep + str(ROOT / 'selfhost'), CRONTAB_STORE=str(store),
                       CRONTAB_BARRIER=str(root / 'barrier'), CRONTAB_READERS=str(readers),
                       PATH=str(commands) + os.pathsep + os.environ['PATH'], **{reconcile.ENABLED_ENV: 'true'})
    return store, environment


class OperatorRuntimeGuardTests(unittest.TestCase):
    def test_incident_listener_isolation_pauses_boot_and_periodic_reconciliation(self):
        from chronicle_ops.__main__ import main
        result = subprocess.run(['bash', '-c', 'source "$1"; validate_command_arguments reconcile stop; printf parsed',
                                 'fixture', str(ROOT / 'selfhost/chronicle')], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(b'parsed', result.stdout)
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder); active = state / 'active'; active.mkdir()
            (active / '.env').write_text(reconcile.ENABLED_ENV + '=true\n')
            (active / 'chronicle_ops').symlink_to(ROOT / 'selfhost/chronicle_ops', target_is_directory=True)
            calls = state / 'calls'
            launcher = active / 'chronicle'
            launcher.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >>"$CALLS"\n')
            launcher.chmod(0o755)
            with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'true', 'CHRONICLE_OPS_STATE': str(state),
                                        'CHRONICLE_OPS_PROJECT': 'fixture', 'CALLS': str(calls), 'HOME': folder}, clear=False), \
                 patch('chronicle_ops.reconcile.platform.system', return_value='Linux'), \
                 patch('chronicle_ops.reconcile.shutil.which', return_value='/fixture/tool'), \
                 patch('chronicle_ops.reconcile.run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as cron:
                reconcile.install(launcher, state, 'fixture')
                self.assertIn('@reboot', cron.call_args.kwargs['input'])
                self.assertIn(f'*/{reconcile.INTERVAL_MINUTES}', cron.call_args.kwargs['input'])
                self.assertEqual(main(['reconcile', 'resume']), 0)
                subprocess.run(['bash', str(state / 'reconcile.sh')], capture_output=True, timeout=10)
                self.assertIn('up', calls.read_text().split())
                calls.unlink()
                self.assertEqual(main(['reconcile', 'stop']), 0)
                result = subprocess.run(['bash', str(state / 'reconcile.sh')], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(calls.exists())

    def test_only_the_first_schedule_install_leaves_the_first_start_to_the_operator(self):
        # A fresh host must not be started by cron before `restore --no-start` can run; a host whose
        # schedule already exists (setup rerun) or that was just started and verified (update) keeps
        # its running stack reconciled.
        scheduled = "@reboot /state/reconcile.sh # chronicle-reconcile:fixture\n"
        for name, crontab, update_only, first, paused, returncode, stderr in (
            ('first install', '', False, True, True, 1, 'no crontab for fixture'),
            ('other project only', scheduled.replace(':fixture', ':fixture-other'), False, True, True, 0, ''),
            ('reinstall', scheduled, False, True, False, 0, ''),
            ('verified start, schedule lost', '', False, False, False, 1, 'no crontab for fixture'),
            ('update only', scheduled, True, False, False, 0, ''),
            ('update without schedule', '', True, False, False, 0, ''),
            ('unreadable crontab', '', False, True, None, 1, 'Permission denied'),
            ('unreadable crontab on update', '', True, False, None, 2, 'crontab unavailable'),
        ):
            with self.subTest(name), tempfile.TemporaryDirectory() as folder:
                state = Path(folder); active = state / 'active'; active.mkdir()
                (state / 'reconcile.sh').write_text('previous launcher\n')
                with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'true', 'HOME': folder}), \
                     patch('chronicle_ops.reconcile.platform.system', return_value='Linux'), \
                     patch('chronicle_ops.reconcile.shutil.which', return_value='/fixture/tool'), \
                     patch('chronicle_ops.reconcile.run', side_effect=lambda args, **_: SimpleNamespace(  # the write succeeds
                         returncode=returncode if args == ['crontab', '-l'] else 0, stdout=crontab, stderr=stderr)) as cron:
                    if paused is None:
                        with self.assertRaisesRegex(ValueError, 'could not read the operator crontab'):
                            reconcile.install(active / 'chronicle', state, 'fixture', update_only=update_only, before_first_start=first)
                        self.assertEqual(cron.call_count, 1)
                        self.assertEqual((state / 'reconcile.sh').read_text(), 'previous launcher\n')
                        self.assertFalse((state / reconcile.STOP_MARKER).exists())
                        continue
                    reconcile.install(active / 'chronicle', state, 'fixture', update_only=update_only, before_first_start=first)
                self.assertIn('@reboot', cron.call_args.kwargs['input'])
                if paused and crontab:
                    self.assertIn(crontab, cron.call_args.kwargs['input'])
                self.assertEqual(paused, (state / reconcile.STOP_MARKER).exists())
                if paused:
                    self.assertIn('./chronicle up', (state / reconcile.STOP_MARKER).read_text())

    def test_schedule_install_refuses_hosts_and_paths_cron_cannot_run(self):
        # cron reads % in a command as a newline; macOS has no operator crontab reconciliation.
        for case, system, missing, directory, error in (
                ('macOS', 'Darwin', None, 'active', 'requires a Linux operator crontab'),
                ('no logger', 'Linux', 'logger', 'active', 'requires crontab and logger on PATH'),
                ('symlinked launcher', 'Linux', None, 'active', 'unsafe reconciliation launcher'),
                ('percent in path', 'Linux', None, 'pilot%2026', 'cron control characters')):
            with self.subTest(case), tempfile.TemporaryDirectory() as folder:
                state = Path(folder); active = state / directory; active.mkdir()
                if case == 'symlinked launcher':
                    (state / 'elsewhere.sh').write_text('previous launcher\n')
                    (state / 'reconcile.sh').symlink_to(state / 'elsewhere.sh')
                with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'true', 'HOME': folder}), \
                     patch('chronicle_ops.reconcile.platform.system', return_value=system), \
                     patch('chronicle_ops.reconcile.shutil.which', side_effect=lambda tool: None if tool == missing else '/usr/bin/' + tool), \
                     patch('chronicle_ops.reconcile.run') as cron:
                    with self.assertRaisesRegex(ValueError, error):
                        reconcile.install(active / 'chronicle', state, 'fixture')
                self.assertEqual([], cron.call_args_list)  # the operator crontab is untouched
                self.assertFalse((state / reconcile.STOP_MARKER).exists())
                self.assertEqual(case == 'symlinked launcher', os.path.lexists(state / 'reconcile.sh'))

    def test_a_crontab_the_operator_cannot_write_or_an_invalid_project_changes_nothing(self):
        for case, project, write_status, error in (
                ('cron.deny refuses the operator', 'fixture', 1, 'could not write the operator crontab; check `crontab -l`'),
                ('uppercase project name', 'Chronicle Pilot', 0, 'invalid reconciliation project')):
            with self.subTest(case), tempfile.TemporaryDirectory() as folder:
                state = Path(folder); active = state / 'active'; active.mkdir()
                kept = '0 1 * * * /usr/local/bin/lab-sync\n'
                calls = []
                def cron(args, **kwargs):
                    calls.append(args)
                    return SimpleNamespace(returncode=write_status if args == ['crontab', '-'] else 0, stdout=kept, stderr='')
                with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'true', 'HOME': folder}), \
                     patch('chronicle_ops.reconcile.platform.system', return_value='Linux'), \
                     patch('chronicle_ops.reconcile.shutil.which', return_value='/usr/bin/tool'), \
                     patch('chronicle_ops.reconcile.run', side_effect=cron):
                    with self.assertRaisesRegex(ValueError, error):
                        reconcile.install(active / 'chronicle', state, project)
                self.assertEqual([['crontab', '-l'], ['crontab', '-']] if write_status else [], calls)

    def test_an_empty_marker_that_cannot_be_removed_is_kept_and_still_blocks(self):
        from chronicle_ops import common
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ):
            os.environ.pop(common.LOCK_FD_ENV, None)
            marker = Path(folder) / reconcile.UPGRADE_LOCK
            marker.mkdir()
            descriptor = None
            try:
                with patch.object(Path, 'rmdir', side_effect=PermissionError(13, 'Permission denied')), \
                     patch('sys.stderr', new_callable=io.StringIO) as warnings:
                    descriptor = common.acquire_operation_lock(folder)  # tries to clear it, and cannot
                    with self.assertRaisesRegex(ValueError, 'empty marker .* recorded no changes; ./chronicle up clears it'):
                        reconcile.check_mutations(folder, Path(folder) / 'chronicle')
                self.assertTrue(marker.is_dir())
                self.assertNotIn('cleared the empty marker', warnings.getvalue())
            finally:
                common.release_operation_lock(descriptor)

    def test_restore_on_a_deployment_without_a_schedule_does_not_install_one(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder); previous = state / 'previous'; previous.mkdir()
            with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'true', 'HOME': folder}), \
                 patch('chronicle_ops.reconcile.run') as cron:
                reconcile.install(previous / 'chronicle', state, 'fixture', update_only=True)
            self.assertEqual([], cron.call_args_list)
            self.assertFalse((state / 'reconcile.sh').exists())

    def test_the_scheduled_job_follows_the_saved_setting(self):
        # The cron script re-reads .env on every run, so disabling reconciliation there stops it without reinstalling.
        with tempfile.TemporaryDirectory() as folder:
            settings = Path(folder) / '.env'
            for content, enabled in (('CHRONICLE_RECONCILE_ENABLED=false\n', False), ('CHRONICLE_RECONCILE_ENABLED=true\n', True),
                                     ('COMPOSE_PROJECT_NAME=chronicle\n', True)):
                with self.subTest(content=content):
                    settings.write_text(content)
                    self.assertEqual(enabled, reconcile.saved_enabled(folder))

    def schedule_command(self, root, project, action, environment):
        host = root / project / 'selfhost'; state = root / project / 'state'
        host.mkdir(parents=True, exist_ok=True); state.mkdir(exist_ok=True)
        (host / 'chronicle').touch()
        process = subprocess.Popen([sys.executable, '-m', 'chronicle_ops', 'reconcile', action], cwd=host,
                                env=dict(environment, CHRONICLE_OPS_STATE=str(state), CHRONICLE_OPS_PROJECT=project),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(process.communicate, timeout=10)
        self.addCleanup(process.kill)
        return process

    def test_concurrent_projects_never_lose_each_others_schedule(self):
        unrelated = 'MAILTO=operator\n0 1 * * * /usr/local/bin/nightly-report\n'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store, environment = crontab_fixture(root, readers=2)
            store.write_text(unrelated)

            def concurrently(*commands):
                shutil.rmtree(root / 'barrier', ignore_errors=True)
                processes = [self.schedule_command(root, project, action, environment) for project, action in commands]
                for process in processes:
                    _, errors = process.communicate(timeout=60)
                    self.assertEqual(0, process.returncode, errors)
                return store.read_text().splitlines()

            def entries(lines, project):
                return [line for line in lines if line.endswith('# chronicle-reconcile:' + project)]

            lines = concurrently(('alpha', 'install'), ('beta', 'install'))
            for project in ('alpha', 'beta'):
                launcher = str(root / project / 'state/reconcile.sh')
                self.assertEqual(['@reboot ' + launcher + ' # chronicle-reconcile:' + project,
                                  f'*/{reconcile.INTERVAL_MINUTES} * * * * ' + launcher + ' # chronicle-reconcile:' + project],
                                 entries(lines, project), lines)
            self.assertEqual(unrelated.splitlines(), lines[:2], lines)
            lines = concurrently(('alpha', 'uninstall'), ('beta', 'install'))
            self.assertEqual([], entries(lines, 'alpha'), lines)
            self.assertEqual(2, len(entries(lines, 'beta')), lines)
            self.assertEqual(len(lines), len(set(lines)), 'duplicate crontab entries')
            self.assertEqual(unrelated.splitlines(), lines[:2], lines)

    def test_refused_crontab_write_reports_and_keeps_the_previous_crontab(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            store, environment = crontab_fixture(root)
            store.write_text('0 1 * * * unrelated\n')
            process = self.schedule_command(root, 'alpha', 'install', dict(environment, CRONTAB_REFUSE_WRITE='1'))
            _, errors = process.communicate(timeout=60)
            self.assertNotEqual(0, process.returncode)
            self.assertIn('could not write the operator crontab', errors)
            self.assertNotIn('Traceback', errors)
            self.assertEqual('0 1 * * * unrelated\n', store.read_text())

    def test_incident_collection_exports_the_database_audit_trail(self):
        runbook = (ROOT / 'selfhost/docs/INCIDENT-RESPONSE.md').read_text()
        export = runbook[runbook.index('# Database audit trail'):runbook.index('# Operator receipts:')]
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            script = 'set -eu\ncase_dir="$CASE_DIR"\ndocker() { printf "%s\\n" "${@: -1}"; };\n' + export
            result = subprocess.run(['bash', '-c', script], env=dict(os.environ, CASE_DIR=str(state)),
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('FROM public.audit)', (state / 'audit.csv').read_text())
            self.assertIn('ON_ERROR_STOP=1', export)

    def up_fixture(self, root):
        state = root / 'state'; state.mkdir(); (state / 'tls').mkdir()
        active = root / 'active'; retired = root / 'retired'
        settings = f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{state}'\nHTTP_BIND=127.0.0.1\nCOMPOSE_FILE=docker-compose.yml:overlays/mode-behind-proxy-internal.yml\n"
        for host in (active, retired):
            host.mkdir(); (host / '.env').write_text(settings); (host / '.env').chmod(0o600)
        (state / 'reconcile.sh').write_text('cd ' + str(active) + '\n')
        (state / reconcile.STOP_MARKER).touch()
        script = '''set -eu
fixture_host="$PWD"
source "$OPS_PACKAGE/chronicle"
cd "$fixture_host"
BLD= GRN= RST= PROJECT=fixture
STATE_ROOT="$PWD"
die() { echo "$*" >&2; exit 1; }
validate_legacy_mobile_values() { :; }
derive_mode() { :; }
for name in begin_operation assert_no_incomplete_mutation ensure_images preflight operation_succeeded; do
  eval "$name() { :; }"
done
lock_operation() { [[ -z "${LOCKED_SETTINGS:-}" ]] || cp "$LOCKED_SETTINGS" .env; }
ops_python() {
  export COMPOSE_FILE="${COMPOSE_FILE:-}" HTTP_BIND="${HTTP_BIND:-}"
  case "$1" in
    -c) PYTHONPATH="$OPS_PACKAGE" python3 "$@" ;;
    owner-check) PYTHONPATH="$OPS_PACKAGE" python3 - "$STATE_ROOT" "$PROJECT" <<'OWNER'
from pathlib import Path
import sys
from unittest.mock import patch
from chronicle_ops.release import require_current_owner
with patch('chronicle_ops.release.compose_projects', return_value=[]):
    require_current_owner(Path.cwd(), sys.argv[1], sys.argv[2])
OWNER
      ;;
    certificates) CHRONICLE_OPS_STATE="$STATE_ROOT" PYTHONPATH="$OPS_PACKAGE" python3 -m chronicle_ops "$@" ;;
    reconcile) [[ "$2" != stopped ]] || return 1
      [[ "$2" != resume ]] || rm -f "$STATE_ROOT/.chronicle-stopped" ;;
  esac
}
dc() {
  printf '%s %s %s\\n' "$HTTP_BIND" "$COMPOSE_FILE" "$*" >>"$CALLS"
  [[ "$*" != 'config --services' ]] || printf 'postgres\\nbackend\\nweb\\n'
}
''' + '\ncmd_up up \"$@\"\n'
        return state, active, retired, settings, script

    def test_up_rejects_superseded_bundle_after_down_and_accepts_active_owner(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state, active, retired, _, script = self.up_fixture(root)
            calls = root / 'calls'
            environment = dict(os.environ, OPS_PACKAGE=str(ROOT / 'selfhost'), CALLS=str(calls),
                               CHRONICLE_RECONCILE_ENABLED='true', CHRONICLE_RECONCILE_RUN='false')
            result = subprocess.run(['bash', '-c', script], cwd=retired, env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('superseded', result.stderr)
            self.assertFalse(calls.exists())
            self.assertTrue((state / reconcile.STOP_MARKER).exists())
            result = subprocess.run(['bash', '-c', script], cwd=active, env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--progress quiet up', calls.read_text())
            self.assertFalse((state / reconcile.STOP_MARKER).exists())

    def test_no_reconcile_up_keeps_the_stop_marker_and_does_not_install_a_schedule(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state, active, _, _, script = self.up_fixture(root)
            calls = root / 'calls'
            script += '\n[[ "$CHRONICLE_RECONCILE_ENABLED" == false ]]\n'
            result = subprocess.run(['bash', '-c', script, 'fixture', '--no-reconcile'], cwd=active,
                env=dict(os.environ, OPS_PACKAGE=str(ROOT / 'selfhost'), CALLS=str(calls),
                         CHRONICLE_RECONCILE_ENABLED='true', CHRONICLE_RECONCILE_RUN='false'),
                capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('--progress quiet up', calls.read_text())
            self.assertTrue((state / reconcile.STOP_MARKER).exists())

    def test_up_reloads_locked_settings_and_rejects_changed_lock_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            _, active, _, settings, script = self.up_fixture(root)
            saved = root / 'locked-settings'; calls = root / 'calls'
            for changes, succeeds in (({'HTTP_BIND': '10.0.0.5', 'HTTP_PORT': '8085', 'COMPOSE_FILE': 'docker-compose.yml:overlays/mode-own-tls-internal.yml'}, True),
                                      ({'COMPOSE_PROJECT_NAME': 'other'}, False),
                                      ({'CHRONICLE_STATE_DIR': str(root)}, False)):
                (active / '.env').write_text(settings)
                latest = envfile.read_env(active / '.env')
                latest.update(changes)
                saved.write_text(''.join(f'{key}={raw}\n' for key, raw in latest.items()))
                calls.unlink(missing_ok=True)
                environment = dict(os.environ, OPS_PACKAGE=str(ROOT / 'selfhost'), CALLS=str(calls),
                                   LOCKED_SETTINGS=str(saved), CHRONICLE_RECONCILE_ENABLED='false')
                result = subprocess.run(['bash', '-c', script], cwd=active, env=environment,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                if succeeds:
                    self.assertIn('10.0.0.5 docker-compose.yml:overlays/mode-own-tls-internal.yml', calls.read_text())
                else:
                    self.assertFalse(calls.exists())

    def test_readable_operation_lock_survives_prestart_failure_and_inheritance(self):
        with tempfile.TemporaryDirectory() as folder:
            descriptor = common.acquire_operation_lock(folder)
            try:
                path = Path(folder) / common.OPERATION_LOCK
                self.assertTrue(path.stat().st_mode & 0o004)
                path.chmod(0o600)
                self.assertIsNone(common.acquire_operation_lock(folder))
                self.assertTrue(path.stat().st_mode & 0o004)
            finally:
                common.release_operation_lock(descriptor)

    def test_managed_update_check_moves_to_active_bundle_and_reports_failures(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); tools = root / 'bin'; tools.mkdir()
            (root / 'release-manifest.json').write_text('{}')
            logger = tools / 'logger'
            logger.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >>"$LOGGER_CALLS"\n')
            logger.chmod(0o755)
            old = root / 'old'; active = root / 'active'
            for host in (old, active):
                host.mkdir()
                copy_selfhost_fixture(host)
                (host / '.env').write_text(reconcile.ENABLED_ENV + '=true\n')
                operator = host / 'chronicle'
                operator.write_text('#!/usr/bin/env bash\n[[ "$*" == "update --check" ]]\nprintf "%s\\n" "$PWD"\nexit "$CHECK_STATUS"\n')
                operator.chmod(0o755)
            with patch.dict(os.environ, {reconcile.ENABLED_ENV: 'true', 'HOME': folder, 'PATH': str(tools) + ':' + os.environ['PATH']}), \
                 patch('chronicle_ops.reconcile.platform.system', return_value='Linux'), \
                 patch('chronicle_ops.reconcile.shutil.which', return_value='/fixture/tool'), \
                 patch('chronicle_ops.reconcile.run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as cron:
                reconcile.install(old / 'chronicle', root, 'fixture')
                reconcile.install(active / 'chronicle', root, 'fixture', update_only=True)
            self.assertIn('--check-updates', cron.call_args.kwargs['input'])
            for code, message in ((0, ''), (release.UPDATE_AVAILABLE_EXIT, 'update available'), (1, 'Update check failed')):
                log = root / 'logger-calls'; log.unlink(missing_ok=True)
                result = subprocess.run(['bash', str(root / 'reconcile.sh'), '--check-updates'],
                    env=dict(os.environ, CHECK_STATUS=str(code), LOGGER_CALLS=str(log)), capture_output=True, timeout=10)
                self.assertEqual(result.returncode, int(code == 1), result.stderr)
                details = root / reconcile.UPDATE_LOG
                self.assertEqual(details.read_text().strip(), str(active))
                self.assertEqual(details.stat().st_mode & 0o777, 0o600)
                if message:
                    self.assertIn(message, log.read_text())
                    self.assertIn('-p user.err' if code == 1 else '-p user.warning', log.read_text())
                else:
                    self.assertFalse(log.exists())

    def test_rotation_recovery_reads_commented_exported_saved_credentials(self):
        from selfhost_fixture import rotation_fixture
        for direction in ('--forward', '--rollback'):
            with self.subTest(direction=direction), tempfile.TemporaryDirectory() as folder:
                fixture = rotation_fixture(Path(folder))
                rotation = fixture.host / '.chronicle-secret-rotation'
                rotation.mkdir(mode=0o700)
                original = (fixture.host / '.env').read_text() + "export JWT_SECRET='synthetic-#-saved' # operator comment\n"
                (fixture.host / '.env').write_text(original.replace('synthetic-#-saved', 'synthetic-#-new'))
                for name, content in dict(kind='jwt', action='rotate', phase='env-published', **{'old.env': original}).items():
                    path = rotation / name
                    path.write_text(content)
                    path.chmod(0o600)
                result = subprocess.run(['bash', str(fixture.host / 'chronicle'), 'rotate-secret', 'recover', direction, '--yes'],
                    env=fixture.environment, capture_output=True, text=True, timeout=20)
                self.assertEqual(0, result.returncode, result.stderr + result.stdout)
                settings = envfile.read_env(fixture.host / '.env')
                self.assertEqual('synthetic-#-saved' if direction == '--rollback' else 'synthetic-#-new',
                                 envfile.value(settings, 'JWT_SECRET'))
                self.assertFalse(rotation.exists())

    def test_rotation_recovery_accepts_reused_pid_under_operation_lock(self):
        from selfhost_fixture import rotation_fixture
        with tempfile.TemporaryDirectory() as folder:
            fixture = rotation_fixture(Path(folder))
            rotation = fixture.host / '.chronicle-secret-rotation'
            rotation.mkdir(mode=0o700)
            (rotation / 'owner-pid').write_text(str(os.getpid()) + '\n')
            descriptor = common.acquire_operation_lock(fixture.host)
            try:
                result = subprocess.run(['bash', str(fixture.host / 'chronicle'), 'rotate-secret', 'recover', '--rollback', '--yes'],
                    env=dict(fixture.environment, **{common.LOCK_FD_ENV: str(descriptor)}),
                    capture_output=True, text=True, timeout=20, pass_fds=(descriptor,), check=True)
            finally:
                common.release_operation_lock(descriptor)
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            self.assertFalse(rotation.exists())

    def test_pruning_expires_interrupted_fragments_and_preserves_locked_active_dump(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); rotation = root / 'secret-rotation'; rotation.mkdir()
            stale = [root / 'pre-upgrade-stale.sql.gz.partial', rotation / 'stale.sql.gz.partial']
            active = rotation / 'active.sql.gz.partial'; fresh = root / 'pre-upgrade-fresh.sql.gz.partial'
            for path in (*stale, active, fresh): path.write_bytes(b'synthetic')
            expired = time.time() - 4 * 24 * 60 * 60
            for path in (*stale, active): os.utime(path, (expired, expired))
            with active.open('rb') as fragment:
                fcntl.flock(fragment, fcntl.LOCK_EX)
                subprocess.run(['bash', str(ROOT / 'selfhost/backup-prune-hook.sh'), 'post-backup'],
                    env=dict(os.environ, BACKUP_DIR=folder, PRE_OP_BACKUP_KEEP_DAYS='1'),
                    capture_output=True, check=True, timeout=10)
                self.assertTrue(active.exists())
            self.assertTrue(fresh.exists())
            self.assertFalse(any(path.exists() for path in stale))
            subprocess.run(['bash', str(ROOT / 'selfhost/backup-prune-hook.sh'), 'post-backup'],
                env=dict(os.environ, BACKUP_DIR=folder, PRE_OP_BACKUP_KEEP_DAYS='1'),
                capture_output=True, check=True, timeout=10)
            self.assertFalse(active.exists())


class InterruptedRecreateTests(unittest.TestCase):
    """Compose 2.40 leaves "<old id>_<name>" (never started) when killed mid-recreation; `up` then conflicts."""

    def test_other_commands_do_not_clean_up_containers(self):
        with patch.dict(os.environ, CHRONICLE_OPS_PROJECT='pilot'), patch.object(common, 'run') as run:
            common.compose('exec', '-T', 'operational-probe', 'record-operation.sh', 'up', 'success', 'none')
        run.assert_called_once_with(['docker', 'compose', '-p', 'pilot', 'exec', '-T',
                                     'operational-probe', 'record-operation.sh', 'up', 'success', 'none'])

    def test_up_removes_only_this_projects_never_started_placeholders(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rows = []
            for number, (project, name, status, started) in enumerate((
                ('pilot', '5b60cb834963_pilot-postgres-1', 'created', '0001-01-01T00:00:00Z'),
                ('pilot', 'pilot-web-1', 'created', '0001-01-01T00:00:00Z'),
                ('other', '5b60cb834963_pilot-web-1', 'created', '0001-01-01T00:00:00Z'),
                ('pilot', '5b60cb834963_pilot-web-1', 'exited', '2026-10-30T03:00:00Z'),
                ('pilot', '5b60cb834963_pilot-backend-1', 'created', '2026-10-30T03:00:00Z'),
                ('pilot', '5b60cb834963-pilot-web-1', 'created', '0001-01-01T00:00:00Z'),
                ('pilot', '5b60cb834963_pilot-backup-1', 'running', '2026-10-30T03:00:00Z'),
                ('pilot', '5b60cb834963_pilot-probe-1', 'created', ''),
            ), 1):
                rows.append(dict(Id=f'{number:012x}' + 'a' * 52, Name='/' + name,
                                 Config=dict(Labels={'com.docker.compose.project': project}),
                                 State=dict(Status=status, StartedAt=started)))
            (root / 'inventory.json').write_text(json.dumps(rows))
            executable = root / 'docker'
            executable.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['RECREATE_FIXTURE'])
rows = json.loads((root / 'inventory.json').read_text())
args = sys.argv[1:]
with (root / 'calls').open('a') as output:
    output.write(json.dumps(args) + '\\n')
if args[0] == 'ps':
    # Include stale results: removal must recheck state, label and never-started evidence.
    print('\\n'.join(row['Id'][:12] + ' ' + row['Name'][1:] for row in rows))
elif args[0] == 'inspect':
    print(json.dumps([row for row in rows if row['Id'].startswith(args[-1])]))
''')
            executable.chmod(0o700)
            environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                               PYTHONPATH=str(ROOT / 'selfhost'), RECREATE_FIXTURE=str(root), CHRONICLE_OPS_PROJECT='pilot')
            (root / '.env').write_text('COMPOSE_PROJECT_NAME=pilot\n')
            (root / 'docker-compose.yml').write_text('services: {}\n')
            wrappers = {
                'common': [sys.executable, '-c', 'from chronicle_ops.common import compose; compose("up", "-d")'],
                'release': [sys.executable, '-c', 'from pathlib import Path; from chronicle_ops.release import compose_release; '
                            'compose_release(Path("' + str(root) + '"), "pilot", ["docker-compose.yml"], "up", "-d")'],
            }
            for filename in ('chronicle', 'rotate-secret.sh'):
                source = (ROOT / 'selfhost' / filename).read_text()
                functions = '\n'.join(re.findall(r'(?ms)^dc\(\) \{.*?^\}', source))
                script = ('set -eu\nPROJECT=pilot\nSCRIPT_DIR="$1"\nSCRIPT_PATH="$1/chronicle"\n' + functions + '\ndc --progress plain up -d\n')
                wrappers[filename] = ['bash', '-c', script, 'fixture', str(ROOT / 'selfhost')]
            for name, command in wrappers.items():
                with self.subTest(wrapper=name):
                    (root / 'calls').unlink(missing_ok=True)
                    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
                    self.assertEqual(0, result.returncode, result.stderr)
                    calls = [json.loads(line) for line in (root / 'calls').read_text().splitlines()]
                    self.assertEqual([['rm', rows[0]['Id']]], [args for args in calls if args[0] == 'rm'])
                    self.assertEqual('compose', calls[-1][0])


class FirstStartScheduleTests(SelfhostSetupFixture):
    """Real setup and cron launcher honor the stop marker; Docker calls are recorded."""

    def test_setup_schedule_stays_stopped_until_resumed(self):
        import runpy
        driver = runpy.run_path(str(ROOT / 'tests/smoke/selfhost_release_setup.py'))
        root = self.host.parent; commands = root / 'bin'; record = root / 'docker-calls'
        store, environment = crontab_fixture(root)
        docker = commands / 'docker'
        # cron gives the launcher a bare environment, so the record path is written into the stub itself.
        docker.write_text(docker.read_text().replace('set -euo pipefail', f'set -euo pipefail\nprintf "%s\\n" "$*" >>{shlex.quote(str(record))}', 1))
        (commands / 'systemctl').write_text('#!/bin/sh\n[ "$2" = cron ] || [ "$2" = crond ]\n')
        (commands / 'systemctl').chmod(0o755)
        (commands / 'uname').write_text('#!/bin/sh\necho Linux\n')
        (commands / 'uname').chmod(0o755)
        environment.update({key: self.environment[key] for key in ('PATH',)},
                           CHRONICLE_RECONCILE_ENABLED='true')
        environment['PATH'] = str(commands) + os.pathsep + environment['PATH']

        def setup(rerun):
            answers = driver['setup_answers'](mode=driver['SetupMode'].BEHIND_PROXY, public_host='chronicle.study-host.org',
                                              password='synthetic-dashboard-password', monitoring=False,
                                              overwrite=rerun, reuse_hash=rerun)
            result = subprocess.run(['bash', str(self.host / 'chronicle'), 'setup'], input=answers, env=environment,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

        def cron_run():
            """Run every installed boot/periodic entry the way cron does: its command, a bare environment."""
            record.unlink(missing_ok=True)
            entries = [line for line in store.read_text().splitlines() if '# chronicle-reconcile:' in line]
            self.assertEqual(['@reboot', f'*/{reconcile.INTERVAL_MINUTES}'], [line.split()[0] for line in entries])
            for line in entries:
                command = line.split(' ', 1)[1] if line.startswith('@') else line.split(' ', 5)[5]
                subprocess.run(['/bin/sh', '-c', command], env=dict(HOME=str(root), PATH='/usr/bin:/bin'),
                               capture_output=True, timeout=120)
            return record.read_text().splitlines() if record.exists() else []

        setup(False)
        state = Path(next(line for line in store.read_text().splitlines() if line.startswith('@reboot')).split()[1]).parent
        self.assertTrue((state / reconcile.STOP_MARKER).exists())
        self.assertEqual([], cron_run(), 'cron touched Docker before the first explicit up')
        setup(True)  # rerunning setup on a never-started host stays stopped
        self.assertTrue((state / reconcile.STOP_MARKER).exists())
        self.assertEqual([], cron_run())
        # The explicit up clears the marker (cmd_up: ops_python reconcile resume); from then on cron reconciles.
        resumed = subprocess.run([sys.executable, '-m', 'chronicle_ops', 'reconcile', 'resume'], cwd=self.host,
                                 env=dict(environment, PYTHONPATH=str(self.host), CHRONICLE_OPS_STATE=str(state)),
                                 capture_output=True, text=True, timeout=30)
        self.assertEqual(0, resumed.returncode, resumed.stderr)
        # Positive control: the resumed launcher runs ./chronicle up, whose first Docker call is the owner check.
        self.assertIn('compose ls --all --format json', cron_run(), (state / 'reconcile.log').read_text())
        setup(True)  # a running deployment's setup rerun must not newly fence it
        self.assertFalse((state / reconcile.STOP_MARKER).exists())
        self.assertIn('compose ls --all --format json', cron_run())
