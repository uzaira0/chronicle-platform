"""Operator setup, db-init and rollback guards; synthetic settings and no live services."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_release import complete_manifest_fixture
from chronicle_ops import receipts, reconcile, release
from chronicle_ops.restore import rollback

ROOT = Path(__file__).resolve().parents[2]


class OperatorSetupRollbackGuardTests(unittest.TestCase):
    def test_plain_db_init_refuses_tde_and_indeterminate_database_state(self):
        shell = '''
mkdir() { :; }; chown() { :; }; chmod() { :; }
psql() {
  if [[ "$*" == *-Atc* ]]; then
    [[ "$TDE_RESULT" != query-failed ]] || return 2
    printf '%s\\n' "$TDE_RESULT"
  else
    cat >/dev/null
    printf 'bootstrap\\n' >>"$BOOTSTRAP_LOG"
  fi
}
source "$1"
'''
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'bootstrap'
            for state, accepted in (('f', True), ('t', False), ('', False), ('query-failed', False)):
                with self.subTest(state=state):
                    log.unlink(missing_ok=True)
                    result = subprocess.run(['bash', '-c', shell, 'fixture', str(ROOT / 'selfhost/db-init.sh')],
                        env=dict(os.environ, ENABLE_ENCRYPTION='false', POSTGRES_PASSWORD='synthetic',
                                 TDE_RESULT=state, BOOTSTRAP_LOG=str(log)), stdin=subprocess.DEVNULL,
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    self.assertEqual(log.exists(), accepted)
                    if state in ('t', ''):
                        self.assertIn('TDE-to-plain database migration', result.stderr)
                        self.assertIn('docs/BACKUP-RESTORE.md#tde-to-plain-database-migration', result.stderr)

    def test_setup_reprompts_for_ipv6_using_the_startup_listener_validator(self):
        # The launcher returns before dispatch when sourced; host_addrs is the only stub.
        shell = (f'source {ROOT / "selfhost/chronicle"}\n'
                 'host_addrs() { printf "fd42:242::1\\n10.20.0.5\\n"; };\nask_bind_addr "$1" "${2:-}"')
        for default, answer, mode in (('fd42:242::1', '\n10.20.0.5\n', ''),
                                      ('127.0.0.1', '::1\n127.0.0.1\n', ''),
                                      ('127.0.0.1', '[::]\n0.0.0.0\n', 'wildcard')):
            with self.subTest(default=default, mode=mode):
                result = subprocess.run(['bash', '-eu', '-c', shell, 'fixture', default, mode],
                    cwd=ROOT / 'selfhost', input=answer, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, answer.splitlines()[-1] + '\n')
                self.assertIn('requires an IPv4 address', result.stderr)

    def test_failed_rollback_acceptance_keeps_a_resumable_checkpoint(self):
        for failure in ('up', 'verify'):
            with self.subTest(failure=failure), \
                 tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                root = Path(folder).resolve()
                old, candidate, state = root / 'old release/selfhost', root / 'candidate/selfhost', root / 'state'
                old.mkdir(parents=True); candidate.mkdir(parents=True); state.mkdir()
                (old / 'chronicle_ops').mkdir(); (old / 'chronicle_ops/__main__.py').touch()
                (candidate / 'chronicle').touch()
                (candidate.parent / 'release-manifest.json').write_text('{"release_version":"2.0.0"}')
                complete_manifest_fixture(candidate.parent)
                settings = f"COMPOSE_PROJECT_NAME=pilot\nCHRONICLE_STATE_DIR='{state}'\n"
                from chronicle_ops.verify import BACKUP_RETENTION_KEYS
                from chronicle_ops.envfile import read_env, value
                retention_keys = (*BACKUP_RETENTION_KEYS, 'BACKUP_KEEP_MINS', 'PRE_OP_BACKUP_KEEP_DAYS')
                for host in (old, candidate):
                    retention = ''.join(f'{key}={"1" if host == old else "all"}\n' for key in retention_keys)
                    (host / '.env').write_text(settings + retention); (host / '.env').chmod(0o600)
                (old / '.env.example').write_text(settings)
                def run(args, **kwargs):
                    self.assertFalse((candidate / '.env').exists())
                    if args[-1] == failure:
                        raise subprocess.CalledProcessError(1, args)
                    return subprocess.CompletedProcess(args, 0)
                stack.enter_context(patch('chronicle_ops.restore.compose'))
                stack.enter_context(patch('chronicle_ops.restore.Restore.execute', return_value=0))
                stack.enter_context(patch('chronicle_ops.common.run', side_effect=run))
                stack.enter_context(patch('chronicle_ops.upgrade.run', side_effect=run))  # verify_release
                stack.enter_context(patch('chronicle_ops.restore.database_moved', return_value=False))
                stack.enter_context(patch('chronicle_ops.upgrade.start_release',
                                          side_effect=lambda host, *_: run([str(host / 'chronicle'), 'up'])))
                stack.enter_context(patch('chronicle_ops.release.compose_projects', return_value=[]))
                stack.enter_context(patch('chronicle_ops.reconcile.shutil.which', return_value=None))
                stack.enter_context(patch.object(Path, 'cwd', return_value=candidate))
                stack.enter_context(patch.dict(os.environ, {reconcile.ENABLED_ENV: 'false'}, clear=True))
                with self.assertRaises(subprocess.CalledProcessError):
                    rollback(old, '/backups/reviewed.sql.gz', 'a' * 64, True)
                release.require_current_owner(old, state, 'pilot')
                # Reconciliation is disabled here, so its uninstall marker stays. The dump is restored,
                # so ingress reopens on the data in place, as before the update.
                self.assertTrue((state / reconcile.STOP_MARKER).exists())
                from chronicle_ops.ingress import fence_path
                self.assertFalse(fence_path(state).exists())
                archive, = (state / receipts.OPERATOR_RECEIPTS_DIR).glob('.env.rollback-*')
                self.assertEqual(archive.read_text(), settings + ''.join(f'{key}=all\n' for key in retention_keys))
                for key in retention_keys:
                    self.assertEqual(value(read_env(old / '.env'), key), 'all', key)
                self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
                self.assertEqual(release.read_manifest(candidate.parent / 'release-manifest.json', True)[0]['release_version'], '2.0.0')
                checkpoint = state / reconcile.UPGRADE_LOCK / reconcile.RECOVERY_FILE
                record = json.loads(checkpoint.read_text())
                self.assertEqual(str(candidate), record['owner'])
                self.assertEqual(str(old), record['previous'])
                from chronicle_ops.restore import ROLLBACK_PHASES
                self.assertIn(record['phase'], ROLLBACK_PHASES)

    def test_post_commit_rollback_states_the_dump_age_and_what_it_discards(self):
        import io
        from datetime import datetime, timezone
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder).resolve()
            old, candidate, state = root / 'old/selfhost', root / 'candidate/selfhost', root / 'state'
            old.mkdir(parents=True); candidate.mkdir(parents=True); state.mkdir()
            (old / 'chronicle_ops').mkdir(); (old / 'chronicle_ops/__main__.py').touch()
            (old / '.env').write_text(f"COMPOSE_PROJECT_NAME=pilot\nCHRONICLE_STATE_DIR='{state}'\n")
            (old / '.env').chmod(0o600)
            dump = state / 'backups/pre-upgrade.sql.gz'
            dump.parent.mkdir(); dump.write_bytes(b'dump')
            written = datetime(2026, 10, 20, 9, 30, tzinfo=timezone.utc).timestamp()
            os.utime(dump, (written, written))
            stack.enter_context(patch('chronicle_ops.release.require_current_owner'))
            stack.enter_context(patch('chronicle_ops.restore.database_moved', return_value=False))
            stack.enter_context(patch.object(Path, 'cwd', return_value=candidate))
            stack.enter_context(patch('chronicle_ops.restore.time.time', return_value=written + 3 * 86400 + 5 * 3600))
            executed = stack.enter_context(patch('chronicle_ops.restore.Rollback'))
            executed.return_value.execute.return_value = 0
            output = stack.enter_context(patch('sys.stdout', io.StringIO()))
            self.assertEqual(0, rollback(old, '/backups/pre-upgrade.sql.gz', 'a' * 64, True))
            shown = output.getvalue()
            self.assertIn('2026-10-20 09:30 UTC', shown)
            self.assertIn('3 d 5 h ago', shown)
            self.assertIn("written since then is discarded", shown)
            shutil.rmtree(state / reconcile.UPGRADE_LOCK)
            dump.unlink()
            errors = stack.enter_context(patch('sys.stderr', io.StringIO()))
            self.assertEqual(0, rollback(old, '/backups/pre-upgrade.sql.gz', 'a' * 64, True))
            self.assertIn('cannot date rollback dump /backups/pre-upgrade.sql.gz', errors.getvalue())

    def test_failed_first_rollback_journal_write_leaves_no_marker_and_retry_starts(self):
        import errno
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder).resolve()
            old, candidate, state = root / 'old/selfhost', root / 'candidate/selfhost', root / 'state'
            old.mkdir(parents=True); candidate.mkdir(parents=True); state.mkdir()
            (old / 'chronicle_ops').mkdir(); (old / 'chronicle_ops/__main__.py').touch()
            (old / '.env').write_text(f"COMPOSE_PROJECT_NAME=pilot\nCHRONICLE_STATE_DIR='{state}'\n")
            (old / '.env').chmod(0o600)
            stack.enter_context(patch('chronicle_ops.release.require_current_owner'))
            stack.enter_context(patch('chronicle_ops.restore.database_moved', return_value=False))
            stack.enter_context(patch.object(Path, 'cwd', return_value=candidate))
            executed = stack.enter_context(patch('chronicle_ops.restore.Rollback'))
            executed.return_value.execute.return_value = 0
            write_text = receipts.write_text
            def disk_full(destination, content):
                if Path(destination).name == reconcile.RECOVERY_FILE:
                    raise OSError(errno.ENOSPC, 'No space left on device')
                write_text(destination, content)
            with patch('chronicle_ops.receipts.write_text', side_effect=disk_full), self.assertRaises(OSError):
                rollback(old, '/backups/reviewed.sql.gz', 'a' * 64, True)
            self.assertFalse(os.path.lexists(state / reconcile.UPGRADE_LOCK))
            reconcile.check_mutations(state, candidate)
            self.assertEqual(0, rollback(old, '/backups/reviewed.sql.gz', 'a' * 64, True))
            record = json.loads((state / reconcile.UPGRADE_LOCK / reconcile.RECOVERY_FILE).read_text())
            self.assertEqual((str(old), str(candidate), '/backups/reviewed.sql.gz'),
                             (record['previous'], record['owner'], record['dump']))
            # Every command that meets the marker names the one command that resumes it.
            with self.assertRaisesRegex(ValueError, f'run ./chronicle update from {old}$'):
                reconcile.check_mutations(state, candidate)
            (state / reconcile.UPGRADE_LOCK / reconcile.RECOVERY_FILE).unlink()
            (state / reconcile.UPGRADE_LOCK).rmdir()
            for name, command in ((reconcile.RESTORE_LOCK, './chronicle restore --recover'),
                                  (reconcile.ROTATION_MARKER, './chronicle rotate-secret recover')):
                (state / name).mkdir(); (state / name / 'phase').write_text('prepared\n')
                with self.subTest(marker=name), self.assertRaisesRegex(ValueError, 'run ' + command):
                    reconcile.check_mutations(state, candidate)
                shutil.rmtree(state / name)

    def test_an_empty_marker_from_an_interrupted_operation_is_cleared_by_the_lock_holder(self):
        # 2026.10.23 setup, restore and rollback created their marker with mkdir before writing any
        # journal file, and rotation still does: an empty marker recorded, and so changed, nothing.
        from chronicle_ops.common import LOCK_FD_ENV, acquire_operation_lock, release_operation_lock
        import io
        from contextlib import redirect_stderr
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, clear=False):
            os.environ.pop(LOCK_FD_ENV, None)
            state = Path(folder)
            journaled = state / reconcile.RESTORE_LOCK
            for name in reconcile.MUTATION_MARKERS:
                (state / name).mkdir()
            # Without the operation lock (doctor) the marker is reported, with the command that clears it.
            with self.assertRaisesRegex(ValueError, r'empty marker .*\./chronicle up clears it'):
                reconcile.check_mutations(state, state)
            self.assertTrue(all((state / name).is_dir() for name in reconcile.MUTATION_MARKERS))
            (journaled / 'phase').write_text('prepared\n')
            errors = io.StringIO()
            with redirect_stderr(errors):
                descriptor = acquire_operation_lock(state)
            try:
                for name in (reconcile.UPGRADE_LOCK, reconcile.ROTATION_MARKER):
                    self.assertFalse(os.path.lexists(state / name), name)
                    self.assertIn(f'cleared the empty marker {state / name}', errors.getvalue())
                # A marker holding any journal file is never removed and still refuses.
                self.assertEqual('prepared\n', (journaled / 'phase').read_text())
                with self.assertRaisesRegex(ValueError, f'incomplete operation at {journaled}; run ./chronicle restore'):
                    reconcile.check_mutations(state, state)
                shutil.rmtree(journaled)
                # check_mutations clears too when its caller verifiably holds the lock (inherited fd).
                (state / reconcile.UPGRADE_LOCK).mkdir()
                with redirect_stderr(io.StringIO()):
                    reconcile.check_mutations(state, state)
                self.assertFalse(os.path.lexists(state / reconcile.UPGRADE_LOCK))
            finally:
                release_operation_lock(descriptor)
            # A process that does not hold the lock never clears, even with a stale inherited descriptor.
            (state / reconcile.UPGRADE_LOCK).mkdir()
            holder = subprocess.Popen(['flock', str(state / '.reconcile.lock'), 'sleep', '30'])
            try:
                for _ in range(100):
                    if subprocess.run(['flock', '-n', str(state / '.reconcile.lock'), 'true']).returncode:
                        break
                    import time; time.sleep(0.05)
                with open(state / '.reconcile.lock') as stale, \
                        patch.dict(os.environ, {LOCK_FD_ENV: str(stale.fileno())}), \
                        self.assertRaisesRegex(ValueError, 'empty marker'):
                    reconcile.check_mutations(state, state)
                self.assertTrue((state / reconcile.UPGRADE_LOCK).is_dir())
            finally:
                holder.kill(); holder.wait()

    def test_an_unreadable_marker_is_kept_and_refused_without_blocking_the_lock_holder(self):
        # An interrupted `sudo ./chronicle restore` leaves its marker root-owned 0700 while the lock
        # file stays account-owned: the marker cannot be listed, so it is not provably empty.
        from chronicle_ops.common import LOCK_FD_ENV, acquire_operation_lock, release_operation_lock
        import io
        from contextlib import redirect_stderr
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, clear=False):
            os.environ.pop(LOCK_FD_ENV, None)
            state = Path(folder)
            marker = state / reconcile.RESTORE_LOCK
            marker.mkdir()
            (marker / 'phase').write_text('prepared\n')
            marker.chmod(0)
            try:
                descriptors = '/dev/fd' if sys.platform == 'darwin' else '/proc/self/fd'
                open_before = set(os.listdir(descriptors))
                # Fresh path: the lock is taken and the marker refusal names the marker.
                descriptor = acquire_operation_lock(state)
                try:
                    with self.assertRaisesRegex(ValueError, f'incomplete operation at {marker}; run ./chronicle restore'):
                        reconcile.check_mutations(state, state)
                    # Inherited path: a child of the lock holder returns at once instead of waiting on its parent.
                    child = subprocess.run(
                        [sys.executable, '-c', 'import signal, sys\n'
                         'from chronicle_ops.common import acquire_operation_lock\n'
                         'signal.alarm(1)\n'
                         'print(acquire_operation_lock(sys.argv[1]))', str(state)],
                        pass_fds=(descriptor,), capture_output=True, text=True, timeout=60,
                        env={**os.environ, 'PYTHONPATH': str(ROOT / 'selfhost')})
                    self.assertEqual((0, 'None\n'), (child.returncode, child.stdout), child.stderr)
                finally:
                    release_operation_lock(descriptor)
                self.assertEqual(open_before, set(os.listdir(descriptors)))
                self.assertNotIn(LOCK_FD_ENV, os.environ)
                # A failure after the lock is taken closes the descriptor and forgets it.
                with patch.object(reconcile, 'clear_empty_markers', side_effect=OSError('unlistable')), \
                        redirect_stderr(io.StringIO()), self.assertRaises(OSError):
                    acquire_operation_lock(state)
                self.assertEqual(open_before, set(os.listdir(descriptors)))
                self.assertNotIn(LOCK_FD_ENV, os.environ)
            finally:
                marker.chmod(0o700)
            self.assertEqual('prepared\n', (marker / 'phase').read_text())

    @unittest.skipUnless(shutil.which('semgrep'), 'Semgrep is not installed')
    def test_semgrep_reports_planted_flavor_violations_and_excludes_tests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            for module in ('chronicle', 'chronicle-server', 'chronicle-api', 'chronicle-models', 'rhizome', 'rhizome-client', 'chronicle-web'):
                (root / module / 'src').mkdir(parents=True)
                subprocess.run(['git', 'init', '-q', str(root / module)], check=True, capture_output=True)
            rules = root / 'tests/security'; rules.mkdir(parents=True)
            (rules / 'rules').symlink_to(ROOT / 'tests/security/rules', target_is_directory=True)
            for source_set in ('main', 'googleServices', 'open', 'minimal', 'test', 'testOpen', 'androidTest'):
                target = root / 'chronicle/app/src' / source_set / 'java/Fixture.kt'
                target.parent.mkdir(parents=True)
                target.write_text('fun probe(participantId: String) { Log.i("fixture", "participant $participantId") }\n')
            for path in ('chronicle-server/src/main/kotlin/controllers/Fixture.kt',
                         'chronicle/app/src/googleServices/java/controllers/Fixture.kt'):
                target = root / path; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('fun probe(@RequestBody rows: List<Row>): Int { return rows.size }\n')
            reports = root / 'reports'; reports.mkdir()
            shell = 'source "$1"; ROOT_DIR="$2"; REPORT_DIR="$2/reports"; android_source_roots; run_sast_semgrep'
            result = subprocess.run(['bash', '-c', shell, 'fixture', str(ROOT / 'tests/security/run-all-security.sh'), str(root)],
                env=dict(os.environ, SEMGREP_SEND_METRICS='off', SEMGREP_ENABLE_VERSION_CHECK='0',
                         SEMGREP_SETTINGS_FILE=str(reports / 'settings.yml'), SEMGREP_LOG_FILE=str(reports / 'runtime.log')),
                capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            for source_set in ('googleServices', 'open', 'minimal'):
                self.assertIn(str(root / 'chronicle/app/src' / source_set) + '\n', result.stdout)
            report = json.loads((reports / 'semgrep.sarif').read_text())
            hits = [hit for run in report['runs'] for hit in run['results']
                    if hit['ruleId'].endswith('chronicle-android-log-raw-participant-id')]
            self.assertEqual({Path(hit['locations'][0]['physicalLocation']['artifactLocation']['uri']).parts[-3] for hit in hits},
                             {'main', 'googleServices', 'open', 'minimal'})
            controllers = [hit for run in report['runs'] for hit in run['results']
                           if hit['ruleId'].endswith('chronicle-unvalidated-list-request-body')]
            self.assertEqual(len(controllers), 1)
            self.assertIn('chronicle-server/src/', controllers[0]['locations'][0]['physicalLocation']['artifactLocation']['uri'])
