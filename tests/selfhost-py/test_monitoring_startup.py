"""Optional monitoring never gates `up`, `update`, `restore` or rollback, and a failed recovery
leaves participant ingress and reconciliation in a state an operator (or cron) can act on.

Every case runs the real operator code against compose_shim's fake `docker` on PATH."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import compose_shim
from chronicle_ops import reconcile, receipts
from chronicle_ops.ingress import fence_path

ROOT = Path(__file__).resolve().parents[2]
BASE = ['docker-compose.yml', 'overlays/mode-behind-proxy-internal.yml']
WITH_MONITORING = BASE + ['overlays/monitoring.yml']


def release_directory(directory, names, state=None):
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).parent.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text('services: {}\n')
    settings = "COMPOSE_PROJECT_NAME=fixture\nCOMPOSE_FILE=" + ':'.join(names) + "\n"
    if state is not None:
        settings += f"CHRONICLE_STATE_DIR='{state}'\n"
    (directory / '.env').write_text(settings)
    (directory / '.env').chmod(0o600)
    (directory / '.env.example').write_text(settings)
    return directory


def wait_calls(environment):
    return [command for command in compose_shim.compose_calls(environment, 'up') if '--wait' in command]


class Captured:
    def __init__(self):
        self.out, self.err = io.StringIO(), io.StringIO()

    def __enter__(self):
        self.stack = [redirect_stdout(self.out), redirect_stderr(self.err)]
        for item in self.stack:
            item.__enter__()
        return self

    def __exit__(self, *exc):
        for item in reversed(self.stack):
            item.__exit__(*exc)

    @property
    def text(self):
        return self.out.getvalue() + self.err.getvalue()


class ReleaseStartupTests(unittest.TestCase):
    def test_update_waits_only_on_core_and_warns_about_unhealthy_monitoring(self):
        from chronicle_ops.upgrade import start_release
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            directory = release_directory(root / 'candidate', WITH_MONITORING)
            environment = compose_shim.install(root / 'bin', unhealthy=['grafana'])
            with patch.dict(os.environ, environment), Captured() as output:
                start_release(directory, 'fixture', WITH_MONITORING, '60')
            core_wait = wait_calls(environment)[0]
            self.assertIn('backend', core_wait)
            self.assertFalse(set(compose_shim.MONITORING) & set(core_wait), core_wait)
            started = [command for command in compose_shim.compose_calls(environment, 'up') if 'grafana' in command]
            self.assertTrue(started, 'monitoring was never started')
            self.assertIn('grafana', output.text)
            self.assertIn('./chronicle logs grafana', output.text)
            self.assertNotIn('victoriametrics is', output.text)

    def test_an_unhealthy_core_service_still_fails_the_update(self):
        from chronicle_ops.upgrade import start_release
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            directory = release_directory(root / 'candidate', WITH_MONITORING)
            environment = compose_shim.install(root / 'bin', unhealthy=['backend'])
            with patch.dict(os.environ, environment), Captured(), \
                 self.assertRaises(subprocess.CalledProcessError):
                start_release(directory, 'fixture', WITH_MONITORING, '60')

    def test_without_the_overlay_every_service_is_core(self):
        from chronicle_ops.upgrade import start_release
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            directory = release_directory(root / 'candidate', BASE)
            environment = compose_shim.install(root / 'bin')
            with patch.dict(os.environ, environment), Captured():
                start_release(directory, 'fixture', BASE, '60')
            self.assertEqual([compose_shim.CORE], [[name for name in command if name in compose_shim.CORE]
                                                   for command in compose_shim.compose_calls(environment, 'up')])

    def test_post_restore_start_ignores_unhealthy_monitoring(self):
        from chronicle_ops.restore import Restore, RestorePhase
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / 'backups').mkdir()
            environment = compose_shim.install(root / 'bin', unhealthy=['victorialogs'])
            environment.update(CHRONICLE_OPS_PROJECT='fixture', COMPOSE_FILE=':'.join(WITH_MONITORING))
            operation = Restore(root, root / 'backups', '', '', '60', False, True)
            (root / reconcile.RESTORE_LOCK).mkdir()
            operation.phase = RestorePhase.DATABASE_RESTORED
            with patch.dict(os.environ, environment), Captured() as output:
                operation.start()
            self.assertIs(operation.phase, RestorePhase.VERIFIED)
            self.assertFalse(set(compose_shim.MONITORING) & set(wait_calls(environment)[0]))
            self.assertIn('./chronicle logs victorialogs', output.text)


# The stderr of the monitoring start that failed in the 2026.11.12 release smoke on 2026-11-11:
# 50 progress events, one per network, volume and container (17 of them repeat the error), then
# Compose's own error on the last line. Docker had no address pool left for the egress network.
ADDRESS_POOLS = (Path(__file__).parent / 'fixtures/compose_up_address_pools.stderr').read_text()
CAUSE = ('failed to create network chronicle-release-smoke-46767-77e7c0_egress: Error response from daemon: '
         'all predefined address pools have been fully subnetted')


def plain(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


class FailedStartCauseTests(unittest.TestCase):
    """A Compose `up` whose output the operator does not see must still say why it failed.

    start_monitoring and start_unawaited ran `up` with its output discarded and did not look at
    the result. When Docker could not create the monitoring networks, every monitoring service
    was reported as "not created" and the operator was told to read the logs of containers that
    did not exist; Compose's one line naming the cause was thrown away."""

    def assert_names_the_cause(self, text, services):
        text = plain(text)
        self.assertEqual(1, text.count(CAUSE), text)
        self.assertNotIn('Creating', text)  # progress events are left out
        self.assertNotIn('error during connect', text)  # and so is each resource's copy of the error
        self.assertNotIn('./chronicle logs', text)  # no container, so no logs to read
        self.assertIn('Chronicle itself is running', text)
        self.assertIn('./chronicle up', text)
        for service in services:
            self.assertIn(service, text)

    def test_update_names_composes_error_when_monitoring_cannot_be_created(self):
        from chronicle_ops.upgrade import start_release
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            directory = release_directory(root / 'candidate', WITH_MONITORING)
            environment = compose_shim.install(root / 'bin', uncreated=compose_shim.MONITORING, up_stderr=ADDRESS_POOLS)
            with patch.dict(os.environ, environment), Captured() as output:
                start_release(directory, 'fixture', WITH_MONITORING, '60')  # monitoring never fails the update
            self.assert_names_the_cause(output.text, compose_shim.MONITORING)
            self.assertIn('monitoring is degraded', output.text)

    def test_an_unhealthy_service_keeps_its_logs_hint_and_gains_composes_reason(self):
        from chronicle_ops.upgrade import start_release
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            directory = release_directory(root / 'candidate', WITH_MONITORING)
            environment = compose_shim.install(root / 'bin', unhealthy=['grafana'])
            with patch.dict(os.environ, environment), Captured() as output:
                start_release(directory, 'fixture', WITH_MONITORING, '60')
            self.assertIn('./chronicle logs grafana', output.text)
            self.assertIn('container fixture-grafana-1 is unhealthy', output.text)

    def fake_dc(self, style, stderr=ADDRESS_POOLS, status=1):
        """A Compose caller whose `up` fails, by returning the failed result or by raising (see
        services.checked); like common.run it has the command's stderr only when asked to pipe it.
        `ps` finds no container."""
        calls = []

        def dc(*args, **kwargs):
            calls.append((args, kwargs))
            if args[0] != 'up':
                return SimpleNamespace(returncode=0, stdout='')
            captured = stderr if kwargs.get('stderr') == subprocess.PIPE else None
            if style == 'raises':
                raise subprocess.CalledProcessError(status, ['docker', 'compose', *args], None, captured)
            return subprocess.CompletedProcess(['docker', 'compose', *args], status, None, captured)
        return dc, calls

    def test_start_monitoring_names_composes_error_whether_the_caller_returns_or_raises(self):
        from chronicle_ops.services import start_monitoring
        services = ['victoriametrics', 'grafana']
        for style in ('returns', 'raises'):
            with self.subTest(style):
                dc, calls = self.fake_dc(style)
                with Captured() as output:
                    failed = start_monitoring(dc, services, ('--force-recreate',))
                self.assertEqual([('victoriametrics', 'not created'), ('grafana', 'not created')], failed)
                self.assert_names_the_cause(output.text, services)
                self.assertTrue(calls[0][1].get('quiet'), 'a start that works still prints no progress')
                self.assertEqual(['up', 'ps'], [args[0] for args, _ in calls])

    def test_start_unawaited_names_composes_error_whether_the_caller_returns_or_raises(self):
        from chronicle_ops.services import start_unawaited
        for style in ('returns', 'raises'):
            with self.subTest(style):
                dc, calls = self.fake_dc(style)
                with Captured() as output:
                    self.assertIsNone(start_unawaited(dc, ['db-backup'], ('--force-recreate',)))
                text = plain(output.text)
                self.assertEqual(1, text.count(CAUSE), text)
                self.assertIn('could not start db-backup', text)
                self.assertIn('Chronicle itself is running', text)
                self.assertNotIn('Creating', text)
                self.assertNotIn('./chronicle logs', text)
                self.assertTrue(calls[0][1].get('quiet'))

    def test_a_failed_up_that_printed_nothing_is_reported_with_its_exit_status(self):
        from chronicle_ops.services import start_monitoring, start_unawaited
        for style in ('returns', 'raises'):
            with self.subTest(style):
                dc, _ = self.fake_dc(style, stderr='', status=137)
                with Captured() as output:
                    start_monitoring(dc, ['grafana'])
                    start_unawaited(dc, ['db-backup'])
                self.assertEqual(2, plain(output.text).count('docker compose up exited with status 137'), output.text)

    def test_the_reported_error_is_the_last_few_lines_compose_wrote_as_its_own(self):
        from chronicle_ops.common import compose_error
        self.assertEqual(CAUSE, compose_error(ADDRESS_POOLS))
        self.assertEqual('error 47; error 48; error 49', compose_error(''.join(f'error {number}\n' for number in range(50))))
        self.assertEqual('same', compose_error('same\n' * 9))
        # Progress events only: their last lines are kept rather than nothing.
        self.assertEqual('Container fixture-grafana-1 Starting; Container fixture-grafana-1 Error',
                         compose_error(' Container fixture-grafana-1 Starting \n Container fixture-grafana-1 Error \n'))
        self.assertLessEqual(len(compose_error('x' * 100_000 + '\n' + 'y' * 100_000)), 1000)
        self.assertEqual('', compose_error(''))
        self.assertEqual('', compose_error(None))

    def test_what_compose_logs_as_a_warning_is_not_reported_as_its_error(self):
        """Compose logs what it warns about on lines of its own (time="..." level=warning msg="..."),
        one for each variable that is not set, for example. With an error line present they are left
        out wherever they stand; when they are all Compose wrote as its own, they are kept."""
        from chronicle_ops.common import compose_error
        warning = ('time="2026-11-11T00:00:00Z" level=warning msg="The \\"GRAFANA_ADMIN_PASSWORD\\" variable is not set. '
                   'Defaulting to a blank string."\n')
        progress = ' Container fixture-grafana-1 Creating \n'
        error = 'Error response from daemon: driver failed programming external connectivity\n'
        for written in (warning + progress + error, progress + error + warning, warning * 4 + error + warning * 4):
            with self.subTest(written=written):
                self.assertEqual(error.strip(), compose_error(written))
        self.assertEqual(warning.strip(), compose_error(progress + warning))

    def test_a_service_without_a_container_is_never_sent_to_its_logs(self):
        from chronicle_ops.services import report, report_unawaited
        with Captured() as output:
            report([('grafana', 'not created'), ('cadvisor', 'not created'), ('victorialogs', 'unhealthy')])
            states = report_unawaited(lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=''), ['db-backup'])
        text = plain(output.text)
        self.assertEqual([('db-backup', 'not created')], states)
        for service in ('grafana', 'cadvisor', 'db-backup'):
            self.assertIn(service, text)
            self.assertNotIn('./chronicle logs ' + service, text)
        self.assertIn('./chronicle logs victorialogs', text)
        self.assertIn('./chronicle up', text)


class UnknownStateTests(unittest.TestCase):
    """A warning says what is known and nothing more.

    When the `up` that starts monitoring hit its process timeout, or `ps` failed or was not
    answered, every service was classed "not created" and the operator read "They have no logs to
    read: correct Docker Compose's error", with no error shown and containers that might exist.
    A timeout is reported as a timeout with its seconds; a `ps` that could not be read as that,
    with every service's state unknown; "not created" only for a service `ps` answered without."""

    HEALTHY = 'grafana\trunning\thealthy\t0\n'

    def compose(self, up=None, ps=HEALTHY):
        """A Compose caller: `up` and `ps` each return (text or a finished process) or raise (an exception)."""
        def dc(*args, **kwargs):
            answer = up if args[0] == 'up' else ps
            if isinstance(answer, BaseException):
                raise answer
            if isinstance(answer, subprocess.CompletedProcess):
                return answer
            return subprocess.CompletedProcess(['docker', 'compose', *args], 0, answer, '')
        return dc

    def start(self, **answers):
        from chronicle_ops.services import start_monitoring
        with Captured() as output:
            failed = start_monitoring(self.compose(**answers), ['grafana', 'cadvisor'])
        return failed, plain(output.text)

    TIMED_OUT = subprocess.TimeoutExpired(['docker', 'compose', 'up'], 420)
    REFUSED = subprocess.CompletedProcess(['docker', 'compose', 'ps'], 1, '',
                                          'Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n')

    def assert_claims_no_compose_error(self, text):
        self.assertNotIn("correct Docker Compose's error", text)
        self.assertNotIn('reported an error', text)

    def test_a_start_that_timed_out_is_a_timeout_and_the_states_are_the_ones_ps_gives(self):
        failed, text = self.start(up=self.TIMED_OUT)
        self.assertEqual([('cadvisor', 'not created')], failed)  # ps answered, and has no row for it
        self.assertIn('did not finish starting monitoring within 420 seconds', text)
        self.assert_claims_no_compose_error(text)
        self.assertIn('cadvisor', text)
        self.assertNotIn('./chronicle logs', text)
        self.assertNotIn("Command '[", text)

    def test_a_timed_out_start_whose_state_cannot_be_read_says_the_state_is_unknown(self):
        for name, ps, why in (('ps failed', self.REFUSED, 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock'),
                              ('ps raised', subprocess.CalledProcessError(1, ['docker', 'compose', 'ps'], '', self.REFUSED.stderr),
                               'Cannot connect to the Docker daemon at unix:///var/run/docker.sock'),
                              ('ps timed out', subprocess.TimeoutExpired(['docker', 'compose', 'ps'], 60),
                               'docker compose ps did not answer within 60 seconds'),
                              ('no docker', FileNotFoundError(2, 'No such file or directory', 'docker'), '[Errno 2] No such file or directory')):
            with self.subTest(name):
                failed, text = self.start(up=self.TIMED_OUT, ps=ps)
                self.assertEqual([('grafana', 'unknown'), ('cadvisor', 'unknown')], failed)
                self.assertIn('did not finish starting monitoring within 420 seconds', text)
                self.assertIn('could not be read (' + why, text)
                self.assertIn('grafana, cadvisor', text)
                self.assertIn('./chronicle doctor', text)
                self.assertNotIn('not created', text)
                self.assertNotIn('no logs to read', text)
                self.assertNotIn('./chronicle logs', text)
                self.assert_claims_no_compose_error(text)

    def test_a_started_monitoring_whose_state_cannot_be_read_is_not_called_not_created(self):
        failed, text = self.start(up='', ps=self.REFUSED)
        self.assertEqual([('grafana', 'unknown'), ('cadvisor', 'unknown')], failed)
        self.assertIn('could not be read (Cannot connect to the Docker daemon', text)
        self.assertNotIn('not created', text)
        self.assert_claims_no_compose_error(text)

    def test_a_service_ps_answers_without_has_no_container_and_no_compose_error_is_claimed(self):
        failed, text = self.start(up='')
        self.assertEqual([('cadvisor', 'not created')], failed)
        self.assertIn('cadvisor', text)
        self.assertIn('./chronicle up', text)
        self.assertNotIn('./chronicle logs', text)
        self.assert_claims_no_compose_error(text)

    def test_docker_that_cannot_be_run_is_reported_as_that(self):
        missing = FileNotFoundError(2, 'No such file or directory', 'docker')
        failed, text = self.start(up=missing, ps=missing)
        self.assertEqual([('grafana', 'unknown'), ('cadvisor', 'unknown')], failed)
        self.assertIn('could not be run to start monitoring', text)
        self.assertNotIn('not created', text)

    def test_the_unawaited_services_are_not_called_not_created_when_ps_fails(self):
        from chronicle_ops.services import report_unawaited
        for name, ps in (('ps failed', self.REFUSED), ('ps timed out', subprocess.TimeoutExpired(['docker', 'compose', 'ps'], 60))):
            with self.subTest(name):
                with Captured() as output:
                    self.assertEqual([], report_unawaited(self.compose(ps=ps), ['db-backup']))
                text = plain(output.text)
                self.assertIn('could not inspect db-backup', text)
                self.assertIn('./chronicle doctor', text)
                self.assertNotIn('not created', text)
                self.assertNotIn('no logs to read', text)

    def test_an_unawaited_start_that_timed_out_is_a_timeout(self):
        from chronicle_ops.services import start_unawaited
        with Captured() as output:
            self.assertIsNone(start_unawaited(self.compose(up=subprocess.TimeoutExpired(['docker', 'compose', 'up'], 600)), ['db-backup']))
        text = plain(output.text)
        self.assertIn('did not finish within 600 seconds', text)
        self.assertIn('db-backup may not have started', text)
        self.assertNotIn('could not start', text)
        self.assertNotIn("Command '[", text)


class OutputThatIsNotTextTests(unittest.TestCase):
    """Compose's captured output never raises on decoding, whether the command worked or failed.

    Every caller that pipes Compose's stderr to name a cause read it as strict text. One byte that
    is not valid in the pipe encoding raised UnicodeDecodeError out of start_monitoring, so
    `./chronicle update` printed "Update failed: 'utf-8' codec can't decode byte" and rolled back,
    and the rollback's own start ran the same code. Each case runs a real process through
    common.run with the options the caller passes."""

    NOISE = b' Container fixture-grafana-1 Started \n\xff\xfe daemon text\n'
    SHOWN = '\\xff\\xfe daemon text'

    def compose(self, status, rows=b''):
        """A Compose caller: `ps` prints rows and one line that is not text; every other command
        writes NOISE to stderr and exits with status."""
        def dc(*args, **kwargs):
            from chronicle_ops import common
            listing = args[0] == 'ps'
            script = 'import sys; sys.stdout.buffer.write({!r}); sys.stderr.buffer.write({!r}); sys.exit({})'.format(
                rows + b'\xff\xff\n' if listing else b'', b'' if listing else self.NOISE, 0 if listing else status)
            return common.run([sys.executable, '-c', script], **kwargs)
        return dc

    def setUp(self):
        encoding = patch('locale.getpreferredencoding', return_value='utf-8')
        encoding.start()
        self.addCleanup(encoding.stop)

    def test_start_monitoring(self):
        from chronicle_ops.services import start_monitoring
        healthy = b'grafana\trunning\thealthy\t0\n'
        with Captured() as output:
            self.assertEqual([], start_monitoring(self.compose(0, healthy), ['grafana']))
        self.assertEqual('', output.text)
        with Captured() as output:
            self.assertEqual([], start_monitoring(self.compose(1, healthy), ['grafana']))
        self.assertIn('docker compose reported an error while starting monitoring: ' + self.SHOWN, plain(output.text))

    def test_start_unawaited(self):
        from chronicle_ops.services import start_unawaited
        with Captured() as output:
            self.assertIsNone(start_unawaited(self.compose(0), ['db-backup']))
        self.assertEqual('', output.text)
        with Captured() as output:
            self.assertIsNone(start_unawaited(self.compose(1), ['db-backup']))
        self.assertIn(f'could not start db-backup ({self.SHOWN})', plain(output.text))

    def test_record_operation(self):
        for status, expected in ((0, ''), (1, 'its monitoring event could not be recorded: ' + self.SHOWN)):
            with self.subTest(status=status):
                with patch.dict(os.environ, {'COMPOSE_FILE': 'overlays/monitoring.yml'}), \
                     patch('chronicle_ops.receipts.compose', side_effect=self.compose(status, b'operational-probe\n')), \
                     Captured() as output:
                    receipts.record_operation('restore', 'failure', 'restore_failed')
                self.assertIn(expected, plain(output.text))
                self.assertEqual(bool(expected), bool(output.text))

    def test_the_stop_after_a_failed_start(self):
        from chronicle_ops.restore import Restore, RestoreError
        operation = Restore.__new__(Restore)
        operation.stopped = ['backend', 'web']
        for status, expected in ((0, ''), (1, 'could not confirm every application service stopped after startup failure: '
                                           + self.SHOWN)):
            with self.subTest(status=status):
                with patch('chronicle_ops.restore.compose', side_effect=self.compose(status)), \
                     Captured() as output, self.assertRaises(RestoreError):
                    operation.stop_failed_start('post-restore startup failed', 'startup failure', 'database restored')
                self.assertIn(expected, plain(output.text))
                self.assertEqual(bool(expected), 'could not confirm' in output.text)


class RollbackTests(unittest.TestCase):
    def rollback_fixture(self, root, unhealthy, restore_status=0):
        old, current, state = root / 'old', root / 'new', root / 'state'
        state.mkdir()
        release_directory(old, WITH_MONITORING, state)
        release_directory(current, WITH_MONITORING, state)
        (old / 'chronicle_ops').mkdir()
        (old / 'chronicle_ops/__main__.py').touch()
        marker = state / reconcile.UPGRADE_LOCK
        marker.mkdir()
        receipts.write_json(marker / reconcile.RECOVERY_FILE,
                            {'previous': str(old), 'owner': str(current), 'phase': reconcile.RECOVERY_PHASE})
        environment = compose_shim.install(root / 'bin', unhealthy=unhealthy)
        verified = subprocess.CompletedProcess(['verify'], 0, '')
        patches = [patch.object(Path, 'cwd', return_value=current),
                   patch('chronicle_ops.restore.Restore.execute', return_value=restore_status),
                   patch('chronicle_ops.restore.compose'),
                   patch('chronicle_ops.common.run', return_value=verified),
                   patch('chronicle_ops.upgrade.run', return_value=verified),
                   patch('chronicle_ops.reconcile.install'),
                   patch.dict(os.environ, environment, clear=True)]
        return old, state, marker, patches

    def run_rollback(self, root, unhealthy, restore_status=0, operator_stop=None):
        from chronicle_ops.restore import rollback
        old, state, marker, patches = self.rollback_fixture(root, unhealthy, restore_status)
        if operator_stop is not None:
            (state / reconcile.STOP_MARKER).write_text(operator_stop)
        for item in patches:
            item.start()
        try:
            with Captured() as output:
                try:
                    status = rollback(old, '/backups/reviewed.sql.gz', 'a' * 64, True)
                except (ValueError, subprocess.CalledProcessError) as error:
                    status = error
        finally:
            for item in reversed(patches):
                item.stop()
        return status, state, marker, output.text

    def test_rollback_completes_and_reopens_ingress_when_only_monitoring_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as folder:
            status, state, marker, text = self.run_rollback(Path(folder).resolve(), ['grafana'])
            self.assertEqual(0, status, text)
            self.assertFalse(fence_path(state).exists())
            self.assertFalse((state / reconcile.STOP_MARKER).exists())
            self.assertFalse(marker.exists())
            self.assertIn('./chronicle logs grafana', text)

    def test_failed_start_after_the_restore_reopens_ingress_and_resumes_reconciliation(self):
        with tempfile.TemporaryDirectory() as folder:
            status, state, marker, text = self.run_rollback(Path(folder).resolve(), ['backend'])
            self.assertIsInstance(status, subprocess.CalledProcessError)
            record = json.loads((marker / reconcile.RECOVERY_FILE).read_text())
            self.assertEqual('rollback-owner', record['phase'])
            self.assertFalse(fence_path(state).exists(), 'restored data was left behind a closed fence')
            self.assertFalse((state / reconcile.STOP_MARKER).exists(), 'reconciliation was left paused')

    def test_failed_restore_keeps_ingress_closed_but_resumes_reconciliation(self):
        with tempfile.TemporaryDirectory() as folder:
            status, state, marker, text = self.run_rollback(Path(folder).resolve(), [], restore_status=1)
            self.assertIsInstance(status, ValueError)
            record = json.loads((marker / reconcile.RECOVERY_FILE).read_text())
            self.assertEqual('rollback-restore', record['phase'])
            # A resumed rollback replays the dump: writes accepted now would be discarded.
            self.assertTrue(fence_path(state).exists())
            self.assertFalse((state / reconcile.STOP_MARKER).exists())
            self.assertIn('ingress stays closed', text)

    def test_failed_rollback_keeps_an_operator_pause(self):
        with tempfile.TemporaryDirectory() as folder:
            status, state, _, _ = self.run_rollback(Path(folder).resolve(), ['backend'], operator_stop='')
            self.assertIsInstance(status, subprocess.CalledProcessError)
            self.assertTrue((state / reconcile.STOP_MARKER).exists())


class RecoverUpdateTests(unittest.TestCase):
    def recover(self, phase, failure):
        from chronicle_ops.upgrade import recover_update
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            state = root / 'state'
            state.mkdir()
            previous = release_directory(root / 'old', WITH_MONITORING, state)
            candidate = release_directory(root / 'new', WITH_MONITORING, state)
            marker = state / reconcile.UPGRADE_LOCK
            marker.mkdir()
            receipts.write_json(marker / reconcile.RECOVERY_FILE,
                                {'previous': str(previous), 'owner': str(candidate),
                                 'phase': phase})
            initial = Path.cwd()
            os.chdir(previous)
            try:
                with patch('chronicle_ops.upgrade.start_release', side_effect=failure), \
                     patch('chronicle_ops.upgrade.run', side_effect=failure), \
                     patch.dict(os.environ, {'CHRONICLE_OPS_STATE': str(state)}), Captured(), \
                     self.assertRaises(subprocess.CalledProcessError):
                    recover_update(state)
            finally:
                os.chdir(initial)
            return fence_path(state).exists(), marker.exists()

    def test_failed_pre_migration_recovery_reopens_ingress(self):
        closed, journal = self.recover('prepared', subprocess.CalledProcessError(1, ['up']))
        self.assertTrue(journal)
        self.assertFalse(closed)

    def test_failed_committed_verification_reopens_ingress(self):
        closed, journal = self.recover('committed', subprocess.CalledProcessError(1, ['verify']))
        self.assertTrue(journal)
        self.assertFalse(closed)


class LauncherTests(unittest.TestCase):
    def install(self, root, unhealthy):
        selfhost = root / 'selfhost'
        selfhost.mkdir()
        for name in ('chronicle', 'doctor.sh'):
            shutil.copy2(ROOT / 'selfhost' / name, selfhost / name)
        (selfhost / 'chronicle_ops').symlink_to(ROOT / 'selfhost/chronicle_ops', target_is_directory=True)
        release_directory(selfhost, WITH_MONITORING)
        with (selfhost / '.env').open('a') as settings:
            settings.write('CHRONICLE_RECONCILE_ENABLED=false\n')
        environment = dict(os.environ, **compose_shim.install(root / 'bin', unhealthy=unhealthy))
        for key in ('COMPOSE_FILE', 'COMPOSE_PROJECT_NAME', 'CHRONICLE_RECONCILE_ENABLED'):
            environment.pop(key, None)
        return selfhost, environment

    def harness(self, selfhost, environment, *command):
        return subprocess.run(['bash', str(ROOT / 'tests/selfhost-py/chronicle_harness.sh'), str(selfhost), *command],
                              env=environment, capture_output=True, text=True, timeout=120)

    def test_up_succeeds_and_names_the_unhealthy_monitoring_service(self):
        with tempfile.TemporaryDirectory() as folder:
            selfhost, environment = self.install(Path(folder).resolve(), ['grafana'])
            result = self.harness(selfhost, environment, 'cmd_up', 'up')
            output = result.stdout + result.stderr
            self.assertEqual(0, result.returncode, output)
            self.assertIn('Started.', output)
            self.assertIn('./chronicle logs grafana', output)
            core_wait = wait_calls(environment)[0]
            self.assertIn('backend', core_wait)
            self.assertFalse(set(compose_shim.MONITORING) & set(core_wait), core_wait)

    def test_up_still_fails_on_an_unhealthy_core_service_after_starting_monitoring(self):
        with tempfile.TemporaryDirectory() as folder:
            selfhost, environment = self.install(Path(folder).resolve(), ['postgres'])
            result = self.harness(selfhost, environment, 'cmd_up', 'up')
            self.assertNotEqual(0, result.returncode)
            self.assertIn('startup failed', result.stdout + result.stderr)
            # Grafana and the retained evidence stay available to explain the failure.
            self.assertTrue([command for command in compose_shim.compose_calls(environment, 'up') if 'grafana' in command])

    def test_doctor_reports_every_monitoring_service_health_as_a_warning(self):
        with tempfile.TemporaryDirectory() as folder:
            selfhost, environment = self.install(Path(folder).resolve(), ['grafana'])
            result = self.harness(selfhost, environment, 'doctor_monitoring')
            plain = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
            rows = {line.split()[1]: line for line in plain.splitlines() if line.strip().startswith(('ok', 'warn', 'FAIL'))}
            self.assertIn('warn', rows['monitor-grafana'], plain)
            self.assertIn('unhealthy', rows['monitor-grafana'])
            self.assertIn('./chronicle logs grafana', result.stdout)
            for service in ('cadvisor', 'victoriametrics', 'metrics-exporter'):
                self.assertIn('ok', rows['monitor-' + service], plain)

    def test_up_succeeds_and_names_composes_error_when_monitoring_cannot_be_created(self):
        with tempfile.TemporaryDirectory() as folder:
            selfhost, environment = self.install(Path(folder).resolve(), [])
            environment.update(compose_shim.install(Path(folder).resolve() / 'bin', uncreated=compose_shim.MONITORING,
                                                    up_stderr=ADDRESS_POOLS))
            result = self.harness(selfhost, environment, 'cmd_up', 'up')
            output = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout + result.stderr)
            self.assertEqual(0, result.returncode, output)
            self.assertIn('Started.', output)
            self.assertEqual(1, output.count(CAUSE), output)
            self.assertNotIn('./chronicle logs', output)
            self.assertNotIn('Creating', output)

    def test_doctor_does_not_send_the_operator_to_the_logs_of_a_missing_monitoring_container(self):
        with tempfile.TemporaryDirectory() as folder:
            selfhost, environment = self.install(Path(folder).resolve(), ['victorialogs'])
            environment.update(compose_shim.install(Path(folder).resolve() / 'bin', unhealthy=['victorialogs'],
                                                    uncreated=['grafana']))
            result = self.harness(selfhost, environment, 'doctor_monitoring')
            plain = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
            self.assertIn('grafana is not created', plain)
            self.assertNotIn('./chronicle logs grafana', plain)
            self.assertIn('./chronicle logs victorialogs', plain)


if __name__ == '__main__':
    unittest.main()
