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
import tempfile
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


if __name__ == '__main__':
    unittest.main()
