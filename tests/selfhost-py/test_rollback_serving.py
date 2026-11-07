"""A rollback ends with the previous release serving, whatever else fails on the way (UPD-N1).

The operator only runs `./chronicle update`. A failure inside its automatic rollback must not leave
nothing serving: the crontab is optional and only warns (the next `./chronicle up` installs it),
and every other step that fails keeps the journal at that step, so the rerun resumes it there.

Every case runs the real Rollback against compose_shim's fake `docker` on PATH."""
import importlib
import json
import os
import pkgutil
import subprocess
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import chronicle_ops
import compose_shim
from chronicle_ops import receipts, reconcile, release
from chronicle_ops.ingress import fence_path
from test_monitoring_startup import (
    WITH_MONITORING,
    Captured,
    release_directory,
    wait_calls,
)

# Operator modules bind common.run when first imported. Import every one now, so that a module the
# rollback imports lazily (update, through clear_recovery) never binds the fixture's patched run
# and keeps it for every later test.
for module in pkgutil.iter_modules(chronicle_ops.__path__):
    importlib.import_module('chronicle_ops.' + module.name)


def crontab_write_fails(lines):
    raise ValueError('could not write the operator crontab; check `crontab -l` and rerun this command '
                     '(crontab: /var/spool/cron: Read-only file system)')


class RollbackFixture:
    def __init__(self, root, names=WITH_MONITORING, starting=()):
        self.old, self.new, self.state = root / 'old', root / 'new', root / 'state'
        self.state.mkdir()
        release_directory(self.old, names, self.state)
        release_directory(self.new, names, self.state)
        (self.old / 'chronicle_ops').mkdir()
        (self.old / 'chronicle_ops/__main__.py').touch()
        self.marker = self.state / reconcile.UPGRADE_LOCK
        self.marker.mkdir()
        receipts.write_json(self.marker / reconcile.RECOVERY_FILE,
                            {'previous': str(self.old), 'owner': str(self.new), 'phase': reconcile.RECOVERY_PHASE})
        # An installed schedule: the rollback rewrites it to start the previous release.
        (self.state / 'reconcile.sh').write_text(f'cd {self.new}\n')
        self.environment = compose_shim.install(root / 'bin', starting=starting)
        verified = subprocess.CompletedProcess(['verify'], 0, '')
        self.patches = [patch.object(Path, 'cwd', return_value=self.new),
                        patch('chronicle_ops.restore.Restore.execute', return_value=0),
                        patch('chronicle_ops.restore.compose'),
                        patch('chronicle_ops.common.run', return_value=verified),
                        patch('chronicle_ops.upgrade.run', return_value=verified),
                        # The real reconcile.install on a Linux host whose crontab cannot be written.
                        patch('chronicle_ops.reconcile.schedule_blocker', return_value=None),
                        patch('chronicle_ops.reconcile.crontab_transaction', nullcontext),
                        patch('chronicle_ops.reconcile.crontab_without_project',
                              return_value=([], '# chronicle-reconcile:fixture', True)),
                        patch('chronicle_ops.reconcile.write_crontab', side_effect=crontab_write_fails),
                        patch.dict(os.environ, self.environment, clear=True)]

    def run(self, *extra):
        from chronicle_ops.restore import rollback
        active = [*self.patches, *extra]
        for item in active:
            item.start()
        try:
            with Captured() as output:
                try:
                    status = rollback(self.old, '/backups/reviewed.sql.gz', 'a' * 64, True)
                except (OSError, ValueError, subprocess.CalledProcessError) as error:
                    status = error
        finally:
            for item in reversed(active):
                item.stop()
        return status, output.text

    def owner(self):
        return Path((self.state / '.chronicle-owner').read_text().strip())

    def started_previous(self):
        return any('backend' in command for command in wait_calls(self.environment))


class RollbackScheduleTests(unittest.TestCase):
    def test_a_crontab_that_cannot_be_written_still_ends_with_the_previous_release_serving(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = RollbackFixture(Path(folder).resolve())
            status, text = fixture.run()
            self.assertEqual(0, status, text)
            self.assertTrue(fixture.started_previous(), 'the previous release was never started')
            self.assertEqual(fixture.old, fixture.owner())
            self.assertFalse(fixture.marker.exists(), 'the rollback journal was left open')
            self.assertFalse(fence_path(fixture.state).exists(), 'participant ingress stayed closed')
            self.assertIn('Read-only file system', text)
            self.assertIn('./chronicle up', text)
            # The next `./chronicle up` installs the schedule it could not write.
            self.assertTrue((fixture.state / reconcile.SCHEDULE_PENDING).is_file())

    def test_the_next_up_installs_a_schedule_the_rollback_could_not_write(self):
        from chronicle_ops.__main__ import run_reconcile
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder).resolve()
            (state / 'reconcile.sh').write_text('cd /a/release/that/was/rolled/back\n')
            (state / reconcile.SCHEDULE_PENDING).write_text('crontab: Read-only file system\n')
            installed = []
            with patch.dict(os.environ, CHRONICLE_OPS_STATE=str(state), CHRONICLE_OPS_PROJECT='fixture',
                            CHRONICLE_RECONCILE_ENABLED='true'), \
                 patch('chronicle_ops.reconcile.unavailable', return_value=None), \
                 patch('chronicle_ops.reconcile.install', side_effect=lambda *args, **_: installed.append(args)):
                self.assertEqual(0, run_reconcile(SimpleNamespace(action='resume')))
            self.assertEqual(1, len(installed), 'up did not reinstall the pending schedule')
            self.assertFalse((state / reconcile.SCHEDULE_PENDING).exists())

    def test_doctor_names_a_pending_schedule(self):
        import io
        from contextlib import redirect_stdout

        from chronicle_ops.__main__ import run_reconcile
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder).resolve()
            (state / reconcile.SCHEDULE_PENDING).write_text('crontab: Read-only file system\n')
            output = io.StringIO()
            with patch.dict(os.environ, CHRONICLE_OPS_STATE=str(state), CHRONICLE_RECONCILE_ENABLED='true'), \
                 patch('chronicle_ops.reconcile.unavailable', return_value=None), redirect_stdout(output):
                self.assertEqual(0, run_reconcile(SimpleNamespace(action='host')))
            self.assertIn('could not write the operator crontab', output.getvalue())

    def test_an_installed_current_schedule_is_left_alone_by_up(self):
        from chronicle_ops.__main__ import run_reconcile
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder).resolve()
            (state / 'reconcile.sh').write_text('cd /current\n')
            with patch.dict(os.environ, CHRONICLE_OPS_STATE=str(state), CHRONICLE_OPS_PROJECT='fixture',
                            CHRONICLE_RECONCILE_ENABLED='true'), \
                 patch('chronicle_ops.reconcile.unavailable', return_value=None), \
                 patch('chronicle_ops.reconcile.install') as install:
                self.assertEqual(0, run_reconcile(SimpleNamespace(action='resume')))
            install.assert_not_called()


class RollbackStepFailureTests(unittest.TestCase):
    """Every other rollback step: a failure stops at that step with a non-zero result, keeps the
    journal there, and the rerun (the operator's next `./chronicle update`) finishes serving."""

    STEPS = (('restore_database', 'rollback-restore'), ('stop_candidate', 'rollback-restored'),
             ('transfer_settings', 'rollback-down'), ('transfer_owner', 'rollback-settings'),
             ('start_previous', 'rollback-owner'), ('verify_previous', 'rollback-started'))

    def test_each_failing_step_is_resumed_by_the_rerun(self):
        from chronicle_ops.restore import Rollback
        for step, phase in self.STEPS:
            with self.subTest(step=step), tempfile.TemporaryDirectory() as folder:
                fixture = RollbackFixture(Path(folder).resolve())
                status, text = fixture.run(patch.object(Rollback, step, side_effect=OSError(f'{step} failed')))
                self.assertIsInstance(status, OSError, text)
                self.assertEqual(phase, json.loads((fixture.marker / reconcile.RECOVERY_FILE).read_text())['phase'])
                status, text = fixture.run()
                self.assertEqual(0, status, text)
                self.assertEqual(fixture.old, fixture.owner())
                self.assertTrue(fixture.started_previous())
                self.assertFalse(fixture.marker.exists())
                self.assertFalse(fence_path(fixture.state).exists())

    def test_an_ownership_write_failure_is_not_mistaken_for_a_schedule_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = RollbackFixture(Path(folder).resolve())
            status, text = fixture.run(patch.object(release, 'set_current_owner', side_effect=OSError('No space left on device')))
            self.assertIsInstance(status, OSError, text)
            self.assertEqual('rollback-settings',
                             json.loads((fixture.marker / reconcile.RECOVERY_FILE).read_text())['phase'])


if __name__ == '__main__':
    unittest.main()
