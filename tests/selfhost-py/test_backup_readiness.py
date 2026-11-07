"""Update and rollback never wait for db-backup's first dump (O10d).

db-backup is healthy only after a fresh full dump passes a restore check (backups.yml healthcheck,
backup-image/selfcheck.py health), which takes up to BACKUP_VERIFY_TIMEOUT_SECONDS. The update has
already taken its own quiesced dump, so waiting on it held ingress closed and rolled a good update
back when the dump was slow. db-backup is now started with the release and reported after the
commit, as monitoring is; backups still run, and doctor and verify still report them.

Every case runs the real operator code against compose_shim's fake `docker` on PATH."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import compose_shim
from chronicle_ops.ingress import fence_path
from test_monitoring_startup import BASE, Captured, release_directory, wait_calls
from test_rollback_serving import RollbackFixture

WITH_BACKUPS = BASE + ['overlays/backups.yml']


def up_calls_for(environment, service):
    return [command for command in compose_shim.compose_calls(environment, 'up') if service in command]


class UpdateStartTests(unittest.TestCase):
    def start(self, **scenario):
        from chronicle_ops.upgrade import report_release_readiness, start_release
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name).resolve()
        directory = release_directory(root / 'candidate', WITH_BACKUPS)
        environment = compose_shim.install(root / 'bin', **scenario)
        with patch.dict(os.environ, environment), Captured() as output:
            start_release(directory, 'fixture', WITH_BACKUPS, '60')
            # What Upgrade.start and Rollback.execute print after their commit.
            report_release_readiness(directory, 'fixture', WITH_BACKUPS)
        return environment, output.text

    def test_a_first_dump_still_running_does_not_fail_the_update_start(self):
        environment, _ = self.start(starting=['db-backup'])
        for command in wait_calls(environment):
            self.assertNotIn('db-backup', command)
        self.assertIn('backend', wait_calls(environment)[0])
        started = up_calls_for(environment, 'db-backup')
        self.assertTrue(started, 'db-backup was never started, so no backup would run')
        self.assertNotIn('--wait', started[0])
        # Started after the core services are healthy, without waiting on its dependencies again.
        self.assertIn('--no-deps', started[0])

    def test_a_failed_db_backup_only_warns_and_names_its_log(self):
        _, text = self.start(unhealthy=["db-backup"])
        self.assertIn('db-backup is unhealthy', text)
        self.assertIn('./chronicle logs db-backup', text)

    def test_a_core_service_still_fails_the_update(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.start(unhealthy=['backend'], starting=['db-backup'])


class RollbackTests(unittest.TestCase):
    def test_a_rollback_ends_serving_while_db_backup_takes_its_first_dump(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = RollbackFixture(Path(folder).resolve(), WITH_BACKUPS, starting=['db-backup'])
            status, text = fixture.run()
            self.assertEqual(0, status, text)
            self.assertFalse(fence_path(fixture.state).exists())
            self.assertFalse(fixture.marker.exists())
            for command in wait_calls(fixture.environment):
                self.assertNotIn('db-backup', command)
            # Reported after the commit, not waited for before it.
            self.assertIn('db-backup is taking its first backup', text)
            self.assertIn('./chronicle doctor', text)


class ReadinessReportTests(unittest.TestCase):
    def test_a_starting_backup_is_a_note_and_a_failed_one_a_warning(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from types import SimpleNamespace

        from chronicle_ops.services import report_unawaited
        for row, expected, shown in (('db-backup\trunning\tstarting\t0', [('db-backup', 'starting')], 'taking its first backup'),
                                     ('db-backup\texited\t\t1', [('db-backup', 'exited with status 1')], 'warning: db-backup is exited'),
                                     ('db-backup\trunning\thealthy\t0', [], '')):
            with self.subTest(row=row):
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    states = report_unawaited(lambda *_args, row=row, **_kwargs: SimpleNamespace(stdout=row + '\n'), ['db-backup'])
                self.assertEqual(expected, states)
                self.assertIn(shown, output.getvalue().replace('\x1b[33m', '').replace('\x1b[0m', ''))

    def test_only_db_backup_is_left_out_of_the_update_wait(self):
        from chronicle_ops.services import UNAWAITED_BY_UPDATE, awaited_by_update
        self.assertEqual({'db-backup'}, set(UNAWAITED_BY_UPDATE))
        self.assertEqual((['postgres', 'backend', 'web'], ['db-backup']),
                         awaited_by_update(['postgres', 'backend', 'db-backup', 'web']))


class PostureBaselineTests(unittest.TestCase):
    """Not waiting for db-backup leaves the verified-backup marker as it was before the update, so
    verify judges the same backup. A gap that existed before stays a warning; it never rolls back."""

    def transcript(self, backups, baseline):
        import io
        from contextlib import redirect_stdout

        from chronicle_ops.verify import reporter, verify_configured_backups
        settings = {'COMPOSE_FILE': 'docker-compose.yml:overlays/backups.yml', 'POSTGRES_DB': 'chronicle',
                    'BACKUP_SCHEDULE': '@daily'}
        report, failed = reporter(baseline)
        output = io.StringIO()
        with patch.dict(os.environ, CHRONICLE_OPS_BACKUPS=str(backups)), \
             patch('chronicle_ops.verify.verify_backup_storage', return_value=0), redirect_stdout(output):
            verify_configured_backups(settings, report)
        return output.getvalue(), failed()

    def test_a_backup_gap_from_before_the_update_stays_a_warning(self):
        import json
        import time

        from chronicle_ops.verify import failed_checks, regressions
        with tempfile.TemporaryDirectory() as folder:
            backups = Path(folder).resolve() / 'backups'
            (backups / 'last').mkdir(parents=True)
            backups.chmod(0o700)
            for gap in ('missing', 'stale'):
                with self.subTest(gap=gap):
                    marker = backups / 'last' / 'chronicle-verified.json'
                    if gap == 'stale':
                        marker.write_text(json.dumps({'database': 'chronicle', 'verified_at': time.time() - 30 * 86400,
                                                      'file': 'chronicle-1.sql.gz', 'sha256': '0' * 64,
                                                      'uncompressed_bytes': 1}))
                    before, failed_before = self.transcript(backups, [])
                    self.assertTrue(failed_before, before)
                    baseline = failed_checks(before)
                    after, failed_after = self.transcript(backups, baseline)
                    self.assertFalse(failed_after, after)
                    self.assertIn('already failing before this update', after)
                    self.assertEqual([], regressions(1, after, baseline))


if __name__ == '__main__':
    unittest.main()
