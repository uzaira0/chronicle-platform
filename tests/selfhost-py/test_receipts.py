import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "selfhost"))
from chronicle_ops import receipts
from chronicle_ops.receipts import finish_operation, publish_journal, write_operation_receipt


class ReceiptTests(unittest.TestCase):
    def test_receipt_contract_private_atomic_and_durable(self):
        stream = io.StringIO()
        stream.name = "/state/operator-receipts/operations/.pending"
        stream.fileno = lambda: 17
        temporary = MagicMock()
        temporary.__enter__.return_value = stream
        with patch.dict(os.environ, {"CHRONICLE_OPS_STATE": "/state", "CHRONICLE_OPS_VERSION": "1.2.3"}), \
             patch.object(Path, "is_symlink", return_value=False), patch.object(Path, "mkdir"), \
             patch.object(Path, "chmod", autospec=True) as protect, patch.object(Path, "unlink"), \
             patch("chronicle_ops.receipts.tempfile.NamedTemporaryFile", return_value=temporary) as create, \
             patch("chronicle_ops.receipts.os.chmod") as chmod, patch("chronicle_ops.receipts.os.fsync") as sync, \
             patch("chronicle_ops.receipts.os.replace") as publish, patch("chronicle_ops.receipts.os.open", return_value=18), \
             patch("chronicle_ops.receipts.os.close"):
            write_operation_receipt("restore", "failure", "restore_failed", 17)
            data = json.loads(stream.getvalue())
            self.assertEqual({key: data[key] for key in ("operation", "outcome", "failureCategory", "durationSeconds", "releaseVersion")},
                             {"operation": "restore", "outcome": "failure", "failureCategory": "restore_failed", "durationSeconds": 17, "releaseVersion": "1.2.3"})
            self.assertTrue(data["timestamp"].endswith("Z"))
            self.assertEqual(create.call_args.kwargs["dir"], Path("/state/operator-receipts/operations"))
            chmod.assert_called_once_with(Path(stream.name), 0o600)
            self.assertEqual([call.args[-1] for call in protect.call_args_list], [0o700, 0o700])
            self.assertEqual([call.args[0] for call in sync.call_args_list], [17, 18])
            self.assertEqual(publish.call_args.args[0], Path(stream.name))

    def test_operation_marker_appears_only_with_its_complete_journal(self):
        import errno
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / ".operation.lock"
            write_text = receipts.write_text
            def second_write_fails(destination, content):
                if Path(destination).name == "phase":
                    raise OSError(errno.ENOSPC, "No space left on device")
                write_text(destination, content)
            with patch("chronicle_ops.receipts.write_text", side_effect=second_write_fails), self.assertRaises(OSError):
                publish_journal(marker, {"owner": "fixture\n", "phase": "prepared\n"})
            self.assertEqual([], list(Path(folder).iterdir()))
            publish_journal(marker, {"owner": "fixture\n", "phase": "prepared\n"})
            self.assertEqual({"owner": "fixture\n", "phase": "prepared\n"},
                             {path.name: path.read_text() for path in marker.iterdir()})
            self.assertEqual(0o700, marker.stat().st_mode & 0o777)
            self.assertEqual({0o600}, {path.stat().st_mode & 0o777 for path in marker.iterdir()})
            with self.assertRaises(FileExistsError):
                publish_journal(marker, {"owner": "other\n"})
            self.assertEqual("fixture\n", (marker / "owner").read_text())

    def test_invalid_contract_or_symlink_never_creates_a_receipt(self):
        with patch.dict(os.environ, {"CHRONICLE_OPS_STATE": "/state"}), \
             patch("chronicle_ops.receipts.tempfile.NamedTemporaryFile") as create:
            for args in (("../bad", "failure"), ("restore", "maybe"), ("restore", "failure", "../bad")):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    write_operation_receipt(*args)
            with patch.object(Path, "is_symlink", return_value=True), self.assertRaises(ValueError):
                write_operation_receipt("restore", "success")
            create.assert_not_called()


    def test_finish_records_one_matching_receipt_and_monitoring_outcome(self):
        for status, outcome, category in ((0, "success", "none"), (41, "failure", "upgrade_failed")):
            with self.subTest(status=status), patch("chronicle_ops.receipts.time.monotonic", return_value=117), \
                 patch("chronicle_ops.receipts.write_operation_receipt") as write, \
                 patch("chronicle_ops.receipts.record_operation") as record:
                finish_operation("upgrade", status, "upgrade_failed", 100)
                write.assert_called_once_with("upgrade", outcome, category, 17)
                record.assert_called_once_with("upgrade", outcome, category)

    def test_monitoring_events_reach_the_running_probe_without_a_one_off_container(self):
        # `compose run` reconciles project networks against this directory's definition: after an update it
        # detaches services a different release started. Recording an event must only exec into the probe.
        from types import SimpleNamespace
        import ast
        for running, expected in (("backend\noperational-probe\n", ["ps", "exec"]), ("backend\n", ["ps"])):
            calls = []
            def compose(*args, **_):
                calls.append(args)
                return SimpleNamespace(returncode=0, stdout=running)
            with self.subTest(running=running), patch.dict(os.environ, {"COMPOSE_FILE": "docker-compose.yml:overlays/monitoring.yml"}), \
                    patch("chronicle_ops.receipts.compose", side_effect=compose):
                receipts.record_operation("update", "success")
            self.assertEqual(expected, [args[0] for args in calls])
            if "exec" in expected:
                self.assertEqual(("exec", "-T", "operational-probe", "/monitoring/record-operation.sh",
                                  "update", "success", "none"), calls[1])
        package = Path(receipts.__file__).parent
        probe_calls = [f"{path.name}:{node.lineno}" for path in sorted(package.glob("*.py"))
                       for node in ast.walk(ast.parse(path.read_text())) if isinstance(node, ast.Call)
                       and any(isinstance(arg, ast.Constant) and arg.value == "operational-probe" for arg in node.args)
                       and not (node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "exec")]
        self.assertEqual([], probe_calls)

    def test_failed_receipt_write_warns_and_still_records_the_monitoring_outcome(self):
        with patch('chronicle_ops.receipts.write_operation_receipt', side_effect=OSError('fixture disk full')), \
             patch('chronicle_ops.receipts.record_operation') as record, patch('sys.stderr', io.StringIO()) as output:
            finish_operation('restore', 0, 'restore_failed', 0)
            record.assert_called_once_with('restore', 'success', 'none')
            self.assertIn('receipt', output.getvalue())


class FailedUpgradeLogTests(unittest.TestCase):
    def test_failed_migration_log_is_shown_kept_privately_and_named_in_the_receipt(self):
        import subprocess
        import tempfile
        from types import SimpleNamespace
        from chronicle_ops import upgrade
        log = ("2026-10-22T09:24:08,572 INFO [main] com.geekbeast.postgres.PostgresTableManager - Processing\n"
               "Exception in thread \"main\" FlywayValidateException: Validate failed\n"
               "Migration checksum mismatch for migration version 1\n"
               "\tat org.flywaydb.core.Flyway.migrate(Flyway.java:187)\n")
        def compose(directory, project, names, *args, **kwargs):
            if args[0] == 'ps':
                return SimpleNamespace(stdout='config-guard 0\nmigrate 1\n')
            if args[0] == 'logs':
                self.assertEqual(args[-1], 'migrate')
                return SimpleNamespace(stdout=log)
            return SimpleNamespace(stdout='', returncode=0)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); previous = root / 'old'; candidate = root / 'new'; state = root / 'state'
            for path in (previous, candidate, state): path.mkdir()
            (previous / '.env').write_text(f"COMPOSE_PROJECT_NAME=fixture\nCHRONICLE_STATE_DIR='{state}'\n")
            (previous / '.env').chmod(0o600)
            (state / '.chronicle-upgrade.lock').mkdir()
            with patch('chronicle_ops.upgrade.recover_update') as recover, patch('chronicle_ops.upgrade.compose_release', side_effect=compose), \
                 patch('chronicle_ops.upgrade.start_release', side_effect=subprocess.CalledProcessError(1, ['up'])), \
                 patch.object(upgrade.Upgrade, 'prepare'), patch.object(upgrade.Upgrade, 'snapshot'), \
                 patch('chronicle_ops.upgrade.os.chdir'), patch('chronicle_ops.upgrade.acquire_operation_lock'), \
                 patch('chronicle_ops.upgrade.release_operation_lock'), patch('chronicle_ops.upgrade.require_current_owner'), \
                 patch('chronicle_ops.upgrade.finish_operation') as finish, patch.dict(os.environ, {}, clear=False), \
                 patch('sys.stdout', io.StringIO()) as output:
                self.assertEqual(upgrade.upgrade(previous, candidate), 1)
            recover.assert_called_once_with(state)
            saved, = (state / 'operator-receipts/failed-services').glob('*-migrate.log')
            self.assertEqual(saved.read_text(), log)
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            shown = output.getvalue()
            self.assertIn('Migration checksum mismatch for migration version 1', shown)
            self.assertNotIn('Processing', shown)
            self.assertIn(str(saved), shown)
            self.assertEqual(finish.call_args.args[:3], ('upgrade', 1, 'migration_failed'))
