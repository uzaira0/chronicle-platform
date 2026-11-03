import io
import gzip
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from test_restore import DUMP
from test_restore_schemas import PgTdeFixture

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "selfhost/backup-image"))
import selfcheck


class SelfcheckTests(unittest.TestCase):
    def setUp(self):
        for name, options in (("os.open", {"return_value": 17}), ("os.close", {}), ("fcntl.flock", {})):
            mock = patch("selfcheck." + name, **options)
            mock.start()
            self.addCleanup(mock.stop)

    source = {"database_bytes": 4096, "version": "112", "extensions": [], "tables": ["studies", "study_participants"],
              "row_counts": {"public.studies": 2, "public.study_participants": 3}}

    def test_cleanup_on_success_failure_timeout_and_signal(self):
        for failure in (None, RuntimeError("restore failed"), RuntimeError("self-check interrupted by signal 15"), subprocess.TimeoutExpired("psql", 15)):
            with self.subTest(failure=failure), patch("selfcheck.os.replace"), patch("selfcheck.publish_backup"), \
                 patch("selfcheck.dump_snapshot", return_value=self.source), \
                 patch("selfcheck.check_dump", side_effect=failure), patch("selfcheck.drop_scratch") as drop, \
                 patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
                self.assertEqual(selfcheck.main(["dump", "chronicle", "backup.sql.gz", "-Z1"]), int(failure is not None))
                drop.assert_called_once_with()

    def test_reserved_source_never_drops_itself(self):
        with patch("selfcheck.drop_scratch") as drop, patch("sys.stderr", io.StringIO()):
            self.assertEqual(selfcheck.main(["dump", selfcheck.SCRATCH, "backup.sql.gz"]), 1)
            drop.assert_not_called()

    def test_cleanup_failure_turns_success_into_failure(self):
        with patch("selfcheck.dump_snapshot", return_value=self.source), patch("selfcheck.check_dump"), \
             patch("selfcheck.drop_scratch", side_effect=subprocess.CalledProcessError(1, "psql")), \
             patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()) as error:
            self.assertEqual(selfcheck.main(["dump", "chronicle", "backup.sql.gz"]), 1)
            self.assertIn("scratch cleanup failed", error.getvalue())

    def test_space_guard_uses_uncompressed_size_and_fails_closed(self):
        for disk in ("disk 100 1 0 1% /db", "disk 100 1 4 1% /db", "malformed"):
            with self.subTest(disk=disk), patch("selfcheck.validate_dump", return_value=4096), \
                 patch("selfcheck.psql", return_value=disk), \
                 patch("selfcheck.drop_scratch") as drop:
                with self.assertRaisesRegex(RuntimeError, "insufficient space"):
                    selfcheck.check_dump("chronicle", Path("backup.sql.gz"), self.source)
                drop.assert_not_called()

    def test_space_guard_also_reserves_the_source_database_size(self):
        source = dict(self.source, database_bytes=1024 * 1024)
        with patch("selfcheck.validate_dump", return_value=4096), \
             patch("selfcheck.psql", return_value="disk 100 1 16 1% /db"), \
             patch("selfcheck.drop_scratch") as drop:
            with self.assertRaisesRegex(RuntimeError, "insufficient space"):
                selfcheck.check_dump("chronicle", Path("backup.sql.gz"), source)
            drop.assert_not_called()

    def test_scratch_restore_gets_only_the_extensions_a_real_restore_creates(self):
        # A fresh-volume restore creates no extension the dump left out unless restore does it, and the
        # functions that call them still replay without error; the scratch copy must not hide that.
        for source_extensions, passes in ((["pgcrypto", "plpgsql"], True), (["pg_trgm", "pgcrypto", "plpgsql"], False)):
            with self.subTest(extensions=source_extensions):
                scratch, events = {"plpgsql"}, []
                def psql(database, sql, capture=True, timeout=None):
                    for name in re.findall(r'CREATE EXTENSION IF NOT EXISTS "?(\w+)', sql):
                        scratch.add(name)
                        events.append((database, name))
                    if "df -Pk" in sql:
                        return "disk 100 1 1000000 1% /db"
                    if "json_build_object" in sql:
                        return json.dumps(dict(self.source, extensions=sorted(scratch)))
                    if "json_object_agg" in sql:
                        return json.dumps(self.source['row_counts'])
                    return "0" if "count(*)" in sql else ""
                restore = MagicMock()
                restore.wait.return_value = 0
                def replay(command, **kwargs):
                    events.append("replay")
                    self.assertIn("ON_ERROR_STOP=1", command)  # a failing statement fails the check
                    return restore
                source = dict(self.source, extensions=source_extensions)
                with patch.dict("os.environ", ENABLE_ENCRYPTION="false"), patch("selfcheck.validate_dump", return_value=4096), \
                     patch("selfcheck.psql", side_effect=psql), patch("selfcheck.drop_scratch"), \
                     patch("selfcheck.subprocess.Popen", side_effect=replay), patch("selfcheck.gzip.open", return_value=io.BytesIO(b"")):
                    if passes:
                        selfcheck.check_dump("chronicle", Path("backup.sql.gz"), source)
                        # Created in scratch before replay, as restore.sh does on a fresh volume.
                        self.assertLess(events.index((selfcheck.SCRATCH, "pgcrypto")), events.index("replay"))
                    else:
                        with self.assertRaisesRegex(RuntimeError, "pg_trgm"):
                            selfcheck.check_dump("chronicle", Path("backup.sql.gz"), source)

    def test_scratch_cleanup_is_bounded(self):
        with patch("selfcheck.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as call:
            selfcheck.drop_scratch()
            self.assertIn("DROP DATABASE IF EXISTS " + selfcheck.SCRATCH, call.call_args.kwargs["input"])
            self.assertEqual(call.call_args.kwargs["timeout"], 15)

    def test_signal_is_an_error_for_the_cleanup_path(self):
        with self.assertRaisesRegex(RuntimeError, "signal 15"):
            selfcheck.interrupted(signal.SIGTERM, None)

class OwnerInput:
    def __init__(self):
        self.text, self.closed = "", False

    def write(self, text):
        self.text += text

    def flush(self):
        pass

    def close(self):
        self.closed = True


class SnapshotOwner:
    """The psql session that holds the exported snapshot open while pg_dump reads it."""
    def __init__(self, replies, status=0):
        self.stdin, self.stdout = OwnerInput(), io.StringIO("".join(reply + "\n" for reply in replies))
        self.status, self.returncode, self.terminated = status, None, False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated, self.returncode = True, -15

    def wait(self):
        if self.returncode is None:
            self.returncode = self.status
        return self.returncode


class SnapshotDumpTests(unittest.TestCase):
    SNAPSHOT = "00000003-0000001B-1"
    MANIFEST = {"database_bytes": 4096, "version": "112", "extensions": ["plpgsql"], "tables": ["studies", "flyway_schema_history"]}

    def dump(self, owner, pg_dump_status=0):
        self.dumped = []
        def pg_dump(command, stdout, check):
            self.dumped.append((command, owner.stdin.text))
            stdout.write(gzip.compress(DUMP))
            if pg_dump_status:
                raise subprocess.CalledProcessError(pg_dump_status, command)
        with tempfile.TemporaryDirectory() as folder, \
             patch("selfcheck.subprocess.Popen", return_value=owner) as popen, patch("selfcheck.subprocess.run", side_effect=pg_dump):
            partial = Path(folder) / "chronicle-20261031-020000.sql.gz.partial"
            try:
                return selfcheck.dump_snapshot("chronicle", partial, ["-Z1"])
            finally:
                self.environment = popen.call_args.kwargs["env"]
                self.written = partial.read_bytes() if partial.exists() else None

    def test_dump_reads_the_counted_snapshot_while_its_transaction_stays_open(self):
        owner = SnapshotOwner([self.SNAPSHOT, json.dumps(self.MANIFEST), json.dumps({"public.studies": 2})])
        manifest = self.dump(owner)
        self.assertEqual(dict(self.MANIFEST, row_counts={"public.studies": 2}), manifest)
        command, sent_before_dump = self.dumped[0]
        self.assertEqual(["pg_dump", "-d", "chronicle", "-Z1", *selfcheck.DUMP_EXCLUDE_OPTIONS, "--snapshot=" + self.SNAPSHOT], command)
        self.assertIn("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;", sent_before_dump)
        self.assertIn("count(*) AS rows FROM public.studies", sent_before_dump)
        self.assertNotIn("ROLLBACK", sent_before_dump)  # pg_dump attaches to a live snapshot
        self.assertTrue(owner.stdin.text.endswith("ROLLBACK;\n\\q\n"))
        self.assertIn("idle_in_transaction_session_timeout=0", self.environment["PGOPTIONS"])
        self.assertEqual(DUMP, gzip.decompress(self.written))
        self.assertFalse(owner.terminated)

    def test_a_lost_snapshot_or_failed_dump_ends_the_source_transaction(self):
        for replies, owner_status, pg_dump_status, error in (
                ([""], 0, 0, "source snapshot unavailable"),  # psql stopped at the catalog gate
                ([self.SNAPSHOT, json.dumps(self.MANIFEST), "{}"], 0, 1, "returned non-zero exit status 1"),
                ([self.SNAPSHOT, json.dumps(self.MANIFEST), "{}"], 2, 0, "source snapshot failed")):
            with self.subTest(error=error):
                owner = SnapshotOwner(replies, owner_status)
                with self.assertRaisesRegex((RuntimeError, subprocess.CalledProcessError), error):
                    self.dump(owner, pg_dump_status)
                # Never left holding an open transaction: either it exited on its own or it is terminated.
                self.assertEqual(owner_status == 0, owner.terminated)
                self.assertIsNotNone(owner.returncode)
                if error == "source snapshot unavailable":
                    self.assertEqual([], self.dumped)
                    self.assertIsNone(self.written)


REAL_POPEN = subprocess.Popen


class ScratchDatabase:
    """Answers check_dump's queries the way the scratch restore would, and records the replayed dump."""
    def __init__(self, source, restored=None, counts=None, wrong_method="0", ready="t", replay_status=0, broken_pipe=False):
        self.restored = dict(source, **(restored or {}))
        self.counts = dict(source["row_counts"], **(counts or {}))
        self.wrong_method, self.ready, self.replay_status, self.broken_pipe = wrong_method, ready, replay_status, broken_pipe
        self.statements, self.replayed = [], bytearray()

    def psql(self, database, sql, capture=True, timeout=None):
        self.statements.append((database, sql))
        if "df -Pk" in sql:
            return "disk 100 1 1000000 1% /db"
        if "pg_tde_key_info" in sql:
            return self.ready
        if "json_build_object" in sql:
            return json.dumps(self.restored)
        if "json_object_agg" in sql:
            return json.dumps(self.counts)
        return self.wrong_method if "a.amname" in sql else ""

    def write(self, chunk):
        if self.broken_pipe:
            raise BrokenPipeError
        self.replayed += chunk

    def close(self):
        if self.broken_pipe:
            raise BrokenPipeError  # psql already exited under ON_ERROR_STOP

    closed = False

    def popen(self, command, **kwargs):
        if command[0] != "psql":
            return REAL_POPEN(command, **kwargs)  # the shipped init-tde.sh bootstrap runs for real
        restore = MagicMock(stdin=self)
        restore.wait.return_value = self.replay_status
        return restore


class ScratchRestoreTests(unittest.TestCase):
    source = dict(SelfcheckTests.source, extensions=["pg_tde", "plpgsql"])

    def check(self, scratch, encryption):
        with tempfile.TemporaryDirectory() as folder, patch.dict("os.environ", ENABLE_ENCRYPTION=encryption), \
             patch("selfcheck.psql", side_effect=scratch.psql), patch("selfcheck.drop_scratch"), \
             patch("selfcheck.subprocess.Popen", side_effect=scratch.popen):
            dump = Path(folder) / "chronicle.sql.gz.partial"
            dump.write_bytes(gzip.compress(DUMP))
            selfcheck.check_dump("chronicle", dump, self.source)

    def test_a_scratch_copy_that_differs_from_the_source_is_never_published(self):
        for encryption, scratch, error in (
                ("false", ScratchDatabase(self.source, replay_status=3), "restore failed"),
                ("false", ScratchDatabase(self.source, broken_pipe=True), "restore failed"),
                ("false", ScratchDatabase(self.source, restored={"version": "111"}), "schema version mismatch"),
                ("false", ScratchDatabase(self.source, restored={"tables": ["studies"]}), "missing public tables"),
                ("false", ScratchDatabase(self.source, counts={"public.study_participants": 2}), "study_participants row count mismatch"),
                ("false", ScratchDatabase(self.source, wrong_method="1"), "restored tables do not use heap"),
                ("true", ScratchDatabase(self.source, restored={"extensions": ["plpgsql"]}), "lacks extensions: pg_tde"),
                ("true", ScratchDatabase(self.source, ready="f"), "lacks TDE key or tde_heap default"),
                ("true", ScratchDatabase(self.source, wrong_method="2"), "restored tables do not use tde_heap"),
                ("yes", ScratchDatabase(self.source), "ENABLE_ENCRYPTION must be true or false")):
            with self.subTest(error=error, encryption=encryption):
                with self.assertRaisesRegex((RuntimeError, ValueError), error):
                    self.check(scratch, encryption)

    def test_a_matching_scratch_copy_passes_with_the_whole_dump_replayed(self):
        for encryption in ("false", "true"):
            with self.subTest(encryption=encryption):
                scratch = ScratchDatabase(self.source, restored={"extensions": ["plpgsql"]} if encryption == "false" else None)
                self.check(scratch, encryption)
                self.assertEqual(DUMP, bytes(scratch.replayed))
                bootstrap = [sql for database, sql in scratch.statements
                             if database == selfcheck.SCRATCH and "default_table_access_method = 'tde_heap'" in sql]
                # The shipped init-tde.sh bootstrap encrypts the scratch copy exactly as db-init does the real one.
                self.assertEqual(int(encryption == "true"), len(bootstrap))
                method = "tde_heap" if encryption == "true" else "heap"
                self.assertIn(f"a.amname <> '{method}'", scratch.statements[-1][1])


class SelfcheckEntryTests(unittest.TestCase):
    def test_health_passes_only_while_every_published_dump_is_non_empty(self):
        with tempfile.TemporaryDirectory() as folder:
            marker, dump, empty = (Path(folder) / name for name in ("backup-success", "chronicle-1.sql.gz", "chronicle-2.sql.gz"))
            dump.write_bytes(gzip.compress(DUMP))
            empty.write_bytes(b"")
            for contents, status in ((None, 1), ("", 1), (f"{dump}\n{empty}\n", 1), (f"{dump}\n", 0)):
                with self.subTest(contents=contents):
                    marker.unlink(missing_ok=True)
                    if contents is not None:
                        marker.write_text(contents)
                    with patch.dict(os.environ, BACKUP_SUCCESS_MARKER=str(marker)):
                        self.assertEqual(status, selfcheck.main(["health"]))

    def test_a_new_run_removes_full_data_fragments_a_killed_run_left_behind(self):
        with tempfile.TemporaryDirectory() as folder:
            last = Path(folder) / "last"
            last.mkdir()
            abandoned = [last / "chronicle-20261030-020000.sql.gz.partial", last / "chronicle-20261030-020000.sql.gz.release.partial"]
            foreign = last / "other-20261030-020000.sql.gz.partial"
            for path in (*abandoned, foreign):
                path.write_bytes(gzip.compress(DUMP))
            seen = []
            def snapshot(database, partial, options):
                seen.extend(path for path in abandoned if path.exists())
                partial.write_bytes(gzip.compress(DUMP))
                return SelfcheckTests.source
            with patch("selfcheck.dump_snapshot", side_effect=snapshot), patch("selfcheck.check_dump"), \
                 patch("selfcheck.drop_scratch"), patch("sys.stdout", io.StringIO()):
                self.assertEqual(0, selfcheck.main(["dump", "chronicle", str(last / "chronicle-20261031-020000.sql.gz")]))
            self.assertEqual([], seen)
            self.assertTrue(foreign.exists())
            self.assertEqual(["chronicle-20261031-020000.sql.gz", "chronicle-verified.json", foreign.name],
                             sorted(path.name for path in last.iterdir() if not path.name.startswith(".")))

    def test_a_dump_whose_verified_marker_cannot_be_written_is_withdrawn(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "last/chronicle-20261031-020000.sql.gz"
            destination.parent.mkdir()
            def snapshot(database, partial, options):
                partial.write_bytes(gzip.compress(DUMP))
                return SelfcheckTests.source
            def marker_disk_full(path, database, source, *, pending):
                os.replace(pending, path)
                raise OSError(28, "No space left on device")
            with patch("selfcheck.dump_snapshot", side_effect=snapshot), patch("selfcheck.check_dump"), \
                 patch("selfcheck.drop_scratch"), patch("selfcheck.publish_backup", side_effect=marker_disk_full), \
                 patch("sys.stderr", io.StringIO()) as error:
                self.assertEqual(1, selfcheck.main(["dump", "chronicle", str(destination)]))
            self.assertIn("Restore self-check FAIL: [Errno 28] No space left on device", error.getvalue())
            self.assertEqual([], [path.name for path in destination.parent.iterdir() if not path.name.startswith(".")])

    def test_the_backup_timeout_signal_cleans_the_scratch_database_and_publishes_nothing(self):
        # backup.sh runs the check under `timeout --signal=TERM`; the stand-in psql delivers that TERM mid-snapshot.
        with tempfile.TemporaryDirectory() as folder:
            bin_dir, last = Path(folder) / "bin", Path(folder) / "last"
            bin_dir.mkdir()
            last.mkdir()
            calls = Path(folder) / "psql.log"
            (bin_dir / "psql").write_text('#!/usr/bin/env bash\nIFS= read -r line\nprintf "%s\\n" "$line" >> "$PSQL_LOG"\n'
                                          'case $line in BEGIN*) kill -TERM "$PPID";; esac\ncat > /dev/null\n')
            (bin_dir / "psql").chmod(0o755)
            result = subprocess.run([sys.executable, "-s", selfcheck.__file__, "dump", "chronicle", str(last / "chronicle-1.sql.gz")],
                                    env=dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], PSQL_LOG=str(calls),
                                             PYTHONDONTWRITEBYTECODE="1"),
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual((1, ""), (result.returncode, result.stdout), result.stderr)
            self.assertIn("Restore self-check FAIL: self-check interrupted by signal 15", result.stderr)
            self.assertEqual(["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;",
                              f"DROP DATABASE IF EXISTS {selfcheck.SCRATCH} WITH (FORCE);"], calls.read_text().splitlines())
            self.assertEqual([], [path.name for path in last.iterdir() if not path.name.startswith(".")])


class SelfcheckPublicationTests(unittest.TestCase):
    def test_stamp_failure_keeps_an_existing_dump_at_the_same_name(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'last/chronicle-existing.sql.gz'
            destination.parent.mkdir()
            destination.write_bytes(gzip.compress(DUMP))
            selfcheck.publish_backup(destination, 'chronicle', SelfcheckTests.source)
            previous = destination.read_bytes()
            def snapshot(database, partial, options):
                partial.write_bytes(gzip.compress(DUMP))
                return SelfcheckTests.source
            with patch('selfcheck.dump_snapshot', side_effect=snapshot), patch('selfcheck.check_dump'), \
                 patch('selfcheck.drop_scratch'), patch('chronicle_ops.dump.stamp_installed_backup', side_effect=OSError('disk full')), \
                 patch('sys.stderr', io.StringIO()):
                self.assertEqual(1, selfcheck.main(['dump', 'chronicle', str(destination)]))
            self.assertTrue(destination.exists(), 'stamp failure deleted the previous published dump')
            self.assertEqual(previous, destination.read_bytes())
            self.assertEqual([], list(destination.parent.glob('*.partial')))

    def test_dump_is_stamped_before_its_public_name_becomes_visible(self):
        replace = os.replace
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'last/chronicle-killed.sql.gz'
            destination.parent.mkdir()
            def snapshot(database, partial, options):
                partial.write_bytes(gzip.compress(DUMP))
                return SelfcheckTests.source
            def killed_after_replace(source, target):
                replace(source, target)
                if Path(target) == destination:
                    raise SystemExit('killed after publication')
            with patch('selfcheck.dump_snapshot', side_effect=snapshot), patch('selfcheck.check_dump'), \
                 patch('selfcheck.drop_scratch'), patch('selfcheck.os.replace', side_effect=killed_after_replace):
                with self.assertRaises(SystemExit):
                    selfcheck.main(['dump', 'chronicle', str(destination)])
            with gzip.open(destination, 'rb') as dump:
                self.assertTrue(dump.readline().startswith(b'-- Chronicle release: '))

    def test_a_failed_second_producer_never_replaces_the_published_dump(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'last/chronicle-20261031-020000.sql.gz'
            destination.parent.mkdir()
            def snapshot(database, partial, options):
                partial.write_bytes(gzip.compress(DUMP))
                return SelfcheckTests.source
            with patch('selfcheck.dump_snapshot', side_effect=snapshot), patch('selfcheck.check_dump'), \
                 patch('selfcheck.drop_scratch'):
                self.assertEqual(0, selfcheck.main(['dump', 'chronicle', str(destination)]))
            first = destination.read_bytes()
            def truncated(database, partial, options):
                partial.write_bytes(gzip.compress(DUMP)[:20])
                return SelfcheckTests.source
            with patch('selfcheck.dump_snapshot', side_effect=truncated), patch('selfcheck.drop_scratch'), \
                 patch('selfcheck.check_dump', side_effect=RuntimeError('restore failed')), patch('sys.stderr', io.StringIO()):
                self.assertEqual(1, selfcheck.main(['dump', 'chronicle', str(destination)]))
            self.assertEqual(first, destination.read_bytes())
            self.assertEqual([], list(destination.parent.glob('*.partial')))


class BackupScriptTests(unittest.TestCase):
    """Runs the shipped backup.sh up to the dump step; a stub selfcheck.sh stands in for pg_dump."""

    def run_backup(self, folder, selfcheck_status=1, hooks=None, **overrides):
        image = Path(folder) / 'image'
        image.mkdir()
        for name in ('backup.sh', 'env.sh'):
            (image / name).write_bytes((Path(selfcheck.__file__).parent / name).read_bytes())
        # The image mounts hooks at /hooks; never run a host's /hooks. Without fixture hooks the directory is absent.
        script = (image / 'backup.sh').read_text()
        self.assertEqual(1, script.count('HOOKS_DIR="/hooks"'))
        (image / 'backup.sh').write_text(script.replace('HOOKS_DIR="/hooks"', f'HOOKS_DIR="{hooks or Path(folder) / "no-hooks"}"'))
        if hooks:
            # The image ships Debian run-parts (`-a ARG`); point it at the fixture.
            (image / 'run-parts').write_text('#!/usr/bin/env bash\nset -e\nwhile [[ $1 == -* ]]; do [[ $1 == -a ]] && { phase=$2; shift; }; shift; done\n'
                                             'for hook in "$1"/*; do "$hook" "$phase"; done\n')
            (image / 'run-parts').chmod(0o755)
            overrides['PATH'] = str(image) + os.pathsep + os.environ['PATH']
        (image / 'selfcheck.sh').write_text('echo "Restore self-check FAIL: fixture" >&2\nexit %d\n' % selfcheck_status)
        (image / 'selfcheck.sh').chmod(0o755)
        environment = dict(os.environ, BACKUP_DIR=str(self.backups), BACKUP_SUCCESS_MARKER=str(self.marker),
                           POSTGRES_DB='chronicle', POSTGRES_DB_FILE='**None**', POSTGRES_HOST='postgres', POSTGRES_PORT='5432',
                           POSTGRES_USER='chronicle', POSTGRES_USER_FILE='**None**', POSTGRES_PASSWORD='fixture',
                           POSTGRES_PASSWORD_FILE='**None**', POSTGRES_PASSFILE_STORE='**None**', BACKUP_KEEP_MINS='1440',
                           BACKUP_KEEP_DAYS='7', BACKUP_KEEP_WEEKS='4', BACKUP_KEEP_MONTHS='6', BACKUP_SUFFIX='.sql.gz',
                           POSTGRES_CLUSTER='FALSE', BACKUP_LATEST_TYPE='none', MIN_FREE_DISK_GIB='0', PYTHONDONTWRITEBYTECODE='1',
                           PYTHONPATH=str(Path(__file__).resolve().parents[2] / 'selfhost'))
        environment.update(overrides)
        return subprocess.run(['bash', str(image / 'backup.sh')], env=environment, capture_output=True, text=True, timeout=60)

    def published(self, folder):
        self.backups = Path(folder) / 'backups'
        (self.backups / 'daily').mkdir(parents=True)
        dump = self.backups / 'daily/chronicle-20261030.sql.gz'
        dump.write_bytes(gzip.compress(DUMP))
        self.marker = Path(folder) / 'backup-success'
        self.marker.write_text(str(dump) + '\n')
        with patch.dict(os.environ, BACKUP_SUCCESS_MARKER=str(self.marker)):
            self.assertEqual(0, selfcheck.main(['health']))

    def test_a_failed_backup_withdraws_the_earlier_success_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            self.published(folder)
            result = self.run_backup(folder)
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn('Restore self-check FAIL: fixture', result.stderr)
            self.assertFalse(self.marker.exists())
            with patch.dict(os.environ, BACKUP_SUCCESS_MARKER=str(self.marker)):
                self.assertEqual(1, selfcheck.main(['health']))

    def test_an_overlapping_run_steps_aside_successfully_without_touching_the_holders_state(self):
        import fcntl
        with tempfile.TemporaryDirectory() as folder:
            self.published(folder)
            with open(self.backups / '.backup.lock', 'a+') as holder:
                fcntl.flock(holder, fcntl.LOCK_EX)
                before = sorted(path.relative_to(self.backups) for path in self.backups.rglob('*'))
                result = self.run_backup(folder, selfcheck_status=0)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn('Backup skipped: another backup run is still publishing', result.stderr)
                self.assertEqual(before, sorted(path.relative_to(self.backups) for path in self.backups.rglob('*')))
                self.assertEqual(self.marker.read_text(), str(self.backups / 'daily/chronicle-20261030.sql.gz') + '\n')
                # The holder keeps its lock and finishes the slot.
                with open(self.backups / '.backup.lock') as probe, self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_expired_safety_dumps_are_reclaimed_even_when_the_backup_then_fails(self):
        import time
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as folder:
            self.published(folder)
            hooks = Path(folder) / 'hooks'
            hooks.mkdir()
            hook = hooks / '50-prune-pre-operation-dumps'  # the overlays/backups.yml mount name
            hook.write_bytes((root / 'selfhost/backup-prune-hook.sh').read_bytes())
            hook.chmod(0o755)
            expired = self.backups / 'pre-restore-20261001-000000.sql.gz'
            fresh = self.backups / 'pre-restore-20261030-000000.sql.gz'
            for path in (expired, fresh):
                path.write_bytes(gzip.compress(DUMP))
            old = time.time() - 3 * 24 * 60 * 60
            os.utime(expired, (old, old))
            result = self.run_backup(folder, hooks=hooks, PRE_OP_BACKUP_KEEP_DAYS='1', MIN_FREE_DISK_GIB='999999')
            self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn('under MIN_FREE_DISK_GIB', result.stderr)
            self.assertFalse(expired.exists())
            self.assertTrue(fresh.exists())
        # The backup runbook promises exactly this order to the operator.
        guide = ' '.join((root / 'selfhost/docs/BACKUP-RESTORE.md').read_text().split())
        self.assertIn('reclaims expired copies in its pre-backup hook, before free-space admission', guide)
        self.assertIn('A copy can therefore disappear even if that backup later fails.', guide)


class SelfcheckDatabaseTests(PgTdeFixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.load_application_fixture()
        cls.sql("CREATE TABLE public.battery_telemetry (sample_id text); "
                "INSERT INTO public.battery_telemetry VALUES ('battery-1'), ('battery-2'), ('battery-3'); "
                "INSERT INTO public.studies (study_id) VALUES ('00000000-0000-0000-0000-000000000001');")

    def test_a_dump_missing_battery_rows_is_rejected_without_publication(self):
        directory = self.work / 'missing-battery/last'
        directory.mkdir(parents=True)
        result = subprocess.run(['docker', 'exec', '--user', '0', '-e', 'PGHOST=127.0.0.1',
                                 '-e', 'PGUSER=' + self.database_user, self.container,
                                 'python3', '/selfhost/backup-image/selfcheck.py', 'dump', 'chronicle',
                                 self.container_path(directory / 'chronicle-missing.sql.gz'), '-Z1', '--no-owner',
                                 '--exclude-table-data=public.battery_telemetry'], capture_output=True, text=True, timeout=120)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('battery_telemetry row count mismatch', result.stderr)
        self.assertEqual([], list(directory.glob('*.sql.gz*')))
        self.assertFalse((directory / 'chronicle-verified.json').exists())

    def test_complete_dump_records_every_restored_tables_counts(self):
        directory = self.work / 'complete/last'
        directory.mkdir(parents=True)
        self.docker('exec', '--user', '0', '-e', 'PGHOST=127.0.0.1', '-e', 'PGUSER=' + self.database_user,
                    self.container, 'python3', '/selfhost/backup-image/selfcheck.py', 'dump', 'chronicle',
                    self.container_path(directory / 'chronicle-complete.sql.gz'), '-Z1', '--no-owner')
        marker = json.loads(self.docker('exec', '--user', '0', self.container, 'cat',
                                       self.container_path(directory / 'chronicle-verified.json')))
        self.assertEqual(3, marker['row_counts']['public.battery_telemetry'])
        self.assertEqual(1, marker['row_counts']['public.audit'])
        self.assertEqual(1, marker['row_counts']['public.studies'])
        self.assertEqual(self.public_table_count(), len(marker['row_counts']))

    def public_table_count(self):
        return int(self.sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p');"))
