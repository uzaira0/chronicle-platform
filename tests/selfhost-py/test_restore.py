import errno
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "selfhost"))
from chronicle_ops.common import application_services
from chronicle_ops.dump import EXIT_REJECTED_BEFORE_MUTATION, RESTORE_MUTATION_MARKER, safe_dump
from chronicle_ops.restore import EXIT_RESTORE_TRANSACTION_ROLLED_BACK, Interrupted, Restore, RestoreError, resolve_host_path


DUMP = (b"-- PostgreSQL database dump\n\\restrict fixture\nSET statement_timeout = 0;\n"
        b"\\unrestrict fixture\n-- PostgreSQL database dump complete\n")


class MemoryFiles:
    def __init__(self):
        self.dirs = {"/deployment", "/deployment/backups", "/deployment/backups/last"}
        self.files = {"/deployment/backups/last/chronicle-latest.sql.gz": gzip.compress(DUMP, mtime=0)}
        self.links = {}
        self.faults = {}
        self.history = []
        self.free = 1 << 40

    def fault(self, action, path):
        error = self.faults.get((action, str(path)))
        if error:
            raise error

    def mkdir(self, path, **kwargs):
        self.fault("mkdir", path)
        key = str(path)
        if self.exists(key):
            raise FileExistsError(key)
        self.dirs.add(key)
        self.history.append(("mkdir", key, kwargs.get("mode")))

    def publish(self, path, files):
        """publish_journal: the marker appears only together with its complete metadata."""
        self.fault("publish", path)
        key = str(path)
        if self.exists(key):
            raise FileExistsError(key)
        self.dirs.add(key)
        for name, content in files.items():
            self.files[key + "/" + name] = content.encode()
        self.history.append(("publish", key, dict(files)))

    def exists(self, path):
        key = str(path)
        return key in self.dirs or key in self.files or key in self.links

    def resolve(self, path, strict=False):
        self.fault("resolve", path)
        path = Path(self.links.get(str(path), str(path)))
        if strict and not self.exists(path):
            raise FileNotFoundError(str(path))
        return path

    def chmod(self, path, mode):
        self.fault("chmod", path)
        self.history.append(("chmod", str(path), mode))

    def write_text(self, path, value):
        self.fault("write", path)
        self.files[str(path)] = value.encode()
        self.history.append(("write", str(path), value))

    def replace(self, source, target):
        self.fault("replace", target)
        self.files[str(target)] = self.files.pop(str(source))
        self.history.append(("replace", str(target), self.files[str(target)]))

    def unlink(self, path, missing_ok=False):
        self.fault("unlink", path)
        self.files.pop(str(path), None)
        self.links.pop(str(path), None)

    def rmdir(self, path):
        self.fault("rmdir", path)
        if any(name.startswith(str(path) + "/") for name in self.files):
            raise OSError("not empty")
        self.dirs.remove(str(path))

    def private_copy(self, source, directory):
        self.fault("copy", source)
        target = Path(directory) / ".reviewed-restore.fixture.sql.gz"
        self.files[str(target)] = self.files[str(source)]
        return target

    def open_gzip(self, path, mode):
        self.fault("gzip", path)
        return gzip.GzipFile(fileobj=io.BytesIO(self.files[str(path)]), mode=mode)

    def statvfs(self, path):
        self.fault('statvfs', path)
        return SimpleNamespace(f_bavail=self.free, f_frsize=1)

    def stat(self, path):
        self.fault('stat', path)
        if str(path) in self.dirs:
            return SimpleNamespace(st_size=0)
        if str(path) not in self.files:
            raise FileNotFoundError(str(path))
        return SimpleNamespace(st_size=len(self.files[str(path)]))

    def patches(self):
        return [
            patch.object(Path, "mkdir", lambda path, **kw: self.mkdir(path, **kw)),
            patch.object(Path, "resolve", lambda path, strict=False: self.resolve(path, strict)),
            patch.object(Path, "exists", lambda path: self.exists(path)),
            patch.object(Path, "is_dir", lambda path: str(path) in self.dirs),
            patch.object(Path, "is_file", lambda path: str(path) in self.files),
            patch.object(Path, "is_symlink", lambda path: str(path) in self.links),
            patch.object(Path, "stat", lambda path: self.stat(path)),
            patch.object(Path, "chmod", lambda path, mode: self.chmod(path, mode)),
            patch.object(Path, "write_text", lambda path, value, **kw: self.write_text(path, value)),
            patch.object(Path, "unlink", lambda path, missing_ok=False: self.unlink(path, missing_ok)),
            patch.object(Path, "rmdir", lambda path: self.rmdir(path)),
            patch("chronicle_ops.restore.os.replace", self.replace),
            patch("chronicle_ops.restore.publish_journal", self.publish),
            patch("chronicle_ops.restore.os.path.lexists", self.exists),
            patch.object(Path, "open", lambda path, mode: io.BytesIO(self.files[str(path)])),
            patch("chronicle_ops.dump.gzip.open", self.open_gzip),
            patch("chronicle_ops.restore.private_copy", self.private_copy),
            patch("chronicle_ops.restore.os.statvfs", self.statvfs),
        ]


class FakeRunner:
    def __init__(self, fs):
        self.fs = fs
        self.calls = []
        self.fail_at = {}
        self.outputs = {}
        self.errors = {}  # call number -> what Compose wrote to stderr, for a caller that pipes it
        self.services = "postgres\nbackend\nweb\ndb-init\ndb-backup\nrestore"
        self.startup = "postgres\nbackend\nweb\ndb-init\ndb-backup\nca-export"
        self.before = "postgres\nbackend\nweb\ndb-backup"
        self.after = "postgres"
        self.ps_count = 0
        self.hook = None

    def compose(self, *args, capture=False, quiet=False, **options):  # check/env: the caller reads returncode.
        status, output = self(["dc", *args], capture=capture, quiet=quiet)
        errors = self.errors.get(len(self.calls)) if options.get("stderr") == subprocess.PIPE else None
        return SimpleNamespace(returncode=status, stdout=output, stderr=errors)

    def __call__(self, args, capture=False, quiet=False):
        self.calls.append((args, capture, quiet))
        number = len(self.calls)
        if self.hook:
            self.hook(number, args)
        if "run" in args and self.fail_at.get(number) != EXIT_REJECTED_BEFORE_MUTATION:
            self.fs.files["/deployment/backups/" + RESTORE_MUTATION_MARKER] = b"mutation started\n"
        if number in self.fail_at:
            failure = self.fail_at[number]
            if isinstance(failure, BaseException):
                raise failure
            return failure, ""
        if number in self.outputs:
            return 0, self.outputs[number]
        if args[:5] == ["dc", "--profile", "restore", "config", "--services"]:
            return 0, self.services
        if args[:5] == ["dc", "--profile", "restore", "ps", "--status"]:
            self.ps_count += 1
            return 0, self.before if self.ps_count == 1 else self.after
        if args == ["dc", "config", "--services"]:
            return 0, self.startup
        return 0, ""


class RestoreTests(unittest.TestCase):
    lock = "/deployment/.chronicle-restore.lock"
    dump_path = "/deployment/backups/last/chronicle-latest.sql.gz"

    def setUp(self):
        self.fs = MemoryFiles()
        self.runner = FakeRunner(self.fs)
        self.out, self.err = io.StringIO(), io.StringIO()
        for item in self.fs.patches() + [patch("sys.stdout", self.out), patch("sys.stderr", self.err),
                                       patch("chronicle_ops.restore.compose", self.runner.compose),
                                       patch("chronicle_ops.restore.acquire_operation_lock", return_value=None),
                                       patch("chronicle_ops.restore.release_operation_lock"),
                                       patch("chronicle_ops.restore.write_text", self.fs.write_text),
                                       patch("chronicle_ops.restore.finish_operation") ]:
            item.start()
            self.addCleanup(item.stop)
        self.operation = Restore("/deployment", "/deployment/backups", "", self.digest(), "17",
                                 False, True, False, "123")

    def digest(self):
        return hashlib.sha256(self.fs.files[self.dump_path]).hexdigest()

    def phases(self):
        return [(row[2]["phase"] if row[0] == "publish" else row[2].decode()).strip() for row in self.fs.history
                if row[:2] in (("publish", self.lock), ("replace", self.lock + "/phase"))]

    def args(self):
        return [row[0] for row in self.runner.calls]

    def recovery(self):
        return [args for args in self.args() if "--no-deps" in args and args[1] == "up"]

    def test_success_order_permissions_and_profile(self):
        self.assertEqual(self.operation.execute(), 0)
        self.assertEqual(self.phases(), ["prepared", "stopping-services", "restoring",
                                        "database-restored", "starting-services", "verified"])
        self.assertNotIn(self.lock, self.fs.dirs)
        self.assertEqual(self.args()[2], ["dc", "stop", *application_services(self.runner.services.splitlines())])
        self.assertEqual(self.args()[4], ["dc", "--profile", "restore", "run", "--rm", "-e",
                                         "CHRONICLE_RESTORE_ORCHESTRATED=true", "-e",
                                         "CHRONICLE_RESTORE_TRUSTED_SHA256=" + self.digest(),
                                         "-e", "RESTORE_FILE=/backups/.reviewed-restore.fixture.sql.gz", "restore"])
        self.assertEqual(self.args()[6], ["dc", "up", "-d", "--wait", "--wait-timeout", "17",
                                         "--remove-orphans", "--force-recreate", "postgres", "backend", "web", "db-init", "db-backup"])
        self.assertEqual(self.args()[7], ["dc", "run", "--rm", "--no-deps", "ca-export"])
        self.assertEqual(self.recovery(), [])
        self.assertIn(("publish", self.lock, {"owner-pid": "123\n", "restore-file": "/backups/last/chronicle-latest.sql.gz\n",
                                               "phase": "prepared\n"}), self.fs.history)
        self.assertIn(("chmod", self.lock + "/.phase.123", 0o600), self.fs.history)

    def test_a_bundle_install_tells_the_restore_container_its_release(self):
        # restore.sh refuses a dump from a newer release; in a bundle it learns the installed one from the manifest.
        self.fs.files["/bundle/release-manifest.json"] = json.dumps({"release_version": "2026.10.31"}).encode()
        # Every post-reset producer stamps its release first.
        self.fs.files[self.dump_path] = gzip.compress(b"-- Chronicle release: 2026.10.31\n", mtime=0) + gzip.compress(DUMP, mtime=0)
        self.operation.digest = self.digest()
        read_text = Path.read_text
        with patch.object(Path, "cwd", return_value=Path("/bundle/selfhost")), \
             patch.object(Path, "read_text", lambda path, **kw: self.fs.files[str(path)].decode()
                          if str(path) in self.fs.files else read_text(path, **kw)):
            self.assertEqual(self.operation.execute(), 0, self.err.getvalue())
        self.assertEqual(self.args()[4], ["dc", "--profile", "restore", "run", "--rm", "-e",
                                         "CHRONICLE_RESTORE_ORCHESTRATED=true", "-e", "RELEASE_VERSION=2026.10.31", "-e",
                                         "CHRONICLE_RESTORE_TRUSTED_SHA256=" + self.digest(),
                                         "-e", "RESTORE_FILE=/backups/.reviewed-restore.fixture.sql.gz", "restore"])

    def test_no_start(self):
        self.operation.no_start = True
        self.assertEqual(self.operation.execute(), 0)
        # Same-release --no-start runs the ordinary restore; only Rollback asks for the rollback continuity proof.
        self.assertEqual(self.args()[4], ["dc", "--profile", "restore", "run", "--rm", "-e",
                                         "CHRONICLE_RESTORE_ORCHESTRATED=true", "-e",
                                         "CHRONICLE_RESTORE_TRUSTED_SHA256=" + self.digest(),
                                         "-e", "RESTORE_FILE=/backups/.reviewed-restore.fixture.sql.gz", "restore"])
        self.assertFalse(any(args[:2] == ["dc", "up"] for args in self.args()))
        self.assertIn("/deployment/.chronicle-stopped", self.fs.files)
        self.assertEqual(self.phases()[-1], "database-restored")
        self.assertIn("application services remain stopped because --no-start", self.out.getvalue())

    def test_rollback_continuity_rejection_preserves_destructive_phase(self):
        self.operation.no_start = self.operation.rollback = True
        self.runner.fail_at[5] = 45
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("CHRONICLE_RESTORE_ROLLBACK=true", self.args()[4])
        self.assertEqual(self.fs.files[self.lock + "/phase"], b"restoring\n")
        self.assertEqual(self.recovery(), [])
        self.assertFalse(any(args[:2] == ["dc", "up"] for args in self.args()))

    def test_rollback_transaction_refusal_resumes_current_services_and_releases_lock(self):
        self.operation.no_start = True
        self.runner.fail_at[5] = EXIT_RESTORE_TRANSACTION_ROLLED_BACK
        self.assertEqual(self.operation.execute(), 1)
        self.assertEqual(self.recovery(), [["dc", "up", "-d", "--wait", "--wait-timeout", "17",
                                           "--no-deps", "backend", "web", "db-backup"]])
        self.assertNotIn(self.lock, self.fs.dirs)
        self.assertIn("live database was preserved", self.err.getvalue())

    def test_optional_services(self):
        self.runner.services = "postgres\nbackend\nweb\nrestore"
        self.runner.startup = "postgres\nbackend\n\nweb"
        self.assertEqual(self.operation.execute(), 0)
        self.assertEqual(self.args()[2], ["dc", "stop", *application_services(self.runner.services.splitlines())])
        self.assertFalse(any(args[-1] == "ca-export" for args in self.args()))

    def test_each_command_failure_and_exact_recovery(self):
        messages = ["configuration is invalid",
                    "inspect running", "stop every", "verify that", "deliberately left stopped",
                    "post-restore Compose", "did not return healthy", "could not publish its local CA"]
        for step in range(1, 9):
            with self.subTest(step=step):
                self.setUp()
                self.runner.fail_at[step] = 42
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn(messages[step - 1], self.err.getvalue())
                if step in (3, 4):
                    self.assertEqual(self.recovery(), [["dc", "up", "-d", "--wait", "--wait-timeout", "17",
                                                       "--no-deps", "backend", "web", "db-backup"]])
                else:
                    self.assertEqual(self.recovery(), [])
                self.assertEqual(self.lock in self.fs.dirs, step >= 5)
                if step >= 5:
                    phase = "restoring" if step == 5 else "starting-services"
                    self.assertEqual(self.fs.files[self.lock + "/phase"], (phase + "\n").encode())
                stops = [args for args in self.args() if args[:2] == ["dc", "stop"]]
                self.assertEqual(len(stops), 2 if step >= 7 else 1 if step >= 3 else 0)
                if step >= 7:
                    self.assertEqual(self.runner.calls[-1], (stops[-1], False, True))
                self.doCleanups()

    def test_exit_46_releases_lock_and_recovers_previous_services(self):
        self.runner.fail_at[5] = EXIT_REJECTED_BEFORE_MUTATION
        self.assertEqual(self.operation.execute(), 1)
        self.assertEqual(self.recovery(), [["dc", "up", "-d", "--wait", "--wait-timeout", "17",
                                           "--no-deps", "backend", "web", "db-backup"]])
        self.assertNotIn(self.lock, self.fs.dirs)
        self.assertIn("failed before database mutation", self.err.getvalue())

    def test_recovery_restart_failure_still_releases_lock(self):
        self.runner.fail_at = {3: 42, 4: 43}
        self.assertEqual(self.operation.execute(), 1)
        self.assertNotIn(self.lock, self.fs.dirs)
        self.assertIn("could not all be restarted", self.err.getvalue())
        self.assertIn("Diagnose Docker Compose, then run ./chronicle up.", self.err.getvalue())

    def test_no_previously_running_services(self):
        self.runner.before = "postgres"
        self.runner.fail_at[3] = 42
        self.assertEqual(self.operation.execute(), 1)
        self.assertEqual(self.recovery(), [])
        self.assertNotIn(self.lock, self.fs.dirs)

    def test_startup_and_ca_failure_stop_warning(self):
        """The stop that follows a failed start says why it failed too: Compose's own error line
        when it wrote one, else its exit status. Its output was discarded."""
        daemon = " Container fixture-backend-1 Stopping \nCannot connect to the Docker daemon at unix:///var/run/docker.sock\n"
        for step, message in ((7, "startup failure"), (8, "CA export failure")):
            for errors, cause in ((None, "docker compose stop exited with status 43"),
                                  (daemon, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock")):
                with self.subTest(step=step, cause=cause):
                    self.setUp()
                    self.runner.fail_at = {step: 42, step + 1: 43}
                    self.runner.errors = {step + 1: errors}
                    self.assertEqual(self.operation.execute(), 1)
                    self.assertIn("could not confirm every application service stopped after " + message + ": " + cause + "\n",
                                  self.err.getvalue())
                    self.assertNotIn("Stopping", self.err.getvalue())
                    self.assertIn(self.lock, self.fs.dirs)
                    self.doCleanups()

    def test_running_service_rejection(self):
        for running, message, recovery in (("postgres\nrestore", "already running", False),
                                          ("postgres\nbackend", "still running", True),
                                          ("postgres\nrestore", "different one-shot", True)):
            with self.subTest(message=message):
                self.setUp()
                if recovery:
                    self.runner.after = running
                else:
                    self.runner.before = running
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn(message, self.err.getvalue())
                self.assertEqual(bool(self.recovery()), recovery)
                self.assertFalse(any(args[-1] == "restore" and "run" in args for args in self.args()))
                self.assertNotIn(self.lock, self.fs.dirs)
                self.doCleanups()

    def test_required_services(self):
        for missing in ("postgres", "backend", "web", "restore"):
            with self.subTest(missing=missing):
                self.runner.services = "\n".join(name for name in ("postgres", "backend", "web", "restore")
                                                 if name != missing)
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn("missing required service: " + missing, self.err.getvalue())
                self.assertNotIn(self.lock, self.fs.dirs)

    def test_empty_startup_list(self):
        self.runner.startup = "ca-export\n"
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("no long-running services", self.err.getvalue())
        self.assertIn(self.lock, self.fs.dirs)

    def test_service_names_preserve_literal_line_endings(self):
        self.runner.services = "postgres\r\nbackend\nweb\nrestore"
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("missing required service: postgres", self.err.getvalue())
        self.assertNotIn(self.lock, self.fs.dirs)

    def test_timeout_validation(self):
        for value, message in (("0", "positive integer"), ("01", "positive integer"),
                               ("-1", "positive integer"), ("x", "positive integer"),
                               ("nan", "positive integer"), ("inf", "positive integer")):
            with self.subTest(value=value):
                self.operation.timeout = value
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn(message, self.err.getvalue())
                self.assertEqual(self.args(), [])

    def test_operator_can_extend_the_startup_deadline(self):
        for timeout in ("3600", "7200", "18446744073709551616"):
            with self.subTest(timeout=timeout):
                self.setUp()
                self.operation.timeout = timeout
                self.assertEqual(self.operation.execute(), 0, self.err.getvalue())
                startup = [args for args in self.args() if '--wait-timeout' in args]
                self.assertIn(timeout, startup[-1])
                self.doCleanups()

    def test_missing_state_root(self):
        self.fs.dirs.remove("/deployment")
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("CHRONICLE_STATE_DIR does not exist: /deployment", self.err.getvalue())

    def test_control_character_path(self):
        self.operation.container_path = "/backups/bad\n.sql.gz"
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("must not contain control characters", self.err.getvalue())

    def test_missing_or_empty_dump(self):
        self.operation.container_path = "/backups/no.sql.gz"
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("dump is unavailable or unsafe", self.err.getvalue())
        self.operation.container_path = "/backups/last/chronicle-latest.sql.gz"
        self.fs.files[self.dump_path] = b""
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("restore dump is empty", self.err.getvalue())

    def test_confirmation(self):
        self.operation.assume_yes = False
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("confirmation requires a terminal", self.err.getvalue())
        self.operation.terminal = True
        with patch("builtins.input", return_value="n"):
            self.assertEqual(self.operation.execute(), 1)
        self.assertIn("restore cancelled", self.err.getvalue())

    def test_confirmation_acceptance(self):
        self.operation.assume_yes = False
        self.operation.terminal = True
        with patch("builtins.input", return_value="Y") as confirm:
            self.assertEqual(self.operation.execute(), 0)
        confirm.assert_called_once_with("Stop Chronicle and replace its database with this dump? [y/N] ")

    def test_a_dump_changed_during_confirmation_is_refused_before_any_service_stops(self):
        replaced = gzip.compress(DUMP.replace(b"statement_timeout = 0", b"statement_timeout = 1"), mtime=0)
        newer = "/deployment/backups/daily/chronicle-newer.sql.gz"

        def overwrite():
            self.fs.files[self.dump_path] = replaced

        def repoint_alias():
            self.fs.dirs.add("/deployment/backups/daily")
            self.fs.files[newer] = replaced
            self.fs.links[self.dump_path] = newer

        def remove():  # retention or the operator removed the dump while the prompt waited
            del self.fs.files[self.dump_path]

        for change, message in ((overwrite, "digest mismatch"), (repoint_alias, "digest mismatch"),
                                (remove, "restore dump is unavailable or unsafe: /backups/last/chronicle-latest.sql.gz")):
            with self.subTest(change=change.__name__):
                self.setUp()
                def change_while_confirming(question):
                    change()
                    return "y"
                self.operation.assume_yes, self.operation.terminal = False, True
                with patch("builtins.input", change_while_confirming):
                    self.assertEqual(self.operation.execute(), 1)
                self.assertIn(message, self.err.getvalue())
                self.assertFalse([args for args in self.args() if "stop" in args or "run" in args or "up" in args])
                self.assertNotIn(self.lock, self.fs.dirs)
                self.assertFalse([name for name in self.fs.files if ".reviewed-restore." in name])
                self.doCleanups()

    def test_an_unresolved_mutation_marker_refuses_a_new_restore_before_any_service_stops(self):
        # A killed restore left restore.sh's marker; its lock was removed by hand.
        self.fs.files["/deployment/backups/" + RESTORE_MUTATION_MARKER] = b"mutation started\n"
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("an unresolved restore mutation marker exists; follow the restore recovery runbook", self.err.getvalue())
        self.assertEqual([], [args for args in self.args() if "stop" in args or "run" in args or "up" in args])
        self.assertIn("/deployment/backups/" + RESTORE_MUTATION_MARKER, self.fs.files)

    def test_restore_receives_the_pinned_copy_of_the_confirmed_dump(self):
        reviewed = self.fs.files[self.dump_path]
        received = {}
        def capture(number, args):
            if "run" in args and args[-1] == "restore":
                pinned = next(arg for arg in args if arg.startswith("RESTORE_FILE=")).split("=", 1)[1]
                received["path"] = pinned
                received["bytes"] = self.fs.files["/deployment" + pinned]
                self.fs.files[self.dump_path] = b"replaced after the pin"
        self.runner.hook = capture
        self.assertEqual(self.operation.execute(), 0)
        self.assertRegex(received["path"], r"^/backups/\.reviewed-restore\.[^/]+\.sql\.gz$")
        self.assertEqual(reviewed, received["bytes"])
        self.assertFalse([name for name in self.fs.files if ".reviewed-restore." in name])

    def test_pin_without_room_for_the_dump_names_the_size_before_any_service_stops(self):
        size = len(self.fs.files[self.dump_path])
        for case, free, failure in (('measured short', size - 1, None),
                                    ('filled during the copy', size, OSError(errno.ENOSPC, 'No space left on device'))):
            with self.subTest(case=case):
                self.setUp()
                self.fs.free = free
                if failure:
                    self.fs.faults[("copy", self.dump_path)] = failure
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn("pinning the confirmed dump needs {} bytes free in /deployment/backups".format(size),
                              self.err.getvalue())
                self.assertNotIn("Errno", self.err.getvalue())
                self.assertFalse([args for args in self.args() if "stop" in args or "run" in args])
                self.assertNotIn(self.lock, self.fs.dirs)
                self.doCleanups()

    def test_pin_checks_available_bytes_on_the_copy_destination(self):
        size = len(self.fs.files[self.dump_path])
        for available, succeeds in ((size - 1, False), (size, True)):
            with self.subTest(available=available):
                self.setUp()
                def disk(path):
                    # The deployment root can have room while backups/ is a separate full mount.
                    return SimpleNamespace(f_bavail=1 if path == self.operation.backups else 1 << 40,
                                           f_frsize=available)
                with patch('chronicle_ops.restore.os.statvfs', side_effect=disk):
                    self.assertEqual(0 if succeeds else 1, self.operation.execute())
                self.assertEqual(succeeds, any('stop' in args for args in self.args()))
                self.assertFalse([name for name in self.fs.files if '.reviewed-restore.' in name])
                self.doCleanups()

    def test_copy_is_trusted_under_the_restore_lock_before_services_stop(self):
        trust = self.operation.trust_dump
        paths = []
        def check(path):
            paths.append(path)
            if len(paths) == 2:
                self.assertIn(self.lock, self.fs.dirs)
                self.assertEqual(self.phases(), ['prepared'])
                self.assertNotEqual(Path(self.dump_path), path)
                self.assertEqual(self.operation.pinned, path)
                self.assertFalse(any('stop' in args for args in self.args()))
            trust(path)
        with patch.object(self.operation, 'trust_dump', check):
            self.assertEqual(0, self.operation.execute())
        self.assertEqual(2, len(paths))

    def test_pinned_copy_is_removed_on_failure_interrupt_and_cleanup_interrupt(self):
        for failure in (RestoreError('fixture'), KeyboardInterrupt()):
            for during_cleanup in (False, True):
                with self.subTest(failure=type(failure).__name__, during_cleanup=during_cleanup):
                    self.setUp()
                    self.runner.fail_at[5] = failure
                    with patch.object(self.operation, 'cleanup', side_effect=KeyboardInterrupt()) if during_cleanup else patch.object(
                            self.operation, 'cleanup', wraps=self.operation.cleanup):
                        if during_cleanup or isinstance(failure, KeyboardInterrupt):
                            with self.assertRaises(KeyboardInterrupt):
                                self.operation.execute()
                        else:
                            self.assertEqual(1, self.operation.execute())
                    self.assertFalse([name for name in self.fs.files if '.reviewed-restore.' in name])
                    self.doCleanups()

    def test_interlocks_and_dangling_symlinks(self):
        for name, operation in ((".chronicle-upgrade.lock", "upgrade"),
                                (".chronicle-secret-rotation", "secret rotation")):
            with self.subTest(name=name):
                self.fs.links["/deployment/" + name] = "/missing"
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn(operation + " is active or incomplete", self.err.getvalue())
                self.assertNotIn(self.lock, self.fs.dirs)
                self.fs.links.clear()

    def test_post_acquisition_interlocks(self):
        for name in (".chronicle-upgrade.lock", ".chronicle-secret-rotation"):
            with self.subTest(name=name):
                self.setUp()
                original = self.fs.publish
                def raced(path, files):
                    original(path, files)
                    self.fs.dirs.add("/deployment/" + name)
                with patch("chronicle_ops.restore.publish_journal", raced):
                    self.assertEqual(self.operation.execute(), 1)
                self.assertIn("started while the restore lock was being acquired", self.err.getvalue())
                self.assertNotIn(self.lock, self.fs.dirs)
                self.assertEqual(self.recovery(), [])
                self.doCleanups()

    def test_adoption_rollback_owner_can_restore_through_the_preserved_upgrade_lock(self):
        from chronicle_ops.reconcile import RECOVERY_FILE, RECOVERY_PHASE
        marker = '/deployment/.chronicle-upgrade.lock'
        self.fs.dirs.add(marker)
        self.fs.files[marker + '/' + RECOVERY_FILE] = json.dumps({
            'owner': '/new/selfhost', 'phase': RECOVERY_PHASE}).encode()
        self.operation.recovery_owner = '/new/selfhost'
        self.operation.no_start = self.operation.rollback = True
        with patch.object(Path, 'read_text', lambda path: self.fs.files[str(path)].decode()):
            self.assertEqual(self.operation.execute(), 0)
        self.assertIn('CHRONICLE_RESTORE_ROLLBACK=true', self.args()[4])

    def test_existing_restore_lock(self):
        self.fs.dirs.add(self.lock)
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("another restore is active or incomplete", self.err.getvalue())
        self.assertIn(self.lock, self.fs.dirs)

    def test_missing_mutation_store_is_not_treated_as_a_pre_mutation_failure(self):
        self.fs.dirs.discard(str(self.operation.backups))
        with self.assertRaises(FileNotFoundError):
            self.operation.mutation_started()

    def test_lock_creation_filesystem_failure_does_not_claim_an_existing_restore(self):
        import errno
        for error in (PermissionError(errno.EACCES, 'Permission denied'), OSError(errno.ENOSPC, 'No space left on device')):
            with self.subTest(error=error):
                self.setUp()
                self.fs.faults[('publish', self.lock)] = error
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn('Could not create the operation lock: ' + str(error), self.err.getvalue())
                self.assertIn('Check state-directory permissions and free space.', self.err.getvalue())
                self.assertNotIn('another restore is active', self.err.getvalue())
                self.assertNotIn(self.lock, self.fs.dirs)
                self.assertFalse(any(args[:2] == ['dc', 'stop'] for args in self.args()))
                self.doCleanups()

    def test_metadata_failures(self):
        for action, path, message in (("write", self.lock + "/.phase.123", "write restore operation metadata"),
                                     ("chmod", self.lock + "/.phase.123", "protect restore operation metadata"),
                                     ("replace", self.lock + "/phase", "publish restore operation metadata")):
            with self.subTest(action=action):
                self.setUp()
                self.fs.faults[(action, path)] = OSError("fixture")
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn(message, self.err.getvalue())
                self.assertNotIn(self.lock, self.fs.dirs)
                self.assertEqual(self.recovery(), [])
                self.doCleanups()

    def test_each_phase_write_failure(self):
        for phase in ("stopping-services", "restoring", "database-restored", "starting-services", "verified"):
            with self.subTest(phase=phase):
                self.setUp()
                original = self.operation.write_lock
                def failing(name, value):
                    if name == "phase" and value == phase:
                        raise RestoreError("could not write restore operation metadata")
                    original(name, value)
                with patch.object(self.operation, "write_lock", failing):
                    self.assertEqual(self.operation.execute(), 1)
                self.assertEqual(self.lock in self.fs.dirs, phase != "stopping-services")
                self.assertEqual(self.recovery(), [])
                self.doCleanups()

    def test_lock_release_failure_after_success_preserves_lock(self):
        self.fs.faults[("rmdir", self.lock)] = OSError("fixture")
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn(self.lock, self.fs.dirs)
        self.assertIn("operation lock could not be released", self.err.getvalue())
        self.assertIn("do not start Chronicle", self.err.getvalue())

    def test_lock_release_failure_before_mutation_warns(self):
        self.fs.faults[("rmdir", self.lock)] = OSError("fixture")
        self.runner.fail_at[3] = 42
        self.assertEqual(self.operation.execute(), 1)
        self.assertIn("could not release restore lock", self.err.getvalue())

    def test_release_missing_symlink_and_unlink_failure(self):
        self.assertTrue(self.operation.release())
        self.operation.held = True
        self.assertFalse(self.operation.release())
        self.fs.dirs.add(self.lock)
        self.fs.links[self.lock] = "/missing"
        self.assertFalse(self.operation.release())
        self.fs.links.clear()
        self.fs.files[self.lock + "/phase"] = b"prepared\n"
        self.fs.faults[("unlink", self.lock + "/phase")] = OSError("fixture")
        self.assertFalse(self.operation.release())

    def test_invalid_metadata_field(self):
        with self.assertRaisesRegex(RestoreError, "invalid restore lock field"):
            self.operation.write_lock("../bad", "value")

    def test_trust_digest_and_safe_framing(self):
        for content, digest, message in ((DUMP, "", "64-character"),
                                         (DUMP, "A" * 64, "digest mismatch"),
                                         (DUMP, "0" * 64, "digest mismatch"),
                                         (b"SELECT 1;\n", None, "safe pg_dump restricted framing")):
            with self.subTest(message=message):
                self.fs.files[self.dump_path] = gzip.compress(content)
                self.operation.digest = self.digest() if digest is None else digest
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn(message, self.err.getvalue())
                self.assertNotIn(self.lock, self.fs.dirs)

    def test_release_header_is_checked_before_any_service_or_database_change(self):
        from chronicle_ops.dump import backup_release_header
        from chronicle_ops.release import FRESH_INSTALL_REQUIRED, UPGRADE_FROM_MINIMUM
        self.operation.target_version = "2026.10.30"
        for header, message in ((b"", FRESH_INSTALL_REQUIRED),
                                (backup_release_header("2026.10.9"), FRESH_INSTALL_REQUIRED),
                                (backup_release_header("2026.11.1"), "newer release")):
            with self.subTest(header=header):
                self.err.seek(0)
                self.err.truncate()
                self.fs.files[self.dump_path] = (gzip.compress(header, mtime=0) if header else b"") + gzip.compress(DUMP, mtime=0)
                self.operation.digest = self.digest()
                self.assertEqual(self.operation.execute(), 1)
                self.assertIn(message, self.err.getvalue())
                self.assertEqual(self.args(), [])
                self.assertNotIn(self.lock, self.fs.dirs)
                self.assertNotIn("/deployment/backups/" + RESTORE_MUTATION_MARKER, self.fs.files)
        self.fs.files[self.dump_path] = gzip.compress(backup_release_header(UPGRADE_FROM_MINIMUM), mtime=0) + gzip.compress(DUMP, mtime=0)
        self.operation.digest = self.digest()
        self.assertEqual(self.operation.execute(), 0)
        self.assertIn(["dc", "stop", *application_services(self.runner.services.splitlines())], self.args())

    def test_mutated_archive_metadata_is_refused_before_any_service_or_database_change(self):
        from chronicle_ops.dump import BACKUP_RELEASE_PREFIX
        self.operation.target_version = "2026.10.30"
        corpus = [b"", b"not-gzip", gzip.compress(b"not a dump")] + [
            gzip.compress(BACKUP_RELEASE_PREFIX + value + b"\n", mtime=0) + gzip.compress(DUMP, mtime=0)
            for value in (b"", b"\0", b"\xff", b"2026.11.1", b"2026.10.9", b"-1", b"9" * 10_000,
                          b"2026.10.30\0", b"[2026,10,30]", b"2026.10.30/../../other")
        ]
        for index, archive in enumerate(corpus):
            with self.subTest(case=index):
                self.fs.files[self.dump_path] = archive
                self.operation.digest = self.digest()
                self.assertEqual(1, self.operation.execute())
                self.assertEqual([], self.args())
                self.assertNotIn(self.lock, self.fs.dirs)
                self.assertNotIn("/deployment/backups/" + RESTORE_MUTATION_MARKER, self.fs.files)

    def test_decompression_failure_is_rejected_before_stopping(self):
        self.fs.faults[("gzip", self.dump_path)] = EOFError()
        with self.assertRaisesRegex(RestoreError, "trust verification failed"):
            self.operation.trust_dump(Path(self.dump_path))
        self.assertEqual(self.args(), [])

    def test_signal_recovery_before_and_after_mutation(self):
        for step, signum, preserved in ((3, signal.SIGHUP, False), (5, signal.SIGTERM, True)):
            with self.subTest(step=step):
                self.setUp()
                self.runner.fail_at[step] = Interrupted(signum)
                self.assertEqual(self.operation.execute(), 128 + signum)
                self.assertEqual(self.lock in self.fs.dirs, preserved)
                self.assertEqual(bool(self.recovery()), not preserved)
                self.doCleanups()


class RollbackRestoreTests(unittest.TestCase):
    def test_rollback_restore_alone_requests_the_continuity_proof_and_stays_stopped(self):
        import tempfile
        from chronicle_ops.restore import Rollback
        built = []
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            rollback = Rollback.__new__(Rollback)
            rollback.state, rollback.assume_yes, rollback.current, rollback.previous = state, True, state, state / 'old'
            rollback.record = dict(dump='/backups/reviewed.sql.gz', sha256='a' * 64)
            with patch.object(Restore, 'execute', autospec=True, side_effect=lambda operation: built.append(operation) or 0):
                rollback.restore_database()
        (operation,) = built
        self.assertTrue(operation.rollback)
        self.assertTrue(operation.no_start)
        self.assertFalse(Restore(folder, folder, '', 'a' * 64, '17', True, True).rollback)


class PinnedCopyTests(unittest.TestCase):
    def test_private_copy_is_owner_only_byte_identical_and_named_for_pruning(self):
        import tempfile
        from chronicle_ops.restore import private_copy
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'reviewed.sql.gz'
            source.write_bytes(gzip.compress(DUMP))
            with patch('chronicle_ops.restore.os.fsync', wraps=os.fsync) as fsync:
                copy = private_copy(source, folder)
            fsync.assert_called_once()
            self.assertEqual(source.read_bytes(), copy.read_bytes())
            self.assertEqual(0o600, copy.stat().st_mode & 0o777)
            # backup-prune-hook.sh expires leftovers under this name after an interrupted restore.
            self.assertRegex(copy.name, r'^\.reviewed-restore\..+\.sql\.gz$')

    def test_partial_copy_is_removed_on_io_failure_and_keyboard_interrupt(self):
        import tempfile
        from chronicle_ops.restore import private_copy
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'reviewed.sql.gz'
            source.write_bytes(gzip.compress(DUMP))
            for failure in (OSError('fixture'), KeyboardInterrupt()):
                with self.subTest(failure=type(failure).__name__), patch(
                        'chronicle_ops.restore.shutil.copyfileobj', side_effect=failure):
                    with self.assertRaises(type(failure)):
                        private_copy(source, folder)
                    self.assertEqual([source], list(Path(folder).iterdir()))


class RestoreAccountTests(unittest.TestCase):
    def test_restore_container_runs_as_the_operator_who_owns_the_private_backups(self):
        import yaml
        selfhost = Path(__file__).resolve().parents[2] / "selfhost"
        launcher = subprocess.run(["bash", "-c", 'source "$1"; printf "%s:%s" "$CHRONICLE_HOST_UID" "$CHRONICLE_HOST_GID"',
                                   "bash", str(selfhost / "chronicle")], capture_output=True, text=True, check=True)
        self.assertEqual(launcher.stdout, "{}:{}".format(os.getuid(), os.getgid()))
        restore = yaml.safe_load((selfhost / "docker-compose.yml").read_text())["services"]["restore"]
        writer = yaml.safe_load((selfhost / "overlays/backups.yml").read_text())["services"]["db-backup"]
        # db-backup writes ./backups 0700 as this account; the restore reads it and writes the safety dump there.
        self.assertEqual(restore["user"], writer["user"])
        self.assertRegex(restore["user"], r"^\$\{CHRONICLE_HOST_UID[:}][^:]*:\$\{CHRONICLE_HOST_GID[:}]")


class PathTests(unittest.TestCase):
    def setUp(self):
        self.fs = MemoryFiles()
        for item in self.fs.patches():
            item.start()
            self.addCleanup(item.stop)

    def test_reject_path_branches(self):
        cases = (("/elsewhere/a.sql.gz", "below /backups"), ("/backups", "below /backups"),
                 ("/backups/../a.sql.gz", "unsafe component"), ("/backups/a.sql", "end in .sql.gz"),
                 ("/backups/a.sql.gz", "cannot resolve"))
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(RestoreError, message):
                    resolve_host_path("/deployment/backups", value)

    def test_resolved_escape_control_directory_and_runtime_error(self):
        path = "/deployment/backups/last/chronicle-latest.sql.gz"
        for target, message in (("/outside.sql.gz", "outside the backups directory"),
                                ("/deployment/backups/bad\n.sql.gz", "control character"),
                                ("/deployment/backups/last", "not a regular file")):
            with self.subTest(target=target):
                if target not in self.fs.dirs:
                    self.fs.files[target] = b"fixture"
                self.fs.links[path] = target
                with self.assertRaisesRegex(RestoreError, message):
                    resolve_host_path("/deployment/backups", "/backups/last/chronicle-latest.sql.gz")
        self.fs.faults[("resolve", path)] = RuntimeError("symlink loop")
        with self.assertRaisesRegex(RestoreError, "cannot resolve restore path: symlink loop"):
            resolve_host_path("/deployment/backups", "/backups/last/chronicle-latest.sql.gz")


class DumpTests(unittest.TestCase):
    def test_validator_cli_returns_the_recovery_contract_on_rejected_input(self):
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                           PYTHONPATH=str(Path(__file__).resolve().parents[2] / "selfhost"))
        result = subprocess.run([sys.executable, "-m", "chronicle_ops.dump", "/missing-restore-fixture.sql.gz"],
                                env=environment, capture_output=True)
        self.assertEqual(result.returncode, EXIT_REJECTED_BEFORE_MUTATION)

    def test_restore_and_rotation_scripts_get_the_dump_policy_and_validation_from_one_cli(self):
        # restore.sh and rotate-secret.sh call `python3 -m chronicle_ops.dump`; only the exit code and output reach them.
        import tempfile
        from chronicle_ops import dump
        selfhost = Path(__file__).resolve().parents[2] / "selfhost"
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(selfhost))
        environment.pop("RELEASE_VERSION", None)
        def cli(*args):
            result = subprocess.run([sys.executable, "-s", "-m", "chronicle_ops.dump", *args], env=environment,
                                    capture_output=True, text=True, timeout=30)
            return result.returncode, result.stdout, result.stderr
        with tempfile.TemporaryDirectory() as folder:
            good, truncated = Path(folder) / "good.sql.gz", Path(folder) / "truncated.sql.gz"
            good.write_bytes(gzip.compress(DUMP))
            truncated.write_bytes(gzip.compress(DUMP)[:-6])
            digest = hashlib.sha256(good.read_bytes()).hexdigest()
            self.assertEqual((0, "\n".join(dump.DUMP_EXCLUDE_OPTIONS) + "\n", ""), cli("--dump-excludes"))
            self.assertEqual((0, dump.RESTORE_EXTENSIONS_SQL + "\n", ""), cli("--restore-extensions"))
            self.assertEqual((0, "", ""), cli(str(good), digest))
            self.assertEqual((EXIT_REJECTED_BEFORE_MUTATION, "", "FAIL restore provenance digest mismatch\n"), cli(str(good), "0" * 64))
            self.assertEqual((EXIT_REJECTED_BEFORE_MUTATION, "", "FAIL restore failed gzip integrity verification (truncated or corrupt)\n"),
                             cli(str(truncated)))
            self.assertEqual((0, "", ""), cli("--stamp", "2026.10.31", str(good)))
            with gzip.open(good, "rb") as stream:
                self.assertEqual(b"-- Chronicle release: 2026.10.31\n", stream.readline())
            missing = cli("--stamp-installed", str(Path(folder) / "missing.sql.gz"), str(selfhost))
            self.assertEqual((EXIT_REJECTED_BEFORE_MUTATION, ""), missing[:2])
            self.assertTrue(missing[2].startswith("FAIL restore [Errno 2] No such file or directory"), missing[2])
            self.assertEqual((0, "", ""), cli("--stamp-installed", str(good), str(selfhost)))
            with patch.dict(os.environ):
                os.environ.pop("RELEASE_VERSION", None)
                installed = dump.installed_backup_version(selfhost)
            with gzip.open(good, "rb") as stream:
                self.assertEqual(dump.BACKUP_RELEASE_PREFIX + installed.encode() + b"\n", stream.readline())

    def test_backup_provenance_comes_from_the_environment_then_the_bundle_then_the_source_checkout(self):
        import tempfile
        from chronicle_ops.dump import installed_backup_version
        from chronicle_ops.release import UPGRADE_FROM_MINIMUM
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ):
            os.environ.pop("RELEASE_VERSION", None)
            selfhost = Path(folder) / "selfhost"; selfhost.mkdir()
            (selfhost / ".env.example").write_text("RELEASE_VERSION=development\n")
            self.assertEqual(UPGRADE_FROM_MINIMUM + "+development", installed_backup_version(selfhost))
            (selfhost / ".env.example").write_text("RELEASE_VERSION=2026.10.30\n")
            self.assertEqual("2026.10.30", installed_backup_version(selfhost))
            (Path(folder) / "release-manifest.json").write_text(json.dumps({"release_version": "2026.10.31"}))
            self.assertEqual("2026.10.31", installed_backup_version(selfhost))
            os.environ["RELEASE_VERSION"] = "2026.11.1"
            self.assertEqual("2026.11.1", installed_backup_version(selfhost))

    def test_a_tampered_verified_marker_or_unsafe_database_name_is_not_a_backup(self):
        import tempfile
        from chronicle_ops.dump import DumpError, publish_backup, verified_backup
        now = 1793448000
        with tempfile.TemporaryDirectory() as folder, patch('chronicle_ops.dump.time.time', return_value=now):
            backups = Path(folder)
            path = backups / "last/chronicle-20261031-020000.sql.gz"; path.parent.mkdir()
            path.write_bytes(gzip.compress(DUMP))
            publish_backup(path, "chronicle", {})
            marker = backups / "last/chronicle-verified.json"
            self.assertEqual(path, verified_backup(backups, "chronicle", "@daily").path)
            original = json.loads(marker.read_text())
            for change, message in (({"file": "../chronicle-20261031-020000.sql.gz"}, "invalid verified backup path"),
                                    ({"file": "other-20261031-020000.sql.gz"}, "invalid verified backup path"),
                                    ({"uncompressed_bytes": original["uncompressed_bytes"] + 1}, "size does not match its marker"),
                                    ({"verified_at": now - 3 * 24 * 3600}, "another database or is stale")):
                with self.subTest(change=change):
                    marker.write_text(json.dumps(dict(original, **change)))
                    with self.assertRaisesRegex(DumpError, message):
                        verified_backup(backups, "chronicle", "@daily")
            for database in ("chronicle/../other", "", "chron\nicle"):
                with self.subTest(database=database), self.assertRaisesRegex(DumpError, "unsafe backup database name"):
                    verified_backup(backups, database, "@daily")

    def framed(self, content):
        return b"-- PostgreSQL database dump\n\\restrict abc\n" + content + b"\n-- PostgreSQL database dump complete\n--\n\\unrestrict abc\n"

    def test_safe_sql_comments_quotes_and_copy_data(self):
        values = [b"SET statement_timeout = 0;", b"COMMENT ON TABLE public.t IS 'it''s; \"fine\"';",
                  b"CREATE FUNCTION public.f() RETURNS text LANGUAGE sql AS $$SELECT '\\x'$$;",
                  b"CREATE VIEW public.v AS SELECT $body$x$body$::text AS c;",
                  b"SET lock_timeout = 0 /* \\evil\n */; -- \\evil",
                  b"COPY public.events (id, \"note\") FROM stdin;\n\\evil PROGRAM lo_export\n\\.",
                  b"\n -- harmless\n\t\nSET lock_timeout = 0;"]
        for value in values:
            with self.subTest(value=value):
                self.assertTrue(safe_dump(io.BytesIO(self.framed(value))))

    def test_dump_cannot_commit_or_escape_the_restore_transaction(self):
        for statement in (b'COMMIT;', b'END;', b'BEGIN;', b'START\nTRANSACTION;',
                          b'SELECT 1; COMMIT;', b'PREPARE TRANSACTION \'escape\';'):
            with self.subTest(statement=statement):
                self.assertFalse(safe_dump(io.BytesIO(self.framed(statement))))
        self.assertTrue(safe_dump(io.BytesIO(self.framed(b'CREATE FUNCTION public.f() RETURNS void AS $$BEGIN NULL; END$$ LANGUAGE plpgsql;'))))

    def test_pg_dump_multiline_statements_are_not_transaction_control(self):
        # Verbatim pg_dump 18.6 output: keywords that open a line inside one statement.
        statements = (b"CREATE SEQUENCE public.t_id_seq\n    AS integer\n    START WITH 1\n    INCREMENT BY 1\n    CACHE 1;",
                      b"ALTER TABLE public.t ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (\n"
                      b"    SEQUENCE NAME public.t_id_seq\n    START WITH 1\n    CACHE 1\n);",
                      b"CREATE VIEW public.v AS\n SELECT\n        CASE\n            WHEN (a > 1) THEN 'x'::text\n"
                      b"            ELSE 'y'::text\n        END AS c\n   FROM public.t;")
        for statement in statements:
            with self.subTest(statement=statement):
                self.assertTrue(safe_dump(io.BytesIO(self.framed(statement))))

    def test_lexes_strings_comments_and_dollar_tags_as_psql_does(self):
        self.assertTrue(safe_dump(io.BytesIO(self.framed(b"SET lock_timeout = 0 /* a /* nested */ b */;"))))
        # A backslash ends a string at a different quote depending on E'' and
        # standard_conforming_strings, which the dump itself could change.
        refused = (b"SELECT 'x\\';", b"SELECT E'x\\'; COMMIT; --';", b"SELECT 'x\\'; COMMIT; --';",
                   b"SET standard_conforming_strings = off;\nSELECT 'a\\'b'; COMMIT; --';",
                   b"SELECT E'x'\n'y\\';junk';\nCOMMIT;\n--';",     # continuation stays an escape string
                   b"SELECT e/**/'x\\'; COMMIT; --';",              # identifier, comment, standard string
                   "SELECT \u00e9E'x\\'; COMMIT; --';".encode("latin1"),  # high-bit bytes continue identifiers
                   b"SELECT 1;\n/* outer /* inner */ still comment */\nCOMMIT;",
                   b"SELECT foo$x$;\nCOMMIT;\n$x$;",               # foo$x$ is an identifier to psql
                   b"SELECT 1;\x00 junk\nCOMMIT;",                 # psql ends the line at NUL
                   b"-- comment\rCOMMIT;",                           # CR ends a -- comment for psql
                   "SELECT $\u00e9$'$\u00e9$; COMMIT; SELECT $\u00e9$'$\u00e9$;".encode("latin1"),
                   b"PREPARE\nTRANSACTION 'x';",
                   b"COMMIT/*a/*b*/c*/WORK;",                         # a comment is whitespace to psql
                   b"COPY public.t TO/*a/*b*/c*/PROGRAM 'true';",
                   b"\xa0--comment")                                  # only ASCII whitespace is blank
        for dump in refused:
            with self.subTest(dump=dump):
                self.assertFalse(safe_dump(io.BytesIO(self.framed(dump))))

    def test_completion_marker_is_not_copy_data_or_quoted_sql(self):
        contents = (b"COPY public.events FROM stdin;\n-- PostgreSQL database dump complete\n\\.",
                    b"SELECT $$\n-- PostgreSQL database dump complete\n$$;")
        for content in contents:
            dump = b"-- PostgreSQL database dump\n\\restrict abc\n" + content + b"\n\\unrestrict abc\n"
            with self.subTest(content=content):
                self.assertFalse(safe_dump(io.BytesIO(dump)))

    def test_server_side_file_role_and_extension_primitives_are_refused(self):
        # The restore runs as the bootstrap superuser, so none of these may reach psql.
        primitives = (b"COPY (SELECT 1) TO '/var/lib/postgresql/data/exported';",
                      b"COPY public.events (id) FROM '/etc/passwd';",
                      b"SELECT lo_export(lo_import('/etc/passwd'), '/var/lib/postgresql/exported');",
                      b"SELECT pg_read_file('/etc/passwd');",
                      b"SELECT pg_read_binary_file('/etc/passwd');",
                      b"SELECT pg_ls_dir('/');",
                      b"SELECT pg_stat_file('/etc/passwd');",
                      b"ALTER ROLE chronicle_app SUPERUSER;",
                      b"ALTER ROLE chronicle_app CREATEROLE;",
                      b"ALTER ROLE chronicle_app REPLICATION;",
                      b"CREATE ROLE imported LOGIN SUPERUSER;",
                      b"SET SESSION AUTHORIZATION postgres;",
                      b"SET ROLE postgres;",
                      b"ALTER SYSTEM SET log_statement = 'none';",
                      b"LOAD 'auto_explain';",
                      b"CREATE EXTENSION IF NOT EXISTS dblink WITH SCHEMA public;",
                      b"SELECT dblink_exec('host=example.invalid', 'SELECT 1');")
        # The statement allowlist admits CREATE FUNCTION; the body must still not name these calls.
        bodies = (b"CREATE FUNCTION public.f() RETURNS text LANGUAGE sql AS $$SELECT pg_read_file('/etc/passwd')$$;",
                  b"CREATE FUNCTION public.f() RETURNS oid LANGUAGE sql AS $$SELECT lo_import('/etc/passwd')$$;",
                  b"CREATE FUNCTION public.f() RETURNS void LANGUAGE sql AS $$SELECT dblink_connect('x')$$;",
                  b"CREATE FUNCTION public.f() RETURNS void LANGUAGE plpgsql AS $$BEGIN COPY public.t TO '/x'; END$$;")
        for statement in primitives + bodies:
            with self.subTest(statement=statement):
                self.assertFalse(safe_dump(io.BytesIO(self.framed(statement))))

    def test_every_unsafe_framing_branch(self):
        values = [b"SELECT 1;", self.framed(b"\\evil"), self.framed(b"SELECT \\evil;"),
                  self.framed(b"COPY t TO PROGRAM 'cmd';"), self.framed(b"SELECT 'open"),
                  self.framed(b'SELECT "open'), self.framed(b"SELECT $tag$open"),
                  self.framed(b"SELECT /* open"), self.framed(b"COPY t FROM STDIN;\nrow"),
                  DUMP.replace(b"\\restrict fixture", b"\\restrict fixture\n\\restrict fixture"),
                  DUMP.replace(b"\\unrestrict fixture", b"\\unrestrict wrong"),
                  DUMP.replace(b"\\restrict fixture\n", b""),
                  DUMP.replace(b"-- PostgreSQL database dump\n", b""),
                  DUMP + b"SELECT 1;\n", DUMP + b"\\restrict extra\n", DUMP + b"\\unrestrict fixture\n"]
        for value in values:
            with self.subTest(value=value):
                self.assertFalse(safe_dump(io.BytesIO(value)))


if __name__ == "__main__":
    unittest.main()
