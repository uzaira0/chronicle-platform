import io
from contextlib import suppress
import os
from pathlib import Path
import shutil
import signal
import site
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "selfhost"))
from chronicle_ops.__main__ import main
from chronicle_ops.common import Interrupted, compose, run
from chronicle_ops.receipts import record_operation

HOSTILE_USER_SITE = "CHRONICLE_HOSTILE_USER_SITE"
USER_SITE_LOADED = "loaded"


class RuntimeTests(unittest.TestCase):
    def test_python_suite_excludes_user_site(self):
        self.assertFalse(site.ENABLE_USER_SITE, "Run the self-host suite with python3 -s")
        self.assertNotIn(HOSTILE_USER_SITE, os.environ)

    def test_security_runner_isolates_a_hostile_user_site(self):
        root = Path(__file__).resolve().parents[2]
        interpreter = shutil.which("python3", path="/usr/bin:/bin:" + os.environ["PATH"])
        target = "test_runtime.RuntimeTests.test_python_suite_excludes_user_site"
        with tempfile.TemporaryDirectory() as folder:
            env = dict(os.environ, PYTHONUSERBASE=folder,
                       PYTHONPATH=str(root / "selfhost") + os.pathsep + str(Path(__file__).parent))
            env.pop("PYTHONNOUSERSITE", None)
            user_site = subprocess.run([interpreter, "-s", "-c", "import site; print(site.getusersitepackages())"],
                                      env=env, text=True, capture_output=True, check=True).stdout.strip()
            Path(user_site).mkdir(parents=True)
            (Path(user_site) / "hostile.pth").write_text(
                f'import os; os.environ[{HOSTILE_USER_SITE!r}] = {USER_SITE_LOADED!r}\n')
            probe = run([interpreter, "-c", f'import os; print(os.environ.get({HOSTILE_USER_SITE!r}))'],
                        env=env, capture=True, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(probe.stdout.strip(), USER_SITE_LOADED, probe.stderr)
            ambient = run([interpreter, "-m", "unittest", target], env=env,
                          capture=True, stderr=subprocess.PIPE, timeout=20)
            self.assertNotEqual(ambient.returncode, 0, ambient.stdout + ambient.stderr)
            isolated = run(["bash", "-c", 'source "$1"; run_selfhost_python_suite "$2"',
                            "fixture", str(root / "tests/security/run-all-security.sh"), target],
                           env=env, capture=True, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(isolated.returncode, 0, isolated.stdout + isolated.stderr)

    def test_native_runtime_preserves_builtin_exception_references(self):
        before = sys.getrefcount(OSError)
        for _ in range(1000):
            os.path.realpath(os.path.join(tempfile.gettempdir(), 'absent-runtime-control'))
        self.assertEqual(sys.getrefcount(OSError), before)

    def test_timeout_terminates_and_reaps_a_real_child_process(self):
        script = '''
import signal, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
def stop(*args):
    child.wait()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
print(child.pid, flush=True)
time.sleep(60)
'''
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            run([sys.executable, "-c", script], capture=True, timeout=0.5)
        child = int(caught.exception.output)
        try:
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            with suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)

    def test_compose_preserves_arguments_and_capture_stream_quiet_modes(self):
        with patch.dict(os.environ, {"CHRONICLE_OPS_PROJECT": "pilot"}), \
             patch("chronicle_ops.common.subprocess.run") as call:
            compose("exec", "two words", "quote'", "line\nbreak", capture=True)
            self.assertEqual(call.call_args.args[0], ["docker", "compose", "-p", "pilot", "exec", "two words", "quote'", "line\nbreak"])
            self.assertEqual(call.call_args.kwargs["stdout"], subprocess.PIPE)
            compose("stop", quiet=True)
            self.assertEqual(call.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(call.call_args.kwargs["stderr"], subprocess.DEVNULL)
            compose("up")
            self.assertIsNone(call.call_args.kwargs["stdout"])

    def test_main_restore_config_and_signal_handler(self):
        from chronicle_ops.dump import file_sha256
        digest = file_sha256(Path(__file__))
        with patch.dict(os.environ, {"CHRONICLE_OPS_STATE": "/state", "CHRONICLE_OPS_BACKUPS": "/backups", "RESTORE_START_WAIT_TIMEOUT_SECONDS": "17"}), \
             patch("chronicle_ops.__main__.Restore") as restore, \
             patch("chronicle_ops.__main__.signal.signal") as install:
            restore.return_value.execute.return_value = 0
            self.assertEqual(main(["restore", "--no-start", "--trusted-sha256=" + digest]), 0)
            self.assertEqual(restore.call_args.args, ("/state", "/backups", "", digest, "17", True, False))
            self.assertEqual([row.args[0] for row in install.call_args_list], [signal.SIGHUP, signal.SIGINT, signal.SIGTERM])
            with self.assertRaises(Interrupted) as caught:
                install.call_args.args[1](signal.SIGTERM, None)
            self.assertEqual(caught.exception.status, 143)

    def test_monitoring_timeout_and_nonzero_warn_but_do_not_fail_operation(self):
        for failure in (subprocess.TimeoutExpired("docker", 15), subprocess.CompletedProcess([], 42)):
            with self.subTest(failure=failure), \
                 patch.dict(os.environ, {"COMPOSE_FILE": "overlays/monitoring.yml"}), \
                 patch("chronicle_ops.receipts.compose", side_effect=[subprocess.CompletedProcess([], 0, "operational-probe\n"), failure]), \
                 patch("sys.stderr", new_callable=io.StringIO) as output:
                record_operation("restore", "failure", "restore_failed")
                self.assertIn("could not be recorded within 15 seconds", output.getvalue())

    def test_monitoring_success_is_quiet_and_bounded(self):
        with patch.dict(os.environ, {"COMPOSE_FILE": "overlays/monitoring.yml"}), \
             patch("chronicle_ops.receipts.compose", side_effect=[subprocess.CompletedProcess([], 0, "operational-probe\n"), subprocess.CompletedProcess([], 0)]) as call, \
             patch("sys.stderr", new_callable=io.StringIO) as output:
            record_operation("restore", "success")
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(call.call_args.kwargs, {"quiet": True, "timeout": 15})
            # exec into the running probe; a one-off run would reconcile the project's networks.
            self.assertEqual(call.call_args.args, ("exec", "-T", "operational-probe", "/monitoring/record-operation.sh",
                                                   "restore", "success", "none"))

    def test_verify_failure_and_signal_always_record_receipts(self):
        for result in (1, Interrupted(signal.SIGTERM)):
            with self.subTest(result=result), patch("chronicle_ops.__main__.signal.signal"), \
                 patch("chronicle_ops.common.acquire_operation_lock", return_value=None), \
                 patch.dict(os.environ, CHRONICLE_OPS_STATE="/state"), \
                 patch("chronicle_ops.verify.verify", side_effect=result if isinstance(result, BaseException) else None, return_value=result), \
                 patch("chronicle_ops.__main__.finish_operation") as finish:
                status = main(["verify"])
                self.assertEqual(status, 143 if isinstance(result, Interrupted) else 1)
                self.assertEqual(finish.call_args.args[:3], ("verify", status, "verification_failed"))


class OperatorCliTests(unittest.TestCase):
    """The installed CLI as ./chronicle, doctor.sh, cron and rotate-secret.sh invoke it."""

    def setUp(self):
        from chronicle_ops.common import LOCK_FD_ENV
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.state = Path(folder.name).resolve()
        origin = Path.cwd()
        self.addCleanup(os.chdir, origin)
        os.chdir(self.state)
        environment = patch.dict(os.environ, CHRONICLE_OPS_STATE=str(self.state), CHRONICLE_OPS_PROJECT="fixture",
                                 CHRONICLE_OPS_BACKUPS=str(self.state / "backups"), HOME=str(self.state), COMPOSE_FILE="docker-compose.yml")
        environment.start()
        self.addCleanup(environment.stop)
        for key in (LOCK_FD_ENV, "CHRONICLE_RECONCILE_ENABLED", "CHRONICLE_RECONCILE_RUN", "MIN_FREE_DISK_GIB"):
            os.environ.pop(key, None)
        signals = patch("chronicle_ops.__main__.signal.signal")
        signals.start()
        self.addCleanup(signals.stop)

    def cli(self, *args, stdin=""):
        from chronicle_ops.__main__ import run_cli
        with patch("sys.stdout", new_callable=io.StringIO) as output, \
             patch("sys.stderr", new_callable=io.StringIO) as errors, patch("sys.stdin", io.StringIO(stdin)):
            status = run_cli(list(args))
        return status, output.getvalue(), errors.getvalue()

    def write_env(self, text, mode=0o600, directory=None):
        path = (directory or self.state) / ".env"
        path.write_text(text)
        path.chmod(mode)
        return path

    def test_scheduled_reconcile_skips_while_another_operation_holds_the_lock(self):
        import fcntl
        from chronicle_ops.common import LOCK_FD_ENV, OPERATION_LOCK
        held = os.open(self.state / OPERATION_LOCK, os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, held)
        fcntl.flock(held, fcntl.LOCK_EX)
        with patch("chronicle_ops.__main__.os.execvp", side_effect=AssertionError("ran while another operation held the lock")):
            self.assertEqual((0, "", ""), self.cli("operation-lock", "--state", str(self.state), "--nonblocking", "--", "bash", "-s"))
        self.assertNotIn(LOCK_FD_ENV, os.environ)

    def test_locked_command_runs_holding_an_inheritable_operation_lock(self):
        import fcntl
        from chronicle_ops.common import LOCK_FD_ENV, OPERATION_LOCK
        (self.state / "deployment").mkdir()
        seen = {}

        def exec_command(program, argv):
            descriptor = int(os.environ[LOCK_FD_ENV])
            self.addCleanup(os.close, descriptor)
            seen.update(program=program, argv=argv, state=os.environ["CHRONICLE_OPS_STATE"],
                        inheritable=os.get_inheritable(descriptor))
            probe = os.open(self.state / "deployment" / OPERATION_LOCK, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)

        with patch("chronicle_ops.__main__.os.execvp", side_effect=exec_command):
            self.cli("operation-lock", "--state", "deployment", "--", "./rotate-secret.sh", "postgres")
        self.assertEqual(dict(program="./rotate-secret.sh", argv=["./rotate-secret.sh", "postgres"],
                              state=str(self.state / "deployment"), inheritable=True), seen)

    def test_rotation_lock_reads_its_state_directory_only_from_a_private_env(self):
        from chronicle_ops.common import OPERATION_LOCK
        deployment = self.state / "deployment"
        deployment.mkdir()
        refused = patch("chronicle_ops.__main__.os.execvp", side_effect=AssertionError("ran without a private .env"))
        refused.start()
        self.addCleanup(refused.stop)
        self.assertEqual((1, "", "error: .env must be a regular file\n"), self.cli("operation-lock", "--", "true"))
        (self.state / "shared.env").write_text(f"CHRONICLE_STATE_DIR={deployment}\n")
        (self.state / ".env").symlink_to(self.state / "shared.env")
        self.assertEqual((1, "", "error: .env must be a regular file\n"), self.cli("operation-lock", "--", "true"))
        (self.state / ".env").unlink()
        self.write_env(f"CHRONICLE_STATE_DIR={deployment}\n", mode=0o644)
        self.assertEqual((1, "", "error: .env must have mode 0600\n"), self.cli("operation-lock", "--", "true"))
        self.write_env(f"CHRONICLE_STATE_DIR={deployment}\n")
        self.assertEqual((1, "", "error: operation-lock requires a command\n"), self.cli("operation-lock", "--"))
        refused.stop()
        with patch("chronicle_ops.__main__.os.execvp") as execute:
            self.cli("operation-lock", "--", "./rotate-secret.sh")
        from chronicle_ops.common import LOCK_FD_ENV, release_operation_lock
        self.addCleanup(release_operation_lock, int(os.environ[LOCK_FD_ENV]))
        self.assertEqual(str(deployment), os.environ["CHRONICLE_OPS_STATE"])
        self.assertTrue((deployment / OPERATION_LOCK).is_file())
        self.assertEqual(["./rotate-secret.sh"], execute.call_args.args[1])

    def test_doctor_sees_paused_reconciliation_until_resume(self):
        from chronicle_ops.common import OPERATION_LOCK
        self.assertEqual(1, self.cli("reconcile", "stopped")[0])
        self.assertEqual(0, self.cli("reconcile", "stop")[0])
        self.assertEqual(0, self.cli("reconcile", "stopped")[0])
        self.assertEqual(0, self.cli("reconcile", "resume")[0])
        self.assertEqual(1, self.cli("reconcile", "stopped")[0])
        self.assertEqual((0, f"{self.state / OPERATION_LOCK}\n", ""), self.cli("reconcile", "lock-path"))

    def test_start_refuses_an_interrupted_update_except_from_its_own_candidate(self):
        from chronicle_ops.receipts import write_json
        from chronicle_ops.reconcile import RECOVERY_FILE, RECOVERY_PHASE, UPGRADE_LOCK
        (self.state / UPGRADE_LOCK).mkdir()
        write_json(self.state / UPGRADE_LOCK / RECOVERY_FILE,
                   dict(previous="/srv/chronicle-selfhost-2026.10.23/selfhost", owner=str(self.state), phase=RECOVERY_PHASE))
        status, _, errors = self.cli("reconcile", "check")
        self.assertEqual(1, status)
        self.assertIn(f"incomplete operation at {self.state / UPGRADE_LOCK}; "
                      "run ./chronicle update from /srv/chronicle-selfhost-2026.10.23/selfhost", errors)
        self.assertEqual((0, "", ""), self.cli("reconcile", "check-start"))
        with patch.dict(os.environ, CHRONICLE_RECONCILE_RUN="true"):
            self.assertEqual(1, self.cli("reconcile", "check-start")[0])

    def test_setup_preflight_warns_on_hosts_without_an_active_cron_service(self):
        from types import SimpleNamespace
        def services(*active):
            return lambda args, **_: SimpleNamespace(returncode=0 if args[-1] in active else 3)
        cases = (
            ("Linux", "/usr/bin/tool", services("cron"), None),
            ("Linux", "/usr/bin/tool", services("crond"), None),
            ("Darwin", "/usr/bin/tool", services("cron"), "automatic reconciliation requires a Linux operator crontab"),
            ("Linux", None, services("cron"), "reconciliation requires crontab, logger and systemctl; "
                                              "install cron/cronie or explicitly disable reconciliation"),
            ("Linux", "/usr/bin/tool", services(), "reconciliation requires an enabled, active cron/crond service"),
        )
        for system, tool, systemctl, reason in cases:
            with self.subTest(system=system, tool=tool, reason=reason), \
                 patch("chronicle_ops.reconcile.platform.system", return_value=system), \
                 patch("chronicle_ops.reconcile.shutil.which", return_value=tool), \
                 patch("chronicle_ops.reconcile.run", side_effect=systemctl):
                status, output, errors = self.cli("reconcile", "preflight")
                self.assertEqual((0, ""), (status, output))  # never refuses setup
                if reason:
                    self.assertIn(f"automatic reconciliation is unavailable: {reason}", errors)
                else:
                    self.assertEqual("", errors)
                with patch.dict(os.environ, CHRONICLE_RECONCILE_ENABLED="false"):
                    self.assertEqual((0, "", ""), self.cli("reconcile", "preflight"))

    def test_uninstall_removes_only_this_deployments_scheduled_jobs(self):
        from types import SimpleNamespace
        from chronicle_ops.reconcile import STOP_MARKER
        (self.state / "reconcile.sh").write_text("#!/usr/bin/env bash\n")
        listed = ("3 2 * * * institutional-backup\n"
                  "@reboot /srv/state/reconcile.sh # chronicle-reconcile:fixture\n"
                  "*/15 * * * * /srv/state/reconcile.sh # chronicle-reconcile:fixture\n"
                  "*/15 * * * * /srv/other/reconcile.sh # chronicle-reconcile:fixture-two\n")
        written = []
        def crontab(args, **kwargs):
            if args == ["crontab", "-"]:
                written.append(kwargs["input"])
            return SimpleNamespace(returncode=0, stdout=listed, stderr="")
        with patch("chronicle_ops.reconcile.shutil.which", return_value="/usr/bin/crontab"), \
             patch("chronicle_ops.reconcile.run", side_effect=crontab):
            self.assertEqual((0, "", ""), self.cli("reconcile", "uninstall"))
        self.assertEqual(["3 2 * * * institutional-backup\n"
                          "*/15 * * * * /srv/other/reconcile.sh # chronicle-reconcile:fixture-two\n"], written)
        self.assertFalse((self.state / "reconcile.sh").exists())
        self.assertTrue((self.state / STOP_MARKER).is_file())

    def test_up_recreates_services_only_when_certificate_content_changes(self):
        from chronicle_ops import release
        tls = self.state / "tls"
        tls.mkdir()
        (tls / "internal-cert.pem").write_text("certificate one\n")
        (tls / "internal-ca.crt").write_text("authority\n")
        (tls / "internal-key.pem").write_text("private key\n")
        (tls / "operator-only.crt").write_text("unreadable\n")
        hash_file = release.file_sha256
        def unreadable(path):
            if Path(path).name == "operator-only.crt":
                raise PermissionError(13, "Permission denied", str(path))
            return hash_file(path)
        with patch("chronicle_ops.release.file_sha256", side_effect=unreadable):
            status, digest, _ = self.cli("certificates", "digest")
        self.assertEqual(0, status)
        self.assertEqual([str(tls / "internal-ca.crt"), str(tls / "internal-cert.pem")],
                         [line.split("  ", 1)[1] for line in digest.splitlines()])
        self.assertEqual((0, "changed\n", ""), self.cli("certificates", "compare", stdin=digest))
        self.assertEqual((0, "", ""), self.cli("certificates", "record", stdin=digest))
        self.assertEqual((0, "unchanged\n", ""), self.cli("certificates", "compare", stdin=digest))
        respelled = digest.replace(str(self.state), "/var/lib/chronicle/../chronicle")
        self.assertEqual((0, "unchanged\n", ""), self.cli("certificates", "compare", stdin=respelled))
        (tls / "internal-cert.pem").write_text("certificate two\n")
        self.assertEqual((0, "changed\n", ""), self.cli("certificates", "compare", stdin=self.cli("certificates", "digest")[1]))

    def test_disk_full_refuses_start_and_names_the_short_filesystem(self):
        from types import SimpleNamespace
        from chronicle_ops.common import GIB, MIN_FREE_INODES
        roomy = SimpleNamespace(f_bavail=50, f_frsize=GIB, f_files=10 ** 6, f_favail=10 ** 5)
        full = SimpleNamespace(f_bavail=1, f_frsize=GIB, f_files=10 ** 6, f_favail=10 ** 5)
        no_inodes = SimpleNamespace(f_bavail=50, f_frsize=GIB, f_files=10 ** 6, f_favail=12)
        for state_disk, docker_disk, floor, expected in (
                (roomy, full, None, f"error: docker-data: {GIB} bytes and {10 ** 5} inodes free; require {5 * GIB} bytes "
                                    f"and {MIN_FREE_INODES} inodes before mutation\n"),
                (no_inodes, roomy, None, f"error: state: {50 * GIB} bytes and 12 inodes free; require {5 * GIB} bytes "
                                         f"and {MIN_FREE_INODES} inodes before mutation\n"),
                (roomy, full, "1", ""),
                (roomy, roomy, None, "")):
            disks = {str(self.state): state_disk, "/var/lib/docker": docker_disk}
            inventory = [SimpleNamespace(stdout="/var/lib/docker\n"), SimpleNamespace(stdout=""), SimpleNamespace(stdout="")]
            with self.subTest(expected=expected, floor=floor), \
                 patch.dict(os.environ, {"MIN_FREE_DISK_GIB": floor} if floor else {}), \
                 patch("chronicle_ops.common.run", side_effect=inventory), \
                 patch("chronicle_ops.common.os.statvfs", side_effect=lambda path: disks[str(path)]):
                self.assertEqual((1 if expected else 0, "", expected), self.cli("storage-check"))

    def test_storage_encryption_checks_accept_only_a_reviewed_waiver(self):
        import subprocess
        from types import SimpleNamespace
        unconfirmed = SimpleNamespace(returncode=1, stdout="")
        for waiver, expected in (("", 1), ("BACKUP_STORAGE_ENCRYPTION_WAIVER=CHANGE_ME\n", 1),
                                 ("BACKUP_STORAGE_ENCRYPTION_WAIVER='Reviewed by institutional IT 2026-10'\n", 0)):
            self.write_env("COMPOSE_PROJECT_NAME=fixture\n" + waiver)
            with self.subTest(waiver=waiver), patch("chronicle_ops.verify.run", return_value=unconfirmed):
                status, output, _ = self.cli("backup-storage")
                self.assertEqual(expected, status)
                self.assertIn("encryption uses a reviewed waiver" if expected == 0 else "encryption is unconfirmed", output)
            with self.subTest(waiver=waiver, storage="database"), \
                 patch("chronicle_ops.verify.database_volume_path", side_effect=subprocess.CalledProcessError(1, "docker")):
                status, output, _ = self.cli("database-storage")
                self.assertEqual(expected, status)
                self.assertIn("database storage uses a reviewed encryption waiver" if expected == 0 else
                              "database volume was not found; its backing-device encryption is unconfirmed", output)

    def test_setup_shows_the_backup_disk_estimate_or_asks_for_retention(self):
        (self.state / "backups").mkdir()
        self.write_env("POSTGRES_DB=chronicle\n")
        status, output, _ = self.cli("backup-footprint")
        self.assertEqual(0, status)
        self.assertIn("WARNING", output)
        self.assertIn("backup disk: Backup retention has not been chosen\n"
                      "  Run ./chronicle setup and answer the backup retention questions", output)
        self.write_env("POSTGRES_DB=chronicle\nBACKUP_KEEP_DAYS=all\nBACKUP_KEEP_WEEKS=all\nBACKUP_KEEP_MONTHS=all\n")
        self.assertEqual((0, "Backup disk: No backup yet; the disk estimate appears after the first backup\n", ""),
                         self.cli("backup-footprint"))

    def test_public_check_probes_the_configured_public_origin(self):
        probed = []
        def curl(url, *_args, **_kwargs):
            probed.append(url)
            return 0, "204" if url.endswith("/health") else "200"
        for settings, origin, expected in (
                ("DOMAIN=estudio.example.cl\n", "https://estudio.example.cl", 0),
                ("DOMAIN=estudio.example.cl\nCHRONICLE_PUBLIC_BASE_URL=https://edge.example.cl:8443/\n",
                 "https://edge.example.cl:8443", 0),
                ("CHRONICLE_PUBLIC_BASE_URL=http://estudio.example.cl\n", None, 1)):
            self.write_env(settings)
            probed.clear()
            with self.subTest(settings=settings), patch("chronicle_ops.verify.curl", side_effect=curl):
                status, _, errors = self.cli("public-check")
                self.assertEqual(expected, status)
                self.assertEqual([origin + "/health", origin + "/chronicle/"] if origin else [], probed)
                self.assertEqual("" if origin else "public acceptance requires an HTTPS origin\n", errors)

    def test_commands_from_a_superseded_release_are_refused(self):
        from chronicle_ops.release import OWNER_FILE
        (self.state / OWNER_FILE).write_text("/srv/chronicle-selfhost-2026.10.30/selfhost\n")
        with patch("chronicle_ops.release.compose_projects", return_value=[]):
            self.assertEqual((1, "", "error: this release was superseded; use the active selfhost directory: "
                                     "/srv/chronicle-selfhost-2026.10.30/selfhost\n"), self.cli("owner-check"))
            (self.state / OWNER_FILE).write_text(f"{self.state}\n")
            self.assertEqual((0, "", ""), self.cli("owner-check"))

    def test_cleanup_previews_by_default_and_removes_only_with_apply(self):
        import json
        from chronicle_ops.common import LOCK_FD_ENV
        from chronicle_ops.release import OWNER_FILE, RELEASE_KEEP_COUNT
        releases = self.state / "releases"
        bundles = []
        for number in range(1, RELEASE_KEEP_COUNT + 3):
            bundle = releases / f"chronicle-selfhost-2026.10.{number}"
            (bundle / "selfhost").mkdir(parents=True)
            (bundle / "release-manifest.json").write_text(json.dumps(dict(release_version=f"2026.10.{number}")))
            bundles.append(bundle)
        (self.state / OWNER_FILE).write_text(f"{bundles[-1] / 'selfhost'}\n")
        with patch("chronicle_ops.release.compose_projects", return_value=[]), patch("chronicle_ops.release.run"):
            status, preview, _ = self.cli("cleanup", "--releases-dir", str(releases))
            self.assertEqual(0, status)
            self.assertEqual([f"Would remove {bundle} and its archive/checksum/signature" for bundle in bundles[1::-1]],
                             preview.splitlines())
            self.assertTrue(all(bundle.exists() for bundle in bundles))
            status, applied, _ = self.cli("cleanup", "--releases-dir", str(releases), "--apply")
        self.assertEqual(0, status)
        self.assertEqual(preview.replace("Would remove", "Removing"), applied)
        self.assertEqual([False, False] + [True] * RELEASE_KEEP_COUNT, [bundle.exists() for bundle in bundles])
        self.assertNotIn(LOCK_FD_ENV, os.environ)

    def test_restore_recover_refuses_a_dump_or_digest(self):
        with patch("chronicle_ops.__main__.Restore", side_effect=AssertionError("restore started")):
            for extra in (["/backups/daily/chronicle-20261030.sql.gz"], ["--trusted-sha256=" + "a" * 64]):
                with self.subTest(extra=extra):
                    self.assertEqual((1, "", "error: restore --recover resumes the committed database; "
                                             "do not supply a dump or digest\n"), self.cli("restore", "--recover", *extra))

    def test_rollback_refuses_the_active_release_as_its_source(self):
        self.assertEqual((1, "", "error: rollback --from must name the previous release\n"),
                         self.cli("rollback", "--from", str(self.state), "--trusted-sha256", "a" * 64,
                                  "/backups/pre-upgrade-1.sql.gz"))

    def test_interrupted_command_exits_with_the_signal_status(self):
        with patch("chronicle_ops.restore.rollback", side_effect=Interrupted(signal.SIGINT)):
            self.assertEqual((130, "", "error: interrupted by signal 2\n"),
                             self.cli("rollback", "--from", "/srv/previous", "--trusted-sha256", "a" * 64,
                                      "/backups/pre-upgrade-1.sql.gz"))

    def test_standalone_verify_reports_a_pending_update_recovery(self):
        from chronicle_ops.reconcile import UPGRADE_LOCK
        (self.state / UPGRADE_LOCK).mkdir()
        (self.state / UPGRADE_LOCK / "recovery.json").write_text("{}")
        with patch("chronicle_ops.verify.verify", return_value=0), patch("chronicle_ops.__main__.finish_operation"):
            self.assertEqual((0, "Update recovery is pending; run ./chronicle update from the recorded release.\n", ""),
                             self.cli("verify"))
            with patch("chronicle_ops.common.acquire_operation_lock", return_value=None):
                self.assertEqual((0, "", ""), self.cli("verify"))

    def test_operation_receipts_are_written_from_the_cli(self):
        self.assertEqual((0, "", ""), self.cli("write-operation-receipt", "backup", "failure", "backup_failed", "42"))
        self.assertEqual((0, "", ""), self.cli("record-operation", "backup", "failure", "backup_failed"))
        receipts = list((self.state / "operator-receipts/operations").glob("*-backup-*.json"))
        self.assertEqual(1, len(receipts))
        import json
        data = json.loads(receipts[0].read_text())
        self.assertEqual(("backup", "failure", "backup_failed", 42),
                         (data["operation"], data["outcome"], data["failureCategory"], data["durationSeconds"]))
        self.assertEqual((1, "", "error: invalid operation receipt\n"),
                         self.cli("write-operation-receipt", "backup", "partial"))
