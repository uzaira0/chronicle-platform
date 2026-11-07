"""Guarded restore orchestration and recovery."""

from datetime import datetime, timezone
from enum import Enum
import errno
from gettext import gettext as _
import os
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time

from .reconcile import RECOVERY_FILE, RESTORE_LOCK, ROTATION_MARKER, UPGRADE_LOCK, recovery_command

from .dump import RESTORE_MUTATION_MARKER, DumpError, EXIT_RESTORE_TRANSACTION_ROLLED_BACK, validate_dump
from .common import BLD, GRN, RED, RST, Interrupted, acquire_operation_lock, release_operation_lock, application_services, compose, compose_project, require, same_path, warn, OPERATION_LOCK_CREATE_ERROR
from .receipts import OPERATOR_RECEIPTS_DIR, durable_replace, finish_operation, json_text, publish_journal, write_text, write_json
from .envfile import read_env, value
from .reconcile import STOP_MARKER
from .services import environment_monitoring, environment_roles, start_split
from .startup import DEFAULT_STARTUP_TIMEOUT_SECONDS, startup_timeout

class RestoreError(Exception):
    pass


def resolve_host_path(root_text, container_text):
    parts = PurePosixPath(container_text).parts
    if len(parts) < 3 or parts[:2] != ("/", "backups"):
        raise RestoreError("restore path must be below /backups")
    relative = parts[2:]
    if any(part in {"", ".", ".."} for part in relative):
        raise RestoreError("restore path contains an unsafe component")
    if not relative[-1].endswith(".sql.gz"):
        raise RestoreError("restore path must end in .sql.gz")
    try:
        root = Path(root_text).resolve(strict=True)
        target = root.joinpath(*relative).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RestoreError("cannot resolve restore path: {}".format(error)) from None
    if any(character in str(target) for character in ("\n", "\r", "\x00")):
        raise RestoreError("restore path resolves to a name containing a control character")
    if os.path.commonpath((str(root), str(target))) != str(root):
        raise RestoreError("restore path resolves outside the backups directory")
    if not target.is_file():
        raise RestoreError("restore path is not a regular file")
    return target


def private_copy(source, directory):
    """Copy source to a new owner-only file in directory, which restore.sh can read as /backups/<name>."""
    descriptor, name = tempfile.mkstemp(prefix=".reviewed-restore.", suffix=".sql.gz", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as writer, open(source, "rb") as reader:
            shutil.copyfileobj(reader, writer)
            writer.flush()
            os.fsync(writer.fileno())
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


class RestorePhase(Enum):
    """Restore lock phases, in the only order a restore may enter them."""
    PREPARED = "prepared"
    STOPPING_SERVICES = "stopping-services"
    RESTORING = "restoring"
    DATABASE_RESTORED = "database-restored"
    STARTING_SERVICES = "starting-services"
    VERIFIED = "verified"

    @property
    def database_restored(self):
        return self in (self.DATABASE_RESTORED, self.STARTING_SERVICES, self.VERIFIED)


class RestoreOutcome(Enum):
    UNCHANGED = "unchanged"
    RESTORED = "restored"
    UNCERTAIN = "uncertain"


RESTORED_STOP = "restored; explicit up required\n"


class Restore:
    LOCK_FIELDS = ("owner-pid", "phase", "restore-file")

    def __init__(self, root, backups, container_path, digest, timeout, no_start,
                 assume_yes, terminal=None, owner_pid=None, recovery_owner=None, target_version=None, rollback=False):
        self.root = Path(root)
        self.backups = backups
        self.mutation_marker = Path(backups) / RESTORE_MUTATION_MARKER
        database = os.environ.get("POSTGRES_DB", "chronicle")
        self.container_path = container_path or f"/backups/last/{database}-latest.sql.gz"
        self.digest, self.timeout = digest, timeout
        self.no_start, self.assume_yes, self.terminal = no_start, assume_yes, terminal
        self.owner_pid = str(owner_pid or os.getpid())
        self.recovery_owner = recovery_owner
        self.target_version = target_version
        # Only Rollback sets this: restore.sh then proves the older dump keeps every protected fact.
        # Leaving services stopped (no_start) is a separate fact and changes nothing in the restore.
        self.rollback = rollback
        self.pinned = None
        self.started = time.monotonic()
        self.lock = self.root / RESTORE_LOCK
        self.held = self.preserve = self.restart = False
        self.phase = None
        self.previous = []
        self.stopped = application_services([])
        self.completion = None

    def dc(self, *args, **kwargs):
        result = compose(*args, **kwargs)
        return result.returncode, (result.stdout or "").rstrip("\n")

    def roles(self, message, monitoring_only=False):
        try:
            return environment_monitoring(compose) if monitoring_only else environment_roles(compose)
        except (OSError, subprocess.SubprocessError, KeyError):
            raise RestoreError(message) from None

    def restart_services(self, services, message=None):
        """Restart services that were running, waiting only on the core ones."""
        monitoring = self.roles(message or "could not resolve the Compose services to restart", True)
        try:
            start_split(compose, [service for service in services if service not in monitoring],
                        [service for service in services if service in monitoring], self.timeout, ("--no-deps",))
        except (OSError, subprocess.SubprocessError):
            if message:
                raise RestoreError(message) from None
            return 1
        return 0

    def require_dc(self, message, *args, **kwargs):
        status, output = self.dc(*args, **kwargs)
        if status:
            raise RestoreError(message)
        return output

    def write_lock(self, name, value):
        if not re.fullmatch("[a-z-]+", name):
            raise RestoreError("internal error: invalid restore lock field")
        temporary = self.lock / ".{}.{}".format(name, self.owner_pid)
        try:
            temporary.write_text(str(value) + "\n", encoding="utf-8", errors="surrogateescape")
        except OSError:
            raise RestoreError("could not write restore operation metadata") from None
        try:
            temporary.chmod(0o600)
        except OSError:
            raise RestoreError("could not protect restore operation metadata") from None
        try:
            os.replace(temporary, self.lock / name)
        except OSError:
            raise RestoreError("could not publish restore operation metadata") from None

    def enter(self, phase):
        phases = list(RestorePhase)
        position = 0 if self.phase is None else phases.index(self.phase) + 1
        if position == len(phases) or phase is not phases[position]:
            raise RestoreError("internal error: restore cannot move from {} to {}".format(self.phase, phase))
        self.write_lock("phase", phase.value)
        self.phase = phase

    def release(self):
        if not self.held:
            return True
        if not self.lock.is_dir() or self.lock.is_symlink():
            return False
        for name in self.LOCK_FIELDS:
            for path in (self.lock / name, self.lock / ".{}.{}".format(name, self.owner_pid)):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    return False
        try:
            self.lock.rmdir()
        except OSError:
            return False
        self.held = False
        return True

    def cleanup(self):

        if self.restart:
            if self.previous:
                warn("the live database was not replaced; restarting the services that were running before the stop attempt: " + " ".join(self.previous))
                try:
                    status = self.restart_services(self.previous)
                except RestoreError:
                    status = 1
                if not status:
                    print("         The pre-restore service state was restored.", file=sys.stderr)
                else:
                    warn("the database was not changed, but the previous application services could not all be restarted.")
                    print("         Diagnose Docker Compose, then run ./chronicle up.", file=sys.stderr)
            self.restart = False
            # Rejected input and rolled-back transactions preserve the original public data.
            self.preserve = False
        if self.held:
            if self.preserve:
                warn("do not start Chronicle application services against this database.")
                print("         Restore state is preserved at {}.".format(self.lock), file=sys.stderr)
                print("         Confirm no restore process or restore container is running, diagnose the", file=sys.stderr)
                print("         failure, then follow docs/BACKUP-RESTORE.md#interrupted-restore-recovery.", file=sys.stderr)
            elif not self.release():
                warn("could not release restore lock {}".format(self.lock))

    def trust_dump(self, path):
        try:
            validate_dump(path, self.digest)
            manifest = Path.cwd().parent / 'release-manifest.json'
            if self.target_version or manifest.is_file():
                from .dump import require_restore_version
                version = self.target_version or json.loads(manifest.read_text())['release_version']
                require_restore_version(path, version)
        except DumpError as error:
            self.reject_dump(str(error))

    def reject_dump(self, message):
        print("FAIL restore " + message, file=sys.stderr)
        raise RestoreError("restore dump trust verification failed")

    def interlocks(self, acquired=False):
        for name, operation in ((UPGRADE_LOCK, "upgrade"), (ROTATION_MARKER, "secret rotation")):
            lock = self.root / name
            if os.path.lexists(lock):
                if operation == "upgrade" and self.recovery_owner:
                    recovery = json.loads((lock / RECOVERY_FILE).read_text())
                    if same_path(recovery["owner"], self.recovery_owner):
                        continue
                article = "an" if operation == "upgrade" else "a"
                detail = ("started while the restore lock was being acquired; restore did not start"
                          if acquired else "is active or incomplete ({}); do not restore concurrently. Run {}".format(
                              lock, recovery_command(lock)))
                raise RestoreError("{} {} {}".format(article, operation, detail))

    def validate_input(self):
        if not self.root.is_dir():
            raise RestoreError("CHRONICLE_STATE_DIR does not exist: {}".format(self.root))
        if "\n" in self.container_path or "\r" in self.container_path:
            raise RestoreError("restore path must not contain control characters")
        try:
            host_path = resolve_host_path(self.backups, self.container_path)
        except RestoreError as error:
            print(str(error), file=sys.stderr)
            raise RestoreError("restore dump is unavailable or unsafe: " + self.container_path) from None
        if not host_path.stat().st_size:
            raise RestoreError("restore dump is empty: " + self.container_path)
        print("{}Restoring Chronicle from{} {}".format(BLD, RST, self.container_path))
        print("  Checking gzip integrity before stopping application services.")
        self.trust_dump(host_path)
        if self.mutation_started():
            raise RestoreError("an unresolved restore mutation marker exists; follow the restore recovery runbook")

    def mutation_started(self):
        try:
            self.mutation_marker.stat()
        except FileNotFoundError:
            self.mutation_marker.parent.stat()
            return False
        return True

    def outcome(self, phase):
        """The one phase rule for an interrupted restore, shared by --recover and rollback.

        restore.sh writes the mutation marker before its replacement transaction begins, and this
        process removes it only after recording database-restored or a rolled-back transaction.
        """
        if phase.database_restored:
            return RestoreOutcome.RESTORED
        return RestoreOutcome.UNCERTAIN if self.mutation_started() else RestoreOutcome.UNCHANGED

    def perform(self):
        self.validate_input()
        self.inspect_services()
        self.confirm()
        self.acquire_restore_lock()
        self.pin_input()
        self.stop_services()
        self.restore_database()
        self.complete()

    def complete(self):
        if self.no_start:
            write_text(self.root / STOP_MARKER, RESTORED_STOP)
            print("  Database restored; application services remain stopped because --no-start was used.")
        else:
            self.start()
        self.preserve = False
        if not self.release():
            self.preserve = True
            raise RestoreError("restore completed, but its operation lock could not be released")

    def inspect_services(self):
        services = self.require_dc("Docker Compose configuration is invalid", "--profile", "restore",
                                   "config", "--services", capture=True).split("\n")
        for name in ("postgres", "backend", "web", "restore"):
            if name not in services:
                raise RestoreError("Docker Compose configuration is missing required service: " + name)
        self.stopped = application_services(services)
        running = self.require_dc("could not inspect running Compose services", "--profile", "restore",
                                  "ps", "--status", "running", "--services", capture=True).split("\n")
        if "restore" in running:
            raise RestoreError("a one-shot restore container is already running; do not start another restore")
        self.previous = [name for name in self.stopped if name in running]

    def confirm(self, recovering=None):
        if self.assume_yes:
            return
        if not (sys.stdin.isatty() if self.terminal is None else self.terminal):
            raise RestoreError("confirmation requires a terminal; review the restore runbook, then repeat with --yes")
        question = {RestoreOutcome.RESTORED: _("Resume the completed restore without replaying its dump? [y/N] "),
                    RestoreOutcome.UNCHANGED: _("Release the interrupted restore and restart the unchanged database? [y/N] "),
                    None: "Stop Chronicle and replace its database with this dump? [y/N] "}[recovering]
        if input(question) not in ("y", "Y"):
            raise RestoreError("restore cancelled")

    def acquire_restore_lock(self):
        self.interlocks()
        try:
            publish_journal(self.lock, {"owner-pid": self.owner_pid + "\n", "restore-file": self.container_path + "\n",
                                        "phase": RestorePhase.PREPARED.value + "\n"})
        except FileExistsError:
            raise RestoreError("another restore is active or incomplete ({}). Run {}".format(
                self.lock, recovery_command(self.lock))) from None
        except OSError as error:
            raise RestoreError(OPERATION_LOCK_CREATE_ERROR.format(error)) from None
        self.held = True
        self.phase = RestorePhase.PREPARED
        self.interlocks(acquired=True)

    def pin_input(self):
        """Freeze the confirmed dump: restore.sh receives this private copy, never the mutable path."""
        print("  Rechecking the confirmed dump before stopping application services.")
        try:
            source = resolve_host_path(self.backups, self.container_path)
        except RestoreError as error:
            print(str(error), file=sys.stderr)
            raise RestoreError("restore dump is unavailable or unsafe: " + self.container_path) from None
        needed = source.stat().st_size
        disk = os.statvfs(self.backups)
        shortage = RestoreError("pinning the confirmed dump needs {} bytes free in {}; free space there and retry".format(
            needed, self.backups))
        if disk.f_bavail * disk.f_frsize < needed:
            raise shortage
        try:
            self.pinned = private_copy(source, self.backups)
        except OSError as error:
            if error.errno == errno.ENOSPC:
                raise shortage from None
            raise
        self.trust_dump(self.pinned)

    def stop_services(self):
        print("  Stopping application access and backup activity: " + " ".join(self.stopped))
        self.enter(RestorePhase.STOPPING_SERVICES)
        self.restart = True
        self.quiesce()
        self.preserve, self.restart = True, False

    def quiesce(self):
        self.require_dc("could not stop every application service; restore was not started", "stop", *self.stopped)
        running = self.require_dc("could not verify that application services stopped", "--profile", "restore",
                                  "ps", "--status", "running", "--services", capture=True).split("\n")
        for name in self.stopped:
            if name in running:
                raise RestoreError("Compose service '{}' is still running; restore was not started".format(name))
        if "restore" in running:
            raise RestoreError("a different one-shot restore container is running; restore was not started")

    def restore_database(self):
        self.enter(RestorePhase.RESTORING)
        args = ["run", "--rm", "-e", "CHRONICLE_RESTORE_ORCHESTRATED=true"]
        if self.rollback:
            args += ["-e", "CHRONICLE_RESTORE_ROLLBACK=true"]
        manifest = Path.cwd().parent / 'release-manifest.json'
        if manifest.is_file():
            args += ['-e', 'RELEASE_VERSION=' + json.loads(manifest.read_text())['release_version']]
        if self.pinned is None:  # pin_dump runs first (execute)
            raise RestoreError("the dump to restore was not pinned")
        args += ["-e", "CHRONICLE_RESTORE_TRUSTED_SHA256=" + self.digest,
                 "-e", "RESTORE_FILE=/backups/" + self.pinned.name, "restore"]
        status, _ = self.dc("--profile", "restore", *args)
        if status:
            if status == EXIT_RESTORE_TRANSACTION_ROLLED_BACK:
                self.mutation_marker.unlink(missing_ok=True)
                self.restart, self.preserve = True, False
                raise RestoreError("restore transaction was rolled back; the live database was preserved. Choose a newer backup or continue from the current release")
            if not self.mutation_started():
                self.restart, self.preserve = True, False
                raise RestoreError("restore failed before database mutation; the live database was preserved")
            raise RestoreError("database restore failed; Chronicle was deliberately left stopped")
        self.enter(RestorePhase.DATABASE_RESTORED)
        self.mutation_marker.unlink(missing_ok=True)

    def start(self):
        print("  Starting Chronicle (bounded health wait: {}s).".format(self.timeout))
        self.enter(RestorePhase.STARTING_SERVICES)
        configured, monitoring = self.roles("could not resolve the post-restore Compose services")
        startup = [service for service in configured if service != "ca-export"]
        if not startup:
            raise RestoreError("restore found no long-running services to start")
        try:
            start_split(compose, startup, monitoring, self.timeout, ("--remove-orphans", "--force-recreate"))
        except (OSError, subprocess.SubprocessError):
            self.stop_failed_start("post-restore startup failed", "startup failure",
                                   "database restored, but Chronicle did not return healthy")
        if "ca-export" in configured:
            status, _ = self.dc("run", "--rm", "--no-deps", "ca-export")
            if status:
                self.stop_failed_start("local CA export failed after restore", "CA export failure",
                                       "database restored, but Chronicle could not publish its local CA")
        self.enter(RestorePhase.VERIFIED)

    def stop_failed_start(self, warning, reason, error):
        warn(warning + "; stopping application services again")
        status, _ = self.dc("stop", *self.stopped, quiet=True)
        if status:
            warn("could not confirm every application service stopped after " + reason)
        raise RestoreError(error)

    def inspect_recovery(self):
        require(self.lock.is_dir() and not self.lock.is_symlink(), _("no safe restore lock to recover"))
        self.interlocks()
        for name in self.LOCK_FIELDS:
            require((self.lock / name).is_file() and not (self.lock / name).is_symlink(),
                    _("restore metadata is missing or unsafe; preserve the lock for review"))
        owner = (self.lock / "owner-pid").read_text().strip()
        require(owner.isdecimal() and int(owner) > 0, _("invalid restore owner PID; preserve the lock for review"))
        phase = RestorePhase((self.lock / "phase").read_text().strip())
        running = self.require_dc(_("could not inspect restore containers"), "--profile", "restore", "ps", "--all",
                                  "--status", "running", "--services", capture=True).splitlines()
        require("restore" not in running, _("a restore container is still running"))
        return phase

    def recover(self):
        outcome = self.outcome(self.inspect_recovery())
        require(outcome is not RestoreOutcome.UNCERTAIN,
                _("database outcome is uncertain; preserve the lock and mutation marker and follow the recovery runbook"))
        self.inspect_services()
        self.confirm(recovering=outcome)
        if self.no_start:
            self.quiesce()
        if outcome is RestoreOutcome.UNCHANGED:
            self.release_unchanged()
            return
        self.mutation_marker.unlink(missing_ok=True)
        from .dump import CATALOG_GATE_SQL
        from .release import postgres_sql
        container = self.require_dc(_("could not locate PostgreSQL"), "ps", "-q", "postgres", capture=True)
        require(container, _("PostgreSQL is unavailable; repair it before recovering the restore"))
        postgres_sql(container, CATALOG_GATE_SQL)
        self.held = self.preserve = True
        self.phase = RestorePhase.DATABASE_RESTORED
        self.write_lock("owner-pid", self.owner_pid)
        self.complete()

    def release_unchanged(self):
        """Interrupted before any database mutation: retire the lock and resume the services."""
        self.held = True
        require(self.release(), _("could not release restore lock {}").format(self.lock))
        if self.no_start:
            write_text(self.root / STOP_MARKER, "restore not applied; explicit up required\n")
        else:
            self.restart_services(self.stopped, _("restore lock released, but the application services did not start; run ./chronicle up"))
        self.completion = _("The database was not replaced; the interrupted restore stopped before changing it.")

    def execute(self, recover=False):
        status = 1
        operation_lock = None
        try:
            operation_lock = acquire_operation_lock(self.root)
            self.timeout = startup_timeout(self.timeout, "RESTORE_START_WAIT_TIMEOUT_SECONDS")
            if recover:
                self.recover()
            else:
                self.perform()
            status = 0
        except (RestoreError, OSError, EOFError, ValueError, KeyError) as error:
            print("{}error:{} {}".format(RED, RST, error), file=sys.stderr)
        except Interrupted as error:
            status = error.status
        finally:
            try:
                finish_operation("restore", status, "restore_failed", self.started)
                if status and self.held:
                    self.cleanup()
            finally:
                try:
                    if self.pinned:
                        self.pinned.unlink(missing_ok=True)
                finally:
                    release_operation_lock(operation_lock)
        if status == 0 and self.completion:
            print("{}Restore lock released.{} {}".format(GRN, RST, self.completion))
        elif status == 0:
            print("Restore took {} seconds.".format(int(time.monotonic() - self.started)))
            detail = ("The Chronicle application remains stopped." if self.no_start else
                      "Chronicle is healthy; run ./chronicle verify next.")
            print("{}Restore complete.{} {}".format(GRN, RST, detail))
        return status


def archive_rollback_settings(current, state, destination=None):
    private = state / OPERATOR_RECEIPTS_DIR
    require(not private.is_symlink(), "unsafe operator receipt directory")
    private.mkdir(mode=0o700, exist_ok=True)
    private.chmod(0o700)
    archived_env = Path(destination) if destination else private / f".env.rollback-{time.time_ns()}"
    require(not os.path.lexists(archived_env),
            "candidate .env.rollback already exists; archive it privately before retrying rollback")
    durable_replace(current / ".env", archived_env)
    return archived_env


# One decision: the pool listener's address, the sources it admits and its transport. guard-config.sh
# refuses an off-host bind without TLS or a recorded waiver, so rollback moves the candidate's group whole.
POOL_LISTENER_SETTINGS = frozenset({'HTTP_BIND', 'POOL_ALLOWED_IPS', 'CADDY_TRUSTED_PROXIES',
                                    'POOL_LISTENER_TLS', 'POOL_PLAINTEXT_WAIVER'})

ROLLBACK_PHASES = ('rollback-restore', 'rollback-restored', 'rollback-down',
                   'rollback-settings', 'rollback-owner', 'rollback-started', 'rollback-verified')


class Rollback:
    def __init__(self, previous, current, state, record, assume_yes):
        self.previous, self.current, self.state, self.record = previous, current, state, record
        self.assume_yes = assume_yes
        self.marker = state / UPGRADE_LOCK
        self.settings = read_env(previous / '.env')
        archive = Path(record.get('settings_archive', current / '.env'))
        current_env = current / '.env' if (current / '.env').exists() else archive
        require(current_env.is_file() and not current_env.is_symlink() and current_env.stat().st_mode & 0o777 == 0o600,
                'candidate settings must be a regular mode-0600 file')
        self.current_settings = read_env(current_env)
        require((current / value(self.current_settings, 'CHRONICLE_STATE_DIR', '.')).resolve() == state,
                'rollback state location differs')
        self.project = compose_project(self.settings)
        require(self.project == compose_project(self.current_settings),
                'rollback projects differ')

    def save(self, phase):
        self.record['phase'] = phase
        write_json(self.marker / RECOVERY_FILE, self.record)

    def restore_database(self):
        if self.record.get('restore_into') == 'previous':
            # The releases use different database volumes (a PostgreSQL major update): the dump is
            # restored into the previous release's own database just before it starts.
            print('The previous release uses its own database volumes; the dump is restored into them before it starts.')
            return
        if self.record.get('fresh_database'):
            # A PostgreSQL major update loaded the dump into new volumes and never touched the old
            # ones; the previous release starts on those, so there is nothing to restore. A restore
            # into the new volumes that was interrupted is abandoned with them.
            if (self.state / RESTORE_LOCK).exists():
                abandoned = Restore(self.state, str(self.state / 'backups'), self.record.get('dump', ''), self.record.get('sha256', ''),
                                    DEFAULT_STARTUP_TIMEOUT_SECONDS, True, True, recovery_owner=str(self.current))
                abandoned.held = True
                require(abandoned.release(), 'could not retire the interrupted restore into the new database volumes')
                abandoned.mutation_marker.unlink(missing_ok=True)
            print('Rollback keeps the previous release\'s own database volumes; no restore is needed.')
            return
        self.restore_dump()

    def restore_dump(self):
        """Restore the rollback dump with the release in the working directory (Compose reads it)."""
        operation = Restore(self.state, str(self.state / 'backups'), self.record['dump'],
                            self.record['sha256'], os.environ.get('RESTORE_START_WAIT_TIMEOUT_SECONDS', DEFAULT_STARTUP_TIMEOUT_SECONDS),
                            True, self.assume_yes, recovery_owner=str(self.current), rollback=True,
                            target_version=(json.loads((self.previous.parent / 'release-manifest.json').read_text())['release_version']
                                            if (self.previous.parent / 'release-manifest.json').is_file() else None))
        if operation.lock.exists():
            outcome = operation.outcome(operation.inspect_recovery())
            operation.held = True
            require(operation.release(), 'could not retire interrupted restore lock')
            operation.mutation_marker.unlink(missing_ok=True)
            if outcome is RestoreOutcome.RESTORED:
                return
            # Unchanged or uncertain: replay the same reviewed dump. The SQL replacement is
            # transactional; its continuity proof checks live restrictions again before committing.
        require(operation.execute() == 0, 'automatic rollback restore failed; retain recovery state')

    def stop_candidate(self):
        compose('down', '--remove-orphans', check=True)
        # Volumes this update's candidate created (its secrets, a new major's database) go with
        # it, so a retried update starts from the same host state as the first attempt.
        created = self.record.get('created_volumes') or []
        if created:
            from .common import run
            result = run(['docker', 'volume', 'rm', '--force', *created], capture=True, timeout=120)
            if result.returncode:
                warn('could not remove the volumes the rolled-back release created ({}); remove them with '
                     'docker volume rm before the next update'.format(', '.join(created)))

    def restore_previous_database(self):
        """Restore the dump into the previous release's database volumes, through its own files."""
        from .env_migration import running_selection
        origin, selection = Path.cwd(), os.environ.get('COMPOSE_FILE')
        os.chdir(self.previous)
        os.environ['COMPOSE_FILE'] = ':'.join(running_selection(read_env(self.previous / '.env'), self.previous))
        try:
            self.restore_dump()
        finally:
            os.chdir(origin)
            if selection is None:
                os.environ.pop('COMPOSE_FILE', None)
            else:
                os.environ['COMPOSE_FILE'] = selection
        stop = self.state / STOP_MARKER
        if stop.is_file() and stop.read_text() == RESTORED_STOP:
            from .upgrade import ROLLBACK_STOP
            write_text(stop, ROLLBACK_STOP)  # the rollback starts the release itself next

    def transfer_settings(self):
        from .env_migration import merge_env, running_selection
        for key in POOL_LISTENER_SETTINGS - self.current_settings.keys():
            self.settings.pop(key, None)
        self.settings.update({key: raw for key, raw in self.current_settings.items()
                              if key in POOL_LISTENER_SETTINGS
                              or key.endswith(('_PASSWORD', '_SECRET', '_SECRET_PREVIOUS', '_BIND', '_ALLOWED_IPS'))
                              or key in {'DASHBOARD_PASSWORD_HASH', 'JWT_SECRET_PREVIOUS_EXPIRES_AT'}
                              or key.startswith('BACKUP_KEEP_') or key == 'PRE_OP_BACKUP_KEEP_DAYS'
                              or key.startswith(('MOBILE_SIGNING_', 'CHRONICLE_REVIEWER_'))})
        merge_env(self.settings, (self.previous / '.env.example').read_text(), self.previous / '.env',
                  self.state, running_selection(self.settings, self.previous), preserve_images=True)
        archive = self.record.get('settings_archive')
        if archive is None:
            archive = str(self.state / OPERATOR_RECEIPTS_DIR / f'.env.rollback-{time.time_ns()}')
            self.record['settings_archive'] = archive
            self.save(self.record['phase'])
        if (self.current / '.env').exists():
            archive_rollback_settings(self.current, self.state, archive)

    def transfer_owner(self):
        """Ownership is mandatory (read back); the crontab only warns, so the previous release
        still starts and serves on a host whose crontab cannot be written (UPD-N1)."""
        from .reconcile import install_after_transfer
        from .release import current_owner, set_current_owner
        set_current_owner(self.previous, self.state)
        require(current_owner(self.state) == self.previous.resolve(),
                f'could not record {self.previous} as the owning release')
        install_after_transfer(self.previous / 'chronicle', self.state, self.project, update_only=True)

    def start_previous(self):
        from .env_migration import running_selection
        from .upgrade import start_release
        if self.record.get('restore_into') == 'previous':
            self.restore_previous_database()
        settings = read_env(self.previous / '.env')
        start_release(self.previous, self.project, running_selection(settings, self.previous),
                      value(settings, 'START_WAIT_TIMEOUT_SECONDS', DEFAULT_STARTUP_TIMEOUT_SECONDS))

    def report_readiness(self):
        """After the commit: services the start did not wait on (db-backup's first dump). Only reports."""
        from .env_migration import running_selection
        from .upgrade import report_release_readiness
        try:
            names = running_selection(read_env(self.previous / '.env'), self.previous)
        except (OSError, ValueError) as error:
            warn(f'could not read the previous release\'s settings ({error}); ./chronicle doctor reports its services')
            return
        report_release_readiness(self.previous, self.project, names)

    def verify_previous(self):
        # An update's journal carries its pre-update baseline; a manual rollback's has none (strict).
        from .upgrade import verify_release
        verify_release(self.previous / 'chronicle', self.record.get('baseline', []))

    def execute(self):
        from .ingress import close_ingress, open_ingress
        from .upgrade import COMMITTED, ROLLBACK_STOP, clear_recovery, settle_failed_recovery
        close_ingress(self.state)
        if not os.path.lexists(self.state / STOP_MARKER):  # An operator's own pause outlives the rollback.
            write_text(self.state / STOP_MARKER, ROLLBACK_STOP)
        os.environ.update(CHRONICLE_OPS_STATE=str(self.state), CHRONICLE_OPS_PROJECT=self.project,
                          CHRONICLE_OPS_BACKUPS=str(self.state / 'backups'),
                          COMPOSE_FILE=value(self.current_settings, 'COMPOSE_FILE'))
        steps = (self.restore_database, self.stop_candidate, self.transfer_settings,
                 self.transfer_owner, self.start_previous, self.verify_previous)
        index = ROLLBACK_PHASES.index(self.record['phase'])
        try:
            for position in range(index, len(steps)):
                steps[position]()
                self.save(ROLLBACK_PHASES[position + 1])
        except BaseException:
            settle_failed_recovery(self.state)
            raise
        self.record['owner'] = str(self.previous)
        self.save(COMMITTED)
        open_ingress(self.state)
        (self.state / STOP_MARKER).unlink(missing_ok=True)
        clear_recovery(self.marker)
        self.report_readiness()
        return 0


def announce_discarded_data(backups, dump):
    """A rollback after commit replaces live data with an older dump: say how old, before anything changes."""
    try:
        written = resolve_host_path(backups, dump).stat().st_mtime
    except RestoreError as error:
        warn("cannot date rollback dump {} ({}); the restore step checks it again".format(dump, error))
        return
    age = max(0, int(time.time() - written))
    print("{}Rollback replaces the database with {}{}, written {} ({} d {} h ago).".format(
        BLD, dump, RST, datetime.fromtimestamp(written, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        age // 86400, age % 86400 // 3600))
    print("  Data written since then is discarded, including participant uploads and new enrollments;")
    print("  withdrawals and erasures recorded since then stay in force. The restore first saves the")
    print("  current database to backups/pre-restore-*.sql.gz.")


def database_moved(previous, current, project):
    """Whether the two releases keep PostgreSQL in different volumes (a major update): a rollback
    then restores into the previous release's volumes, which it starts on, not the current ones."""
    from .env_migration import running_selection
    from .release import compose_release
    from .upgrade import database_volumes
    volumes = []
    for directory in (previous, current):
        names = running_selection(read_env(directory / '.env'), directory)
        config = compose_release(directory, project, names, 'config', '--format', 'json', capture=True, check=True).stdout
        volumes.append(database_volumes(json.loads(config)))
    return volumes[0] != volumes[1]


def rollback(source, dump, digest, assume_yes=False):
    from .release import require_current_owner
    from .reconcile import ENABLED_ENV
    old, current = Path(source).resolve(), Path.cwd().resolve()
    require(old != current, 'rollback --from must name the previous release')
    require((old / 'chronicle_ops/__main__.py').is_file(), 'rollback requires the current operator package')
    require((old / '.env').is_file() and not (old / '.env').is_symlink()
            and (old / '.env').stat().st_mode & 0o777 == 0o600, 'previous settings must be regular mode-0600')
    settings = read_env(old / '.env')
    state = (old / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve()
    descriptor = acquire_operation_lock(state)
    try:
        marker = state / UPGRADE_LOCK
        resuming = (marker / RECOVERY_FILE).exists()
        if resuming:
            record = json.loads((marker / RECOVERY_FILE).read_text())
            require(same_path(record['previous'], old) and same_path(record['owner'], current),
                                    'rollback recovery owner differs')
        else:
            require_current_owner(current, state, compose_project(settings))
            announce_discarded_data(state / 'backups', dump)
            record = dict(previous=str(old), owner=str(current), phase=ROLLBACK_PHASES[0])
            if database_moved(old, current, compose_project(settings)):
                record['restore_into'] = 'previous'
        if record['phase'] not in ROLLBACK_PHASES:
            record['phase'] = ROLLBACK_PHASES[0]
        record.update(dump=dump, sha256=digest)
        if resuming:
            write_json(marker / RECOVERY_FILE, record)
        else:
            publish_journal(marker, {RECOVERY_FILE: json_text(record)})
        os.environ.setdefault(ENABLED_ENV, value(settings, ENABLED_ENV, 'true'))
        return Rollback(old, current, state, record, assume_yes).execute()
    finally:
        release_operation_lock(descriptor)
