"""Entry point for the installed selfhost package."""

import argparse
from gettext import gettext as _
import os
import signal
import sys
import time

from .common import Interrupted, interrupted
from .dump import canonical_digest
from .receipts import finish_operation, record_operation, write_operation_receipt, write_text
from .restore import Restore
from .startup import DEFAULT_STARTUP_TIMEOUT_SECONDS


def argument_parser():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    restore = commands.add_parser("restore")
    restore.add_argument("--yes", action="store_true")
    restore.add_argument("--no-start", action="store_true")
    restore.add_argument("--recover", action="store_true")
    restore.add_argument("--trusted-sha256", default=None, type=canonical_digest)
    restore.add_argument("dump", nargs="?", default="")
    child = commands.add_parser("rollback")
    child.add_argument("--from", dest="source", required=True)
    child.add_argument("--trusted-sha256", required=True, type=canonical_digest)
    child.add_argument("--yes", action="store_true")
    child.add_argument("dump")
    verify = commands.add_parser("verify")
    verify.add_argument("--dashboard-password", action="store_true")
    for command in ("record-operation", "write-operation-receipt"):
        child = commands.add_parser(command)
        child.add_argument("operation")
        child.add_argument("outcome")
        child.add_argument("category", nargs="?", default="none")
        if command == "write-operation-receipt":
            child.add_argument("duration", nargs="?", default="0", type=int)
    child = commands.add_parser("reconcile")
    child.add_argument("action", nargs="?", choices=("install", "uninstall", "stop", "resume", "preflight", "host", "lock-path", "check", "check-start", "stopped"), default="install")
    commands.add_parser("owner-check")
    commands.add_parser("setup-env")
    commands.add_parser("setup-storage")
    child = commands.add_parser("host-memory")
    child.add_argument("action", choices=("check", "monitoring-default", "logging", "ceilings"))
    child = commands.add_parser("record-source-images")
    child.add_argument("--backend-image", required=True)
    child.add_argument("--frontend-image", required=True)
    child.add_argument("--caddy-image", required=True)
    child = commands.add_parser("update")
    child.add_argument("--check", action="store_true")
    child.add_argument("--apply-from", help=argparse.SUPPRESS)
    child.add_argument("version", nargs="?", type=lambda text: text.removeprefix("v"))
    child = commands.add_parser("cleanup")
    child.add_argument("--releases-dir", required=True)
    child.add_argument("--apply", action="store_true")
    child = commands.add_parser("storage-check")
    commands.add_parser("update-reserve")
    child = commands.add_parser("public-check")
    child = commands.add_parser("backup-storage")
    commands.add_parser("database-storage")
    commands.add_parser("backup-footprint")
    commands.add_parser("database-privileges")
    child = commands.add_parser("certificates")
    child.add_argument("action", choices=("digest", "compare", "record"))
    child = commands.add_parser("compose-services")
    child.add_argument("role", choices=("core", "monitoring"))
    child = commands.add_parser("start-monitoring")
    child.add_argument("--force-recreate", action="store_true")
    child.add_argument("--no-recreate", action="store_true")
    commands.add_parser("monitoring-health")
    commands.add_parser("config-drift")
    child = commands.add_parser("alerts")
    child.add_argument("--syslog", action="store_true")
    commands.add_parser("host-versions")
    commands.add_parser("host-architecture")
    child = commands.add_parser("operation-lock")
    child.add_argument("--state")
    child.add_argument("--nonblocking", action="store_true")
    child.add_argument("args", nargs=argparse.REMAINDER)
    return parser


def run_operation_lock(options):
    from .common import acquire_operation_lock, LOCK_FD_ENV
    from .envfile import read_env, value
    from .common import require
    from pathlib import Path
    # Read only the state location to bootstrap locking; the child reloads settings under it.
    state = options.state
    if state is None:
        path = Path.cwd() / ".env"
        require(path.is_file() and not path.is_symlink(), ".env must be a regular file")
        require(path.stat().st_mode & 0o777 == 0o600, ".env must have mode 0600")
        state = value(read_env(path), "CHRONICLE_STATE_DIR", ".") or "."
    command = options.args[1:] if options.args[:1] == ["--"] else options.args
    require(command, "operation-lock requires a command")
    try:
        acquire_operation_lock(state, blocking=not options.nonblocking)
    except BlockingIOError:
        return 0
    os.environ["CHRONICLE_OPS_STATE"] = str(Path(state).resolve())
    os.set_inheritable(int(os.environ[LOCK_FD_ENV]), True)
    os.execvp(command[0], command)


def run_verify(options):
    from .verify import verify
    from .common import acquire_operation_lock, release_operation_lock
    status = 1
    started = time.monotonic()
    descriptor = None
    try:
        descriptor = acquire_operation_lock(os.environ["CHRONICLE_OPS_STATE"])
        status = verify(["--dashboard-password"] if options.dashboard_password else [])
        if status == 0 and descriptor is not None:
            from .reconcile import complete_recovery
            complete_recovery()
    except Interrupted as error:
        status = error.status
    finally:
        release_operation_lock(descriptor)
        finish_operation("verify", status, "verification_failed", started)
    return status


def run_reconcile(options):
    from .reconcile import install, preflight, check_mutations, STOP_MARKER
    from .common import OPERATION_LOCK
    from pathlib import Path
    state = Path(os.environ["CHRONICLE_OPS_STATE"])
    if options.action == "stopped":
        return 0 if (state / STOP_MARKER).exists() else 1
    if options.action == "lock-path":
        print(state / OPERATION_LOCK)
    elif options.action in ("check", "check-start"):
        check_mutations(state, Path.cwd(), allow_forward=options.action == "check-start")
    elif options.action == "preflight":
        preflight()
    elif options.action == "host":
        # Doctor's row: why an enabled schedule cannot run here, or nothing.
        from .reconcile import SCHEDULE_PENDING, is_enabled, unavailable
        reason = is_enabled() and unavailable()
        if not reason and is_enabled() and (state / SCHEDULE_PENDING).is_file():
            reason = "the last update or rollback could not write the operator crontab, so the schedule may still start the previous release"
        if reason:
            print(reason)
    elif options.action == "install":
        # Only setup reaches this action (the CLI accepts stop|uninstall) and it may precede the first
        # start; update installs after a verified start through reconcile.install directly.
        install(Path.cwd() / "chronicle", state, os.environ["CHRONICLE_OPS_PROJECT"], before_first_start=True)
    elif options.action == "uninstall":
        from .reconcile import uninstall
        uninstall(state, os.environ["CHRONICLE_OPS_PROJECT"])
    elif options.action == "stop":
        write_text(state / STOP_MARKER, "")
    else:
        (state / STOP_MARKER).unlink(missing_ok=True)
        # A host that gained cron since setup (or since a skipped install), or whose crontab an
        # update or rollback could not write (SCHEDULE_PENDING), gets its schedule here.
        from .reconcile import SCHEDULE_PENDING, is_enabled, unavailable
        pending = state / SCHEDULE_PENDING
        if is_enabled() and (pending.exists() or not (state / "reconcile.sh").exists()) and not unavailable():
            install(Path.cwd() / "chronicle", state, os.environ["CHRONICLE_OPS_PROJECT"])
            pending.unlink(missing_ok=True)
    return 0


def run_certificates(options):
    from .release import certificate_digest, certificates_changed, record_applied_certificates
    state = os.environ["CHRONICLE_OPS_STATE"]
    if options.action == "digest":
        print(certificate_digest(state))
    elif options.action == "compare":
        print("changed" if certificates_changed(state, sys.stdin.read()) else "unchanged")
    else:
        record_applied_certificates(state, sys.stdin.read().rstrip("\n"))
    return 0


def run_services(options):
    """The launcher's view of services.py: one classification for bash and Python."""
    from .common import compose, warn
    from .services import environment_monitoring, environment_roles, monitoring_health, start_monitoring
    import subprocess
    if options.command == "monitoring-health":
        for service, state in monitoring_health():
            print(service + "\t" + state)
        return 0
    try:
        if options.command == "compose-services" and options.role == "monitoring":
            core, monitoring = [], environment_monitoring()  # No Compose call when the overlay is off.
        else:
            core, monitoring = environment_roles()
    except (OSError, subprocess.SubprocessError) as error:
        if options.command == "start-monitoring":
            warn(f"could not resolve the monitoring services ({error}); run ./chronicle doctor")
            return 0
        raise ValueError(f"could not resolve the Compose service list: {error}") from None
    if options.command == "compose-services":
        print("\n".join(core if options.role == "core" else monitoring))
        return 0
    start_monitoring(compose, monitoring, [flag for flag, chosen in (("--force-recreate", options.force_recreate),
                                                                     ("--no-recreate", options.no_recreate)) if chosen])
    return 0


def run_settings_command(options):
    if options.command == "owner-check":
        from .release import require_current_owner
        from pathlib import Path
        require_current_owner(Path.cwd(), os.environ["CHRONICLE_OPS_STATE"], os.environ["CHRONICLE_OPS_PROJECT"])
    elif options.command == "record-source-images":
        from .release import record_source_images
        record_source_images({"BACKEND_IMAGE": options.backend_image,
                              "SELFHOST_FRONTEND_IMAGE": options.frontend_image,
                              "CADDY_IMAGE": options.caddy_image})
    elif options.command == "reconcile":
        return run_reconcile(options)
    elif options.command == "cleanup":
        from .release import cleanup_releases
        from .common import acquire_operation_lock, release_operation_lock
        descriptor = acquire_operation_lock(os.environ["CHRONICLE_OPS_STATE"])
        try:
            cleanup_releases(options.releases_dir, os.environ["CHRONICLE_OPS_STATE"], options.apply)
        finally:
            release_operation_lock(descriptor)
    elif options.command == "storage-check":
        from .common import require_storage
        from .release import free_disk_floor
        require_storage(os.environ["CHRONICLE_OPS_STATE"], os.environ["CHRONICLE_OPS_PROJECT"], free_disk_floor({}))
    elif options.command == "public-check":
        from .verify import verify_public_origin
        from .envfile import read_env, value
        from pathlib import Path
        settings = read_env(Path.cwd() / ".env")
        return verify_public_origin(value(settings, "CHRONICLE_PUBLIC_BASE_URL") or "https://" + value(settings, "DOMAIN"))
    elif options.command == "setup-storage":
        from .setup_env import confirm_storage_encryption
        confirm_storage_encryption()
    elif options.command == "backup-storage":
        from .verify import STORAGE_ENCRYPTION_WAIVER, verify_backup_storage
        from .envfile import read_env, value
        from pathlib import Path
        return verify_backup_storage(os.environ["CHRONICLE_OPS_BACKUPS"],
                                     value(read_env(Path.cwd() / ".env"), STORAGE_ENCRYPTION_WAIVER))
    elif options.command == "database-storage":
        from .verify import STORAGE_ENCRYPTION_WAIVER, verify_database_storage
        from .envfile import read_env, value
        from pathlib import Path
        return verify_database_storage(os.environ["CHRONICLE_OPS_PROJECT"],
                                       value(read_env(Path.cwd() / ".env"), STORAGE_ENCRYPTION_WAIVER))
    elif options.command == "backup-footprint":
        from .common import RST, YEL
        from .envfile import read_env
        from .verify import backup_footprint
        from pathlib import Path
        _, status, message, action = backup_footprint(read_env(Path.cwd() / ".env"), os.environ["CHRONICLE_OPS_BACKUPS"])
        print(f"Backup disk: {message}" if status == "ok" else f"{YEL}WARNING{RST} backup disk: {message}\n  {action}")
    elif options.command == "database-privileges":
        from .verify import verify_database_privileges
        status, message = verify_database_privileges()
        print(message)
        return status
    elif options.command == "certificates":
        return run_certificates(options)
    elif options.command == "update-reserve":
        from .verify import update_reserve
        return update_reserve()
    elif options.command == "host-versions":
        from .host_versions import check
        return check()
    elif options.command == "host-architecture":
        from .host_versions import architecture_check
        return architecture_check()
    elif options.command == "alerts":
        from .alerts import command
        return command(options.syslog)
    elif options.command == "config-drift":
        from .services import config_drift_row
        print("\x1f".join(config_drift_row()))
        return 0
    elif options.command in ("compose-services", "start-monitoring", "monitoring-health"):
        return run_services(options)
    elif options.command == "record-operation":
        record_operation(options.operation, options.outcome, options.category)
    else:
        write_operation_receipt(options.operation, options.outcome, options.category, options.duration)
    return 0


def main(args=None):
    options = argument_parser().parse_args(args)
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    if options.command == "operation-lock":
        return run_operation_lock(options)
    if options.command == "setup-env":
        from .setup_env import write_setup_environment
        write_setup_environment()
        return 0
    if options.command == "host-memory":
        from .host_memory import host_memory
        return host_memory(options.action)
    if options.command == "restore":
        if options.recover and (options.dump or options.trusted_sha256):
            raise ValueError(_("restore --recover resumes the committed database; do not supply a dump or digest"))
        return Restore(os.environ["CHRONICLE_OPS_STATE"], os.environ["CHRONICLE_OPS_BACKUPS"],
                       options.dump, options.trusted_sha256 or "",
                       os.environ.get("RESTORE_START_WAIT_TIMEOUT_SECONDS", os.environ.get("START_WAIT_TIMEOUT_SECONDS", DEFAULT_STARTUP_TIMEOUT_SECONDS)),
                       options.no_start, options.yes).execute(recover=options.recover)
    if options.command == "rollback":
        from .restore import rollback
        return rollback(options.source, options.dump, options.trusted_sha256 or "", options.yes)
    if options.command == "update":
        from .update import apply_candidate, update
        if options.apply_from:
            return apply_candidate(options.apply_from)
        return update(options.check, options.version)
    if options.command == "verify":
        return run_verify(options)
    return run_settings_command(options)


def run_cli(args=None):
    args = sys.argv[1:] if args is None else args
    try:
        return main(args)
    except (OSError, ValueError) as error:
        print("error: " + str(error), file=sys.stderr)
        return 1
    except Interrupted as error:
        print("error: " + str(error), file=sys.stderr)
        return error.status


if __name__ == "__main__":
    sys.exit(run_cli())
