"""Install an operator-owned reconciliation schedule without replacing other cron jobs."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess

from .common import compose_project, run, same_path
from .receipts import SCHEDULED_OPERATIONS, write_text

INTERVAL_MINUTES = 15
STOP_MARKER = ".chronicle-stopped"
RECOVERY_PHASE = "migration-started"
RECOVERY_FILE = "recovery.json"
UPGRADE_LOCK = ".chronicle-upgrade.lock"
# One operator crontab serves every deployment of this user; each edit is a read-modify-write.
CRONTAB_LOCK = ".chronicle-crontab.lock"
RESTORE_LOCK = ".chronicle-restore.lock"
ROTATION_MARKER = ".chronicle-secret-rotation"
# Every operation that leaves a recovery marker in the state directory while it mutates it.
MUTATION_MARKERS = (RESTORE_LOCK, UPGRADE_LOCK, ROTATION_MARKER)
RECOVERY_COMMANDS = {
    RESTORE_LOCK: "./chronicle restore --recover from the active release "
                  "(docs/BACKUP-RESTORE.md#interrupted-restore-recovery)",
    ROTATION_MARKER: "./chronicle rotate-secret recover --forward or --rollback (docs/SECRET-ROTATION.md)",
}
ENABLED_ENV = "CHRONICLE_RECONCILE_ENABLED"
# An update or rollback that could not write the crontab leaves this; the next `./chronicle up`
# installs the schedule and removes it (__main__.run_reconcile).
SCHEDULE_PENDING = ".chronicle-schedule-pending"
UPDATE_LOG = "reconcile.update.log"
SCHEDULED_UPDATE = "update-check"
SCHEDULED_RECONCILE = "reconcile"
if SCHEDULED_OPERATIONS != {SCHEDULED_UPDATE, SCHEDULED_RECONCILE}:  # receipts.py prunes these names
    raise ImportError("receipts.SCHEDULED_OPERATIONS must name the scheduled operations")


def is_enabled():
    return os.environ.get(ENABLED_ENV, "true") == "true"


def saved_enabled(directory):
    from .envfile import read_env, value
    return value(read_env(Path(directory) / ".env"), ENABLED_ENV, "true") == "true"


def record_scheduled(operation, status):
    from .envfile import read_env, value
    from .receipts import record_operation, write_operation_receipt
    from .release import UPDATE_AVAILABLE_EXIT
    if operation not in SCHEDULED_OPERATIONS:
        raise ValueError("unknown scheduled operation")
    settings = read_env(Path.cwd() / ".env")
    os.environ["COMPOSE_FILE"] = value(settings, "COMPOSE_FILE")
    os.environ["CHRONICLE_OPS_PROJECT"] = compose_project(settings)
    os.environ["CHRONICLE_OPS_VERSION"] = value(settings, "RELEASE_VERSION", "unknown")
    status = int(status)
    outcome, category = "success", "none"
    if operation == SCHEDULED_UPDATE and status == UPDATE_AVAILABLE_EXIT:
        category = "update_available"
    elif status:
        outcome, category = "failure", operation.replace("-", "_") + "_failed"
    write_operation_receipt(operation, outcome, category)
    record_operation(operation, outcome, category)


def unavailable():
    """Why this host cannot run the operator crontab schedule, or None when it can."""
    if platform.system() != "Linux":
        return "automatic reconciliation requires a Linux operator crontab"
    if any(shutil.which(tool) is None for tool in ("crontab", "logger", "systemctl")):
        return "reconciliation requires crontab, logger and systemctl; install cron/cronie or explicitly disable reconciliation"
    if not any(run(["systemctl", "is-enabled", service], quiet=True).returncode == 0
               and run(["systemctl", "is-active", service], quiet=True).returncode == 0
               for service in ("cron", "crond")):
        return "reconciliation requires an enabled, active cron/crond service"
    return None


def warn_unavailable(reason):
    from .common import warn
    warn(f"automatic reconciliation is unavailable: {reason}. Chronicle keeps running, but nothing "
         "restarts it after a reboot or a failed container. Install and enable cron (cron or cronie); "
         f"the next ./chronicle up or update installs the schedule. Or set {ENABLED_ENV}=false in .env.")


def preflight():
    """Warn, never refuse: a host without Linux cron (a macOS trial, a minimal image) still runs
    Chronicle and its updates; it only lacks the boot and periodic restart."""
    if not is_enabled():
        return None
    reason = unavailable()
    if reason:
        warn_unavailable(reason)
    return reason


def recovery_command(marker):
    """The one supported command that resumes or settles the operation recorded at marker."""
    if marker.name != UPGRADE_LOCK:
        return RECOVERY_COMMANDS[marker.name]
    try:
        previous = json.loads((marker / RECOVERY_FILE).read_text())["previous"]
    except (OSError, ValueError, KeyError, TypeError):
        return "./chronicle update from the previous release directory (docs/UPGRADE-ROLLBACK.md)"
    return f"./chronicle update from {previous}"


def is_empty_marker(marker):
    """Whether marker is a directory provably holding no file; one that cannot be listed (an
    interrupted sudo run leaves it root-owned 0700) is not, so it is kept and refused."""
    if not marker.is_dir() or marker.is_symlink():
        return False
    try:
        return not any(marker.iterdir())
    except OSError:
        return False


def clear_empty_markers(state):
    """Remove markers an interrupted operation left before writing its first journal file.

    2026.10.23 setup, restore and rollback created their marker with mkdir and only then wrote
    their journal, and rotation still does (rotate-secret.sh begin_transaction); none of them
    changes anything before that first file. Only the shared operation lock holder may decide
    that no operation is running, and rmdir refuses a directory that holds any file, so a
    journal is never removed."""
    from .common import holds_operation_lock, warn
    if not holds_operation_lock(state):
        return
    for name in MUTATION_MARKERS:
        marker = Path(state) / name
        if is_empty_marker(marker):
            try:
                marker.rmdir()
            except OSError:
                continue
            warn(f"cleared the empty marker {marker} left by an interrupted operation; it recorded no changes")


def check_mutations(state, launcher, allow_forward=False):
    clear_empty_markers(state)
    for name in MUTATION_MARKERS:
        marker = Path(state) / name
        if not os.path.lexists(marker):
            continue
        if is_empty_marker(marker):
            raise ValueError(f"empty marker {marker} from an interrupted operation that recorded no changes; "
                             "./chronicle up clears it")
        if allow_forward and name == UPGRADE_LOCK and os.environ.get("CHRONICLE_RECONCILE_RUN") != "true":
            try:
                recovery = json.loads((marker / RECOVERY_FILE).read_text())
                if same_path(recovery["owner"], launcher) and recovery["phase"] == RECOVERY_PHASE:
                    continue
            except (OSError, ValueError, KeyError):
                pass
        raise ValueError(f"incomplete operation at {marker}; run {recovery_command(marker)}")


def crontab_without_project(project):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
        raise ValueError("invalid reconciliation project")
    current = run(["crontab", "-l"], capture=True, stderr=subprocess.PIPE,
                  env=dict(os.environ, LC_ALL="C"))
    if current.returncode and (current.returncode != 1 or "no crontab" not in current.stderr.lower()):
        raise ValueError("could not read the operator crontab")
    marker = "# chronicle-reconcile:" + project
    lines = current.stdout.splitlines()
    kept = [line for line in lines if not line.endswith(marker)]
    return kept, marker, len(kept) != len(lines)


@contextmanager
def crontab_transaction():
    """Hold the user's crontab lock, so two deployments editing it never drop each other's jobs."""
    descriptor = os.open(Path.home() / CRONTAB_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def write_crontab(lines):
    # cronie 1.7 (Alpine, Fedora) backs up the previous crontab to $XDG_CACHE_HOME/crontab, by
    # default ~/.cache/crontab, creating only that last directory: on an account with no ~/.cache
    # it printed "mkdir: No such file or directory" and kept no backup. Create the base directory
    # as the XDG base-directory specification asks of whoever writes there (0700).
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    try:
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        from .common import warn
        warn(f"could not create {cache} for crontab's backup of the previous schedule: {error}")
    # Output is kept: on success it is only cronie's backup notice, on failure the reason.
    result = run(["crontab", "-"], input="\n".join(lines) + "\n", capture=True, stderr=subprocess.PIPE)
    if result.returncode:
        reason = " ".join(part.strip() for part in (result.stderr, result.stdout) if part and part.strip())
        raise ValueError("could not write the operator crontab; check `crontab -l` and rerun this command"
                         + (f" (crontab: {reason})" if reason else ""))


def uninstall(state, project):
    write_text(Path(state) / STOP_MARKER, "uninstalled reconciliation\n")
    if shutil.which("crontab"):
        with crontab_transaction():
            lines, _, _ = crontab_without_project(project)
            write_crontab(lines)
    (Path(state) / "reconcile.sh").unlink(missing_ok=True)


def schedule_blocker(launcher, state, script, update_only):
    if platform.system() != "Linux":
        return "automatic reconciliation requires a Linux operator crontab"
    if not update_only and any(shutil.which(tool) is None for tool in ("crontab", "logger")):
        return "reconciliation requires crontab and logger on PATH"
    if script.is_symlink():
        return f"unsafe reconciliation launcher {script} is a symlink; replace it with nothing and rerun"
    for path in (launcher, state):
        if any(char in str(path) for char in "\r\n%"):
            return f"reconciliation path {path} contains cron control characters; move the release"
    return None


def install(launcher, state, project, update_only=False, before_first_start=False):
    from .release import UPDATE_AVAILABLE_EXIT, set_current_owner
    launcher, state = Path(launcher).resolve(), Path(state).resolve()
    set_current_owner(launcher.parent, state)
    if not is_enabled():
        uninstall(state, project)
        return
    script = state / "reconcile.sh"
    if update_only and not script.exists():
        return
    reason = schedule_blocker(launcher, state, script, update_only)
    if reason:
        # Ownership already moved; only the schedule is skipped, and the crontab is left as it was.
        warn_unavailable(reason)
        return
    quote = shlex.quote
    docker_environment = "\n".join(f"export {key}={quote(os.environ[key])}"
                                   for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
                                   if key in os.environ)
    content = f'''#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH={quote(os.environ.get("PATH", "/usr/bin:/bin"))}
{docker_environment}
cd {quote(str(launcher.parent))}
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH={quote(str(launcher.parent))}
export CHRONICLE_OPS_STATE={quote(str(state))}
enabled=$(python3 -c 'from chronicle_ops.reconcile import saved_enabled; print(str(saved_enabled(".")).lower())')
[[ "$enabled" == true ]] || exit 0
record_status() {{
  python3 -c 'from chronicle_ops.reconcile import record_scheduled; import sys; record_scheduled(*sys.argv[1:])' "$@"
}}
export -f record_status
if [[ "${{1:-}}" == --check-updates ]]; then
  update_status=0
  ./chronicle update --check >{quote(str(state / UPDATE_LOG))} 2>&1 || update_status=$?
  record_status {quote(SCHEDULED_UPDATE)} "$update_status"
  python3 -m chronicle_ops update-reserve >>{quote(str(state / UPDATE_LOG))} 2>&1 ||
    logger -p user.warning -t chronicle 'Free disk is below what the next update needs; run ./chronicle doctor'
  case "$update_status" in
    0) exit 0 ;;
    {UPDATE_AVAILABLE_EXIT}) logger -p user.warning -t chronicle 'Chronicle update available; run ./chronicle update --check and read the release installation guide' ;;
    *) logger -p user.err -t chronicle 'Update check failed; inspect the private state {UPDATE_LOG}'; exit 1 ;;
  esac
  exit 0
fi
exec python3 -m chronicle_ops operation-lock --state {quote(str(state))} --nonblocking -- bash -s <<'RECONCILE'
[[ ! -e {quote(str(state / STOP_MARKER))} ]] || exit 0
if (
  up_status=0
  CHRONICLE_RECONCILE_RUN=true ./chronicle up || up_status=$?
  CHRONICLE_ALERT_SYSLOG=true ./chronicle doctor && ((up_status == 0))
) >{quote(str(state / "reconcile.log"))} 2>&1; then
  record_status {quote(SCHEDULED_RECONCILE)} 0
else
  record_status {quote(SCHEDULED_RECONCILE)} 1
  logger -p user.err -t chronicle 'Reconciliation failed; inspect the private state reconcile.log'
  exit 1
fi
RECONCILE
'''
    with crontab_transaction():
        lines, marker, scheduled = crontab_without_project(project)
        if before_first_start and not scheduled:
            # Reconciliation keeps a started stack running; it never performs the first start. On a
            # fresh host that start would initialise the database (and its participant-token key)
            # before a documented `setup` then `restore --no-start` recovery. `./chronicle up` resumes.
            # Callers that install after a verified start (update) leave a running stack reconciled.
            write_text(state / STOP_MARKER, "installed; first start is ./chronicle up\n")
        write_text(script, content)
        script.chmod(0o700)
        command = quote(str(script)) + " " + marker
        lines += ["@reboot " + command, f"*/{INTERVAL_MINUTES} * * * * " + command]
        if (launcher.parent.parent / "release-manifest.json").is_file():
            lines.append("0 6 * * * " + quote(str(script)) + " --check-updates " + marker)
        write_crontab(lines)


def install_after_transfer(launcher, state, project, update_only=False):
    """The schedule step of an update or rollback, after the caller wrote and checked ownership.

    The crontab is the only optional part of either transaction: a host whose crontab cannot be
    read or written still runs the verified release. So a failure here warns, records
    SCHEDULE_PENDING for the next `./chronicle up`, and returns False instead of raising."""
    pending = Path(state) / SCHEDULE_PENDING
    try:
        install(launcher, state, project, **({"update_only": True} if update_only else {}))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        from .common import warn
        try:
            write_text(pending, f"{error}\n")
        except OSError:
            pass
        warn(f"the release is running, but the reconciliation schedule was not installed: {error}. "
             "Fix the operator crontab; the next ./chronicle up installs it.")
        return False
    pending.unlink(missing_ok=True)
    return True


def complete_recovery():
    # Only the transaction owner can commit and reopen ingress. A standalone verify
    # proves health but must not discard a resumable rollback journal.
    state = Path(os.environ['CHRONICLE_OPS_STATE'])
    if (state / UPGRADE_LOCK).exists():
        print('Update recovery is pending; run ./chronicle update from the recorded release.')
