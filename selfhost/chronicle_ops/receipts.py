"""Local operation receipts and best-effort monitoring events."""

import datetime
import errno
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from .common import SHOWN, compose, failure_cause, warn


ROUTINE_RECEIPT_KEEP = 96
OPERATOR_RECEIPTS_DIR = "operator-receipts"
# The cron schedule's own receipts (reconcile.py): one reconcile every 15 minutes is 35,040 a
# year, so they are pruned like every other routine operation.
SCHEDULED_OPERATIONS = frozenset(("update-check", "reconcile"))
ROUTINE_OPERATIONS = frozenset({"up", "doctor", "status", "check"} | SCHEDULED_OPERATIONS)


def durable_replace(temporary, destination):
    os.replace(temporary, destination)
    sync_directory(Path(destination).parent)


def sync_directory(path):
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_text(destination, content):
    destination = Path(destination)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                     prefix="." + destination.name + "-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            os.chmod(temporary, 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            durable_replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def json_text(data):
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def write_json(destination, data):
    write_text(destination, json_text(data))


def publish_journal(marker, files):
    """Publish an operation marker directory together with its complete recovery journal.

    The files are written and flushed in a private staging directory that is then renamed into
    place, so an interruption or a failed write leaves either no marker or a complete one."""
    marker = Path(marker)
    if os.path.lexists(marker):
        raise FileExistsError(errno.EEXIST, "an operation marker already exists", str(marker))
    with tempfile.TemporaryDirectory(prefix="." + marker.name + "-", dir=marker.parent) as staging:
        for name, content in files.items():
            write_text(Path(staging) / name, content)
        durable_replace(staging, marker)


def write_operation_receipt(operation, outcome, category="none", duration=0):
    if not (re.fullmatch("[a-z0-9-]{1,64}", operation)
            and outcome in ("success", "failure")
            and re.fullmatch("[a-z0-9_-]{1,48}", category)):
        raise ValueError("invalid operation receipt")
    parent = Path(os.environ["CHRONICLE_OPS_STATE"]) / OPERATOR_RECEIPTS_DIR
    root = parent / "operations"
    if parent.is_symlink() or root.is_symlink():
        raise ValueError("unsafe operation receipt directory")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    root.chmod(0o700)
    now = datetime.datetime.now(datetime.timezone.utc)
    receipt = root / "{}-{}-{}-{}.json".format(now.strftime("%Y%m%dT%H%M%SZ"), operation,
                                             os.getpid(), time.time_ns())
    write_json(receipt, {"operation": operation, "timestamp": now.isoformat().replace("+00:00", "Z"),
                         "releaseVersion": os.environ.get("CHRONICLE_OPS_VERSION", "unknown"),
                         "outcome": outcome, "failureCategory": category,
                         "durationSeconds": int(duration)})

    if operation in ROUTINE_OPERATIONS:
        routine = sorted(root.glob(f"*-{operation}-*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        matching = []
        for path in routine:
            try:
                if not path.is_symlink() and json.loads(path.read_text()).get("outcome") == outcome:
                    matching.append(path)
            except (OSError, ValueError):
                continue
        for path in matching[ROUTINE_RECEIPT_KEEP:]:
            path.unlink()


def record_operation(operation, outcome, category="none"):
    if "overlays/monitoring.yml" not in os.environ.get("COMPOSE_FILE", ""):
        return
    try:
        running = compose("ps", "--status", "running", "--services", capture=True, timeout=15, errors=SHOWN)
        if running.returncode or "operational-probe" not in running.stdout.splitlines():
            return
        # exec, not run: a one-off container makes Compose reconcile project networks against this
        # directory's definition, which can detach a stack started from another release.
        result = compose("exec", "-T", "operational-probe", "/monitoring/record-operation.sh",
                         operation, outcome, category, quiet=True, stderr=subprocess.PIPE, timeout=15)
        if not result.returncode:
            return
        cause = failure_cause(result, "the recording command")
    except subprocess.TimeoutExpired:
        cause = "no answer within 15 seconds"
    except OSError as error:
        cause = str(error)
    warn(f"the command completed, but its monitoring event could not be recorded: {cause}")


def finish_operation(operation, status, category, started):
    outcome = "success" if status == 0 else "failure"
    category = "none" if status == 0 else category
    try:
        write_operation_receipt(operation, outcome, category, int(time.monotonic() - started))
    except (OSError, ValueError):
        warn("the command {}, but its local operation receipt could not be written".format(
            "completed" if status == 0 else "failed"))
    record_operation(operation, outcome, category)
