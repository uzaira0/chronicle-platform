"""Shared operator output and subprocess calls."""

import os
from contextlib import suppress
import fcntl
import json
import ipaddress
import locale
from pathlib import Path
import re
import signal
import subprocess
import sys
from .startup import startup_timeout

GIB = 1024 ** 3

RED, GRN, YEL, BLD, RST = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[0m"
WRITABLE_ROOT_REASON_LABEL = "org.chronicle.security.writable-root-reason"
OPERATION_LOCK = ".reconcile.lock"
OPERATION_LOCK_CREATE_ERROR = "Could not create the operation lock: {}. Check state-directory permissions and free space."
OPERATION_LOCK_MODE = 0o644  # Contains no data; older bundle preflights require readability.
LOCK_FD_ENV = "CHRONICLE_OPERATION_LOCK_FD"
MIN_FREE_INODES = 10_000
# Below this share of free space doctor and the disk-pressure alert advise more capacity.
LOW_FREE_PERCENT = 15
UPDATE_PEAK_BYTES = 3 * GIB
# MIN_FREE_DISK_GIB when .env does not set it: the reserve update, restore and up keep free.
DEFAULT_MIN_FREE_DISK_GIB = 5
PREPARATION_TIMEOUT_SECONDS = 600
DEFAULT_COMPOSE_PROJECT = "chronicle-selfhost"
TRANSFER_TIMEOUT_ENV = "CHRONICLE_TRANSFER_TIMEOUT_SECONDS"
# How much of a failed Compose command's stderr a warning repeats.
COMPOSE_ERROR_LINES = 3
COMPOSE_ERROR_LINE_LENGTH = 300
# A line Compose logs below error level (logrus form); compose_error does not report it as the error.
COMPOSE_LOG_LINE = re.compile(r'time="[^"]*" level=(?:warning|info|debug) ')
# How run() decodes text that is only matched or shown, never written back: a byte that is not
# valid in the pipe encoding becomes \xNN instead of raising UnicodeDecodeError. Every stderr is
# decoded this way; a caller passes errors=SHOWN to have stdout decoded so too.
SHOWN = "backslashreplace"


def same_path(recorded, actual):
    """Whether a recorded release or state directory is `actual`, with symlinks resolved.

    Recovery records, handoffs and owner markers store paths as text. Comparing that text with
    a resolved directory fails whenever either side was reached through a symlink (macOS /var,
    a symlinked /home or data mount), which refused an operator's own resume or rollback."""
    if not recorded or not Path(recorded).is_absolute():
        return False
    return Path(recorded).resolve() == Path(actual).resolve()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def database_volume_path(project):
    """Host path behind PostgreSQL's PGDATA, or None before the volume exists."""
    containers = run(["docker", "ps", "-a", "-q", "--filter", f"label=com.docker.compose.project={project}",
                      "--filter", "label=com.docker.compose.service=postgres"], capture=True, timeout=15, check=True)
    if containers.stdout.strip():
        inspected = run(["docker", "inspect", *containers.stdout.split()], capture=True, timeout=15, check=True)
        for container in json.loads(inspected.stdout):
            pgdata = next((entry.partition("=")[2] for entry in container["Config"]["Env"] if entry.startswith("PGDATA=")), None)
            if not pgdata:
                raise ValueError("cannot identify PostgreSQL's actual PGDATA mount")
            for mount in container["Mounts"]:
                if Path(pgdata).is_relative_to(mount["Destination"]):
                    return Path(mount["Source"])
    else:
        volumes = run(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}",
                       "--filter", "label=com.docker.compose.volume=postgres_data"], capture=True, timeout=15, check=True)
        if volumes.stdout.strip():
            inspected = run(["docker", "volume", "inspect", *volumes.stdout.split()], capture=True, timeout=15, check=True)
            for volume in json.loads(inspected.stdout):
                device = (volume.get("Options") or {}).get("device", "")
                return Path(device if device.startswith("/") else volume["Mountpoint"])
    return None


def storage_report(state, project, floor_gib=DEFAULT_MIN_FREE_DISK_GIB, peak_bytes=0, *, image=None):
    info = run(["docker", "info", "--format", "{{.DockerRootDir}}"], capture=True, timeout=15, check=True)
    paths = {"state": Path(state), "docker-data": Path(info.stdout.strip())}
    database = database_volume_path(project)
    if database is not None:
        paths["database-volume"] = database
    rows = []
    for name, path in paths.items():
        try:
            try:
                disk = os.statvfs(path)
            except PermissionError:
                # Protected descendants still share the filesystem's accessible mount point.
                mounts = [Path(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), line.split()[4]))
                          for line in Path("/proc/self/mountinfo").read_text().splitlines()]
                mount = max((mount for mount in mounts if mount == path or mount in path.parents), key=lambda mount: len(mount.parts))
                disk = os.statvfs(mount)
            free, inodes = disk.f_bavail * disk.f_frsize, disk.f_favail
            total_inodes = disk.f_files
        except (PermissionError, FileNotFoundError):
            if name == "state":
                raise
            from .envfile import read_env, value
            image = image or os.environ.get("POSTGRES_IMAGE") or value(read_env(Path.cwd() / ".env"), "POSTGRES_IMAGE")
            require(image, f"POSTGRES_IMAGE is not set, so the {name} filesystem cannot be measured")
            # A first `up` runs this before Compose pulls anything; the reference is digest-pinned.
            measured = run(["docker", "run", "--rm", "--pull", "missing", "--network", "none", "--read-only",
                            "--cap-drop", "ALL", "--user", "0", "--mount", f"type=bind,src={path},dst=/storage,readonly",
                            "--entrypoint", "/bin/bash", image, "-ceu", "df -Pk /storage; df -Pi /storage"],
                           capture=True, timeout=transfer_timeout(), check=True).stdout.splitlines()
            free, inodes = int(measured[1].split()[3]) * 1024, int(measured[3].split()[3])
            total_inodes = int(measured[3].split()[1])
        required = int(floor_gib) * GIB + (peak_bytes if name != "database-volume" else 0)
        enough_inodes = total_inodes == 0 or inodes >= MIN_FREE_INODES
        enough = free >= required and enough_inodes
        rows.append((name, enough, free, inodes, required))
    return rows


def require_storage(state, project, floor_gib=DEFAULT_MIN_FREE_DISK_GIB, peak_bytes=0, *, image=None):
    for name, enough, free, inodes, required in storage_report(state, project, floor_gib, peak_bytes, image=image):
        if not enough:
            raise ValueError(f"{name}: {free} bytes and {inodes} inodes free; require {required} bytes and {MIN_FREE_INODES} inodes before mutation")


def acquire_operation_lock(state, blocking=True):
    from .reconcile import clear_empty_markers
    path = Path(state) / OPERATION_LOCK
    inherited = os.environ.get(LOCK_FD_ENV, "")
    if inherited.isdigit():
        held = False
        with suppress(OSError):
            if os.path.samestat(os.fstat(int(inherited)), path.stat()):
                fcntl.flock(int(inherited), fcntl.LOCK_EX)
                os.fchmod(int(inherited), OPERATION_LOCK_MODE)
                held = True
        if held:
            # Outside the suppress: a marker error falling through to a second open would wait
            # forever on the lock this process already holds through the inherited descriptor.
            clear_empty_markers(state)
            return None
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        os.fchmod(descriptor, OPERATION_LOCK_MODE)
        os.environ[LOCK_FD_ENV] = str(descriptor)
        clear_empty_markers(state)
    except BaseException:
        if os.environ.get(LOCK_FD_ENV) == str(descriptor):
            os.environ.pop(LOCK_FD_ENV)
        os.close(descriptor)
        raise
    return descriptor


def holds_operation_lock(state):
    """Whether this process holds the shared operation lock: the inherited descriptor is the
    state's lock file and taking it without waiting succeeds (it would fail while any other
    open file holds the lock)."""
    inherited = os.environ.get(LOCK_FD_ENV, "")
    if not inherited.isdigit():
        return False
    try:
        if not os.path.samestat(os.fstat(int(inherited)), (Path(state) / OPERATION_LOCK).stat()):
            return False
        fcntl.flock(int(inherited), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def release_operation_lock(descriptor):
    if descriptor is not None:
        os.environ.pop(LOCK_FD_ENV, None)
        os.close(descriptor)


def dashboard_ca(tls):
    tls = Path(tls)
    anchor, certificate = tls / "internal-ca.crt", tls / "internal-cert.pem"
    if anchor.is_file() and run(["openssl", "verify", "-no_check_time", "-CAfile", str(anchor),
                                str(certificate)], quiet=True, timeout=10).returncode == 0:
        return anchor
    return certificate


def authority(host, port):
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"


def dashboard_origin(settings):
    from .envfile import value
    return value(settings, "DASHBOARD_BASE_URL") or "https://" + authority(
        value(settings, "INTERNAL_BIND") or "127.0.0.1", value(settings, "INTERNAL_PORT") or "8081")


def compose_gateway(subnet):
    return str(ipaddress.ip_network(subnet).network_address + 1)


class Interrupted(BaseException):
    def __init__(self, signum):
        super().__init__(f"interrupted by signal {signum}")
        self.status = 128 + signum


def interrupted(signum, _frame):
    raise Interrupted(signum)


def warn(message):
    print("{}warning:{} {}".format(YEL, RST, message), file=sys.stderr)


def compose_project(settings):
    from .envfile import value
    return value(settings, "COMPOSE_PROJECT_NAME") or DEFAULT_COMPOSE_PROJECT


def transfer_timeout():
    return int(startup_timeout(os.environ.get(TRANSFER_TIMEOUT_ENV, str(PREPARATION_TIMEOUT_SECONDS)),
                               TRANSFER_TIMEOUT_ENV))


def pipe_text(data, errors):
    """The text subprocess's own text mode makes of a pipe's bytes (the locale's encoding, universal
    newlines), with the given handler for a byte that encoding does not have."""
    if not isinstance(data, bytes):
        return data
    return data.decode(locale.getpreferredencoding(False), errors).replace("\r\n", "\n").replace("\r", "\n")


def run(args, capture=False, quiet=False, timeout=None, **kwargs):
    """Run an argv command. Text results by default (text=False for bytes): stdout is data and is
    decoded strictly unless errors= says otherwise, because a caller may write it back (a crontab,
    a rendered configuration); stderr is a message for a person and never raises on decoding
    (SHOWN). A command with a timeout runs in its own process group, which is killed with it."""
    if timeout is None and "pull" in args:
        timeout = transfer_timeout()
    elif timeout is None and any(arg in ("config", "info", "inspect") for arg in args):
        timeout = PREPARATION_TIMEOUT_SECONDS
    descriptor = os.environ.get(LOCK_FD_ENV, "")
    if descriptor.isdigit():
        kwargs.setdefault("pass_fds", (int(descriptor),))
    text, errors = kwargs.pop("text", True), kwargs.pop("errors", "strict")
    streams = dict(stdout=kwargs.pop("stdout", subprocess.PIPE if capture else subprocess.DEVNULL if quiet else None),
                   stderr=kwargs.pop("stderr", subprocess.DEVNULL if quiet else None))
    data, check = kwargs.pop("input", None), kwargs.pop("check", False)
    if text and isinstance(data, str):
        data = data.encode(locale.getpreferredencoding(False))
    if timeout is None:
        finished = subprocess.run(args, input=data, **streams, **kwargs)
        status, output, diagnostics = finished.returncode, finished.stdout, finished.stderr
    else:
        if data is not None:
            kwargs["stdin"] = subprocess.PIPE
        with spawn(args, **streams, **kwargs) as process:
            try:
                output, diagnostics = process.communicate(data, timeout=timeout)
            except BaseException:
                # The timeout (or interrupt) is what the caller is told, whatever stopping the group
                # runs into. macOS answers EPERM for a group that holds only the dead, unreaped
                # command. A process that left the group (a helper in its own session) can keep the
                # pipes open after the group is dead, so the rest of the output is waited for one
                # second, not until that process exits; leaving the block closes the pipes.
                try:
                    with suppress(ProcessLookupError, PermissionError, subprocess.TimeoutExpired):
                        os.killpg(process.pid, signal.SIGTERM)
                        process.communicate(timeout=1)
                finally:
                    with suppress(ProcessLookupError, PermissionError):
                        os.killpg(process.pid, signal.SIGKILL)
                    with suppress(subprocess.TimeoutExpired):
                        process.communicate(timeout=1)
                raise
            status = process.returncode
    if text:
        output, diagnostics = pipe_text(output, errors), pipe_text(diagnostics, SHOWN)
    if check and status:
        raise subprocess.CalledProcessError(status, args, output, diagnostics)
    return subprocess.CompletedProcess(args, status, output, diagnostics)


def spawn(args, **kwargs):
    """Start an argv command in a process group owned by its caller."""
    return subprocess.Popen(args, start_new_session=True, **kwargs)


def clear_interrupted_recreates(project):
    """Compose names a replacement "<old id>_<name>" and renames it once the old container is gone.
    An interrupted recreation leaves that never-started placeholder, and every later `up` then fails
    on the name. Only such placeholders are removed; started containers and volumes are untouched."""
    placeholder = re.compile(rf"[0-9a-f]{{12}}_{re.escape(project)}-")
    listed = run(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project}",
                  "--filter", "status=created", "--format", "{{.ID}} {{.Names}}"], capture=True)
    if listed.returncode or not listed.stdout:
        return
    for line in listed.stdout.splitlines():
        container, _, name = line.partition(" ")
        if placeholder.match(name):
            inspected = run(["docker", "inspect", container], capture=True, quiet=True)
            if inspected.returncode:
                continue
            for current in json.loads(inspected.stdout):
                state = current.get("State", {})
                if (current.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") == project
                        and placeholder.match(current.get("Name", "").lstrip("/"))
                        and state.get("Status") == "created"
                        and re.fullmatch(r"0001-01-01T00:00:00(?:\.0+)?Z", state.get("StartedAt", ""))):
                    run(["docker", "rm", current["Id"]], quiet=True)


def before_compose(project, args):
    """Every compose entry point (Python and both shells) calls this; `up` after any --progress option clears placeholders."""
    args = list(args)
    if args[:1] == ["--progress"]:
        args = args[2:]
    if args[:1] == ["up"]:
        clear_interrupted_recreates(project)


def compose(*args, **kwargs):
    before_compose(os.environ["CHRONICLE_OPS_PROJECT"], args)
    return run(["docker", "compose", "-p", os.environ["CHRONICLE_OPS_PROJECT"], *args], **kwargs)


def compose_error(text):
    """Compose's own error out of the stderr of a failed command, bounded. Compose writes one
    progress event per network, volume and container, each line starting with a space (50 in the
    monitoring start that failed on 2026-11-11, 17 of them repeating the error), and then its
    error on a line that does not. The last few distinct lines of that kind are returned, or the
    last progress events when there is no such line. What Compose logs as a warning is on such a
    line too (time="..." level=warning msg="The \"X\" variable is not set..."); those are left out
    unless they are all it wrote as its own."""
    own = [line.strip() for line in (text or "").splitlines() if line.strip() and not line[0].isspace()]
    lines = [line for line in own if not COMPOSE_LOG_LINE.match(line)] or own
    lines = lines or [line.strip() for line in (text or "").splitlines() if line.strip()]
    return "; ".join(line[:COMPOSE_ERROR_LINE_LENGTH] for line in list(dict.fromkeys(lines))[-COMPOSE_ERROR_LINES:])


def failure_cause(result, command):
    """Why `command` failed, for a warning: Compose's error from the stderr the caller piped
    (compose_error), or the exit status when it wrote none. result is the finished process, or
    the CalledProcessError of a caller that raises."""
    return compose_error(getattr(result, "stderr", None)) or f"{command} exited with status {result.returncode}"


def application_services(services):
    # Stop all configured services except the database. New writers must be quiesced too.
    return [service for service in services if service not in ("postgres", "restore")] if services else ["backend", "web", "db-init", "migrate"]


def network_subnet(release=None):
    """A release's network-subnet.py, loaded as a module: the owner of the core network's range
    and of everything derived from CHRONICLE_CORE_PREFIX. Default: the release this package is in."""
    import importlib.util
    from pathlib import Path
    path = Path(release) / 'network-subnet.py' if release else Path(__file__).resolve().parents[1] / 'network-subnet.py'
    spec = importlib.util.spec_from_file_location('chronicle_network_subnet', path)
    if spec is None or spec.loader is None:
        raise ValueError(f'cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

