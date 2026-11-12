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
import time
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
# Docker (Engine 23.0 and newer) sets this label on every volume made without a name: the ones
# it creates for a container's VOLUME paths, and one an operator makes with `docker volume create`
# and no name. So the label alone does not say whose a volume is (volume_ownership).
ANONYMOUS_VOLUME_LABEL = "com.docker.volume.anonymous"
# In the list before_compose returns: a labelled volume that is only reported, never removed.
KEPT_VOLUME_PREFIX = "kept:"
# What every forced recreation here passes to `up`. Compose mounts the anonymous volumes it
# carries over to a recreated container by name, exactly as it mounts a volume an operator asked
# for, and from then on nothing in Docker says which of the two a volume is; such a volume is
# never removed (volume_ownership). With --renew-anon-volumes the new container gets its own, the
# old container's are removed with it (after_compose), and none is left that cannot be told apart.
# They are empty in this stack; `down` followed by `up` never carried them over either.
FORCED_RECREATION = ("--force-recreate", "--renew-anon-volumes")
# The Compose commands that can remove a container or replace its anonymous volumes: `up` and
# `create` remove orphans and replace what --renew-anon-volumes names, and recreate a container
# from an image that no longer declares a path. `run --remove-orphans` is matched by its option.
REMOVING_COMMANDS = frozenset({"create", "down", "rm", "up"})
# Compose's own options that take a value and come before the command.
COMPOSE_VALUE_OPTIONS = frozenset({"--ansi", "--env-file", "-f", "--file", "--parallel", "--profile", "--progress",
                                   "--project-directory", "-p", "--project-name"})
DOCKER_QUERY_TIMEOUT_SECONDS = 120
# All Docker calls of after_compose together. They take about 0.05 seconds each on a daemon that
# answers (measured with 18,000 volumes on it, 2026-11-11). The command the operator ran has
# finished by then, so a daemon that has stopped answering must not hold the terminal.
AFTER_COMPOSE_SECONDS = 30
ANONYMOUS_VOLUME_HINT = "`docker volume ls --filter dangling=true --filter label=com.docker.volume.anonymous` lists them"


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


def note(message):
    """Something an operator may want to know that is not a fault. On stderr, like warn: commands
    whose output a script reads print only that output on stdout."""
    print("note: {}".format(message), file=sys.stderr)


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
    on the name. Only such placeholders are removed; started containers and named volumes are
    untouched. --volumes removes the anonymous volumes Docker made for the placeholder alone; the
    ones it took over from the container it was replacing are mounted by name, which --volumes
    never removes, and that container still mounts them."""
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
                    run(["docker", "rm", "--volumes", current["Id"]], quiet=True)


def compose_command(args):
    """The Compose command in args, after Compose's own options: `--progress quiet up -d` is `up`."""
    args = [str(arg) for arg in args]
    index = 0
    while index < len(args) and args[index].startswith("-"):
        index += 2 if args[index] in COMPOSE_VALUE_OPTIONS else 1
    return args[index] if index < len(args) else ""


def seconds_until(until):
    """The timeout for one Docker call that has to end by `until` (a time.monotonic() value), or
    the limit of a single query when there is none. Raises subprocess.TimeoutExpired once that
    time has passed, so that no further call is started."""
    if until is None:
        return DOCKER_QUERY_TIMEOUT_SECONDS
    left = until - time.monotonic()
    if left <= 0:
        raise subprocess.TimeoutExpired(["docker"], 0)
    return left


def docker_query(*args, missing_ok=False, until=None):
    """What a read-only `docker <args>` prints. Raises OSError or subprocess.SubprocessError, with
    Docker's own message, when Docker cannot answer; within DOCKER_QUERY_TIMEOUT_SECONDS, or by
    `until` (seconds_until).
    missing_ok is for the inspect commands: an object removed since it was listed makes Docker
    exit 1 and still print the others, which is an answer.
    The output is only matched (ids, names, JSON), so it is decoded like stderr (SHOWN): a byte
    outside the pipe encoding, in a container's label or environment, cannot raise here."""
    result = run(["docker", *args], capture=True, stderr=subprocess.PIPE, errors=SHOWN, timeout=seconds_until(until))
    errors = [line.strip() for line in (result.stderr or "").splitlines() if line.strip()]
    if result.returncode and not (missing_ok and errors and all("no such" in line.lower() for line in errors)):
        raise subprocess.SubprocessError(errors[0][:COMPOSE_ERROR_LINE_LENGTH] if errors
                                         else f"docker {args[0]} exited {result.returncode}")
    return result.stdout or ""


def project_containers(project, until=None):
    """`docker inspect` of every container of the Compose project, in any state. Raises like docker_query."""
    containers = docker_query("ps", "-a", "-q", "--filter", f"label=com.docker.compose.project={project}", until=until).split()
    return json.loads(docker_query("inspect", *containers, missing_ok=True, until=until) or "[]") if containers else []


def mounted_volumes(containers):
    """Names of the volumes the inspected containers list as a mount."""
    return {mount["Name"] for container in containers for mount in container.get("Mounts") or []
            if mount.get("Type") == "volume" and mount.get("Name")}


def requested_volumes(container):
    """Names the container's own configuration asks for as the source of a mount.

    `docker run -v name:/path`, and Compose 5 for a volume of the Compose file in either syntax,
    put "name:/path[:options]" in HostConfig.Binds; `--mount`, Compose 2.17 for every volume of
    the Compose file, and every Compose for a volume it carries over to a recreated container put
    {"Type": "volume", "Source": name, "Target": path} in HostConfig.Mounts. A volume Docker makes
    by itself for a VOLUME path of the image is in neither."""
    host = container.get("HostConfig") or {}
    return ({str(bind).split(":", 1)[0] for bind in host.get("Binds") or []}
            | {mount.get("Source") for mount in host.get("Mounts") or [] if mount.get("Source")})


def volume_ownership(project):
    """(Docker's own, asked for) among the volumes without a name that the project's containers
    mount now at a VOLUME path of their image: two sorted lists of names.

    Docker creates a volume for every VOLUME path of an image that the Compose file mounts nothing
    over: the Percona image declares six (/backrestrepo, /data/db, /pgconf, /pgdata, /pgwal, /sshd),
    so each container made from POSTGRES_IMAGE or BACKUP_IMAGE has five or six.
    They are empty in a running stack: PostgreSQL's data directory is the named volume mounted
    over /data/db, and nothing writes to the other five paths.

    Docker's own, the only ones ever removed, are those for which all of this holds:
      - a container of the project mounts it at a path its Config.Volumes lists (the image's VOLUMEs);
      - that container's configuration does not name it (requested_volumes) and has no
        HostConfig.VolumesFrom, so Docker made the volume for this container and nobody asked for it;
      - no other container of the project names it;
      - Docker labels it ANONYMOUS_VOLUME_LABEL.
    `docker rm --volumes` draws the same line: it leaves a volume that was specified with a name.
    The label alone is not enough: Docker also sets it on a volume an operator made with
    `docker volume create` and no name. Mounted over /data/db through the Compose file, such a
    volume held the database and `./chronicle down` removed it (Engine 29.8.2, 2026-11-11).

    Asked for: labelled and mounted at such a path, but named by a container, or reached through
    --volumes-from. That is an operator's own volume, and also every volume Compose carried over
    to a container it recreated: Compose mounts those by name, and with Compose 2.17 the entry is
    the same as for a volume the Compose file asks for in the long syntax. They are never removed;
    after_compose reports the ones a command leaves unused. FORCED_RECREATION keeps this code's
    own recreations from producing any.

    An Engine older than 23.0 sets no label (20.10.24 measured): both lists are empty there, so
    nothing is removed and nothing is reported.
    Raises OSError, ValueError or subprocess.SubprocessError when Docker cannot be asked."""
    containers = project_containers(project)
    named = set().union(*(requested_volumes(container) for container in containers)) if containers else set()
    own: set[str] = set()
    candidates: set[str] = set()
    for container in containers:
        declared = set((container.get("Config") or {}).get("Volumes") or {})
        at_image_paths = {mount["Name"] for mount in container.get("Mounts") or []
                          if mount.get("Type") == "volume" and mount.get("Name") and mount.get("Destination") in declared}
        candidates |= at_image_paths
        if not (container.get("HostConfig") or {}).get("VolumesFrom"):
            own |= at_image_paths - named
    if not candidates:
        return [], []
    volumes = json.loads(docker_query("volume", "inspect", *sorted(candidates), missing_ok=True) or "[]")
    labelled = {volume["Name"] for volume in volumes if ANONYMOUS_VOLUME_LABEL in (volume.get("Labels") or {})}
    return sorted(own & labelled), sorted((candidates - own) & labelled)


def anonymous_volumes(project):
    """Names of the anonymous volumes Docker made for the project's containers, sorted: the ones
    that may be removed once no container mounts them (volume_ownership). Raises like it."""
    return volume_ownership(project)[0]


def used_volumes(volumes, until=None):
    """The ones among volumes that a container lists as a mount: any project, any state.

    `docker volume rm` refuses a volume only while a container holds a reference to it, and a
    container that took a volume with --volumes-from and has never started holds none when the
    first container mounted the volume by name, as Compose does for the anonymous volumes of a
    recreated container (Engine 29.8.2: the volume was removed under a created container that
    listed it). So the containers are asked. Raises like docker_query."""
    def listing(names):
        filters = [argument for name in names for argument in ("--filter", "volume=" + name)]
        return docker_query("ps", "-a", "-q", *filters, until=until).split()
    volumes = list(volumes)
    if not volumes or not listing(volumes):
        return set()
    return {volume for volume in volumes if listing([volume])}


def removes_containers(args):
    """Whether the Compose command in args can remove a container (REMOVING_COMMANDS, --remove-orphans)."""
    return compose_command(args) in REMOVING_COMMANDS or "--remove-orphans" in [str(arg) for arg in args]


def resolved_project(options):
    """The project name Compose itself resolves for a command line that starts with these options
    (--env-file, -f, ...), for an entry point that passes no -p. Compose takes it from -p, else
    from COMPOSE_PROJECT_NAME in the environment, else from that variable in the file given with
    --env-file, else from the Compose file's `name:`, else from the directory (Compose 2.17.0 and
    5.5.0, 2026-11-11). Read from the first line of the form `name: ...` in what `config` prints:
    2.17.0 has no name in `config --format json`.
    Raises OSError, ValueError or subprocess.SubprocessError when Compose cannot load the
    project; the command itself then fails the same way."""
    result = run(["docker", "compose", *options, "config"], capture=True, stderr=subprocess.PIPE, errors=SHOWN,
                 timeout=DOCKER_QUERY_TIMEOUT_SECONDS)
    if result.returncode:
        raise subprocess.SubprocessError(compose_error(result.stderr) or f"docker compose config exited {result.returncode}")
    named = re.search(r"""(?m)^name: *(["']?)(.+?)\1 *$""", result.stdout or "")
    if not named:
        raise ValueError("docker compose config printed no project name")
    return named.group(2)


def project_volumes_before(options, args):
    """anonymous_volumes_before for a shell entry point that leaves the project name to Compose
    (scripts/deploy.sh, scripts/rotate-secrets.sh): [project, *volumes], or nothing when there
    are no volumes. options are the Compose options the entry point puts before args; Compose is
    asked for the name only when args can remove a container. Never raises: when Compose cannot
    say which project it is the command still runs, and a warning says that the volumes it leaves
    stay."""
    if not removes_containers(args):
        return []
    try:
        project = resolved_project(options)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        warn(f"could not ask Compose for the project name ({error}); the anonymous volumes this command leaves "
             f"will stay; {ANONYMOUS_VOLUME_HINT}")
        return []
    volumes = anonymous_volumes_before(project, args)
    return [project, *volumes] if volumes else []


def anonymous_volumes_before(project, args):
    """What the Compose command in args can leave behind, when it can remove a container
    (REMOVING_COMMANDS, --remove-orphans), else nothing: the names of the anonymous volumes Docker
    made for the project's containers, then, each with KEPT_VOLUME_PREFIX, the ones a container
    asked for (volume_ownership). For after_compose, which removes the first kind and only reports
    the second. Never raises: when Docker cannot be asked the command still runs, and a warning
    says that the volumes it leaves stay."""
    if removes_containers(args):
        try:
            own, asked_for = volume_ownership(project)
            return [*own, *(KEPT_VOLUME_PREFIX + name for name in asked_for)]
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            warn(f"could not list the project's anonymous volumes ({error}); the ones this command leaves "
                 f"will stay; {ANONYMOUS_VOLUME_HINT}")
    return []


def before_compose(project, args):
    """Every compose entry point (Python and both shells) calls this before the command and
    after_compose with what it returns after it. `up` after any Compose option clears placeholders.
    Returns anonymous_volumes_before(project, args)."""
    # Before the placeholders go, so their volumes are in the list.
    volumes = anonymous_volumes_before(project, args)
    if compose_command(args) == "up":
        clear_interrupted_recreates(project)
    return volumes


def after_compose(project, volumes, seconds=AFTER_COMPOSE_SECONDS):
    """Remove the anonymous volumes a Compose command left unattached.

    volumes is what before_compose returned. Compose removes a container's anonymous volumes only
    for `down --volumes` (which also removes the named ones and is never used here) and `rm
    --volumes`. So `down`, an orphan removed by `up` and --renew-anon-volumes each left five or
    six volumes per container made from the Percona image, for good.
    Removed here: a volume from the list that Docker made for a container (volume_ownership) and
    that no container mounts any more, in this project (mounted_volumes) or any other
    (used_volumes). A named volume is never in the list; a volume some container still lists is
    left out, and `docker volume rm` without --force also refuses one a started container holds.
    A listed volume that a container asked for by name (KEPT_VOLUME_PREFIX) is never removed:
    when the command leaves it unused, one line says how many there are and how to list them.
    When Docker cannot be asked nothing is removed. Never raises an error: a volume that stays
    is unused space, not a failure.
    All Docker calls here end within `seconds` together; after that the volumes stay and a
    warning says so. A signal handled by `interrupted` passes through (Interrupted) once the
    Docker call in progress has been stopped (run).
    The list lives in the calling process only. An interrupt (SIGINT, SIGTERM, SIGHUP) still
    reaches this call, through `finally` here and the subshell in the shell entry points; when
    the process is killed outright (SIGKILL, power loss) between the Compose command and this
    call, that command's volumes stay, because nothing in Docker ties an anonymous volume to its
    project once the container is gone."""
    volumes = [str(volume) for volume in volumes]
    if not volumes:
        return
    kept = [volume[len(KEPT_VOLUME_PREFIX):] for volume in volumes if volume.startswith(KEPT_VOLUME_PREFIX)]
    removable = [volume for volume in volumes if not volume.startswith(KEPT_VOLUME_PREFIX)]
    until = time.monotonic() + seconds

    def anonymous(count):
        return f"{count} anonymous volume{'s' if count != 1 else ''}"

    def unanswered(reason):
        # With nothing removable in the list, only the count of kept volumes is lost.
        what = (f"could not remove the {anonymous(len(removable))} that removed containers may have left" if removable
                else "could not see which volumes without a name the removed containers left unused")
        warn(f"{what} ({reason}); {ANONYMOUS_VOLUME_HINT}")
    try:
        attached = mounted_volumes(project_containers(project, until))
        unattached = [volume for volume in (*removable, *kept) if volume not in attached]
        used = used_volumes(unattached, until)
        detached = [volume for volume in removable if volume not in attached and volume not in used]
        left = [volume for volume in kept if volume not in attached and volume not in used]
        if left:
            note(f"{len(left)} volume{'s' if len(left) != 1 else ''} without a name {'were' if len(left) != 1 else 'was'} left: "
                 f"the removed containers mounted {'them' if len(left) != 1 else 'it'} by name, "
                 "as Compose does for a volume of yours and for the "
                 f"anonymous volumes it carries over to a container it recreates; {ANONYMOUS_VOLUME_HINT}")
        if not detached:
            return
        removal = run(["docker", "volume", "rm", *detached], capture=True, stderr=subprocess.PIPE, errors=SHOWN,
                      timeout=seconds_until(until))
        # Not failures: another container still uses it (Docker keeps it), or it is already gone.
        refused = [line for line in (removal.stderr or "").splitlines()
                   if line.strip() and "in use" not in line and "no such volume" not in line.lower()]
        if refused:
            warn(f"could not remove {anonymous(len(refused))} that removed containers left "
                 f"({refused[0].strip()[:COMPOSE_ERROR_LINE_LENGTH]}); {ANONYMOUS_VOLUME_HINT}")
    except subprocess.TimeoutExpired:
        unanswered(f"Docker did not answer within {seconds} second{'s' if seconds != 1 else ''}")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        unanswered(error)


def after_compose_status(project, volumes):
    """after_compose for the shell entry points, which exit with what this returns (0).

    Their subshell lets its signals through again once Compose has returned. A signal that arrives
    here stops the Docker call in progress with its process group (run) and then ends this process
    by that same signal: the shell above then sees an interrupted command, as it does when Ctrl-C
    ends any other program. A signal the script was started ignoring (nohup, a background job)
    stays ignored."""
    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        if signal.getsignal(signum) is not signal.SIG_IGN:
            signal.signal(signum, interrupted)
    try:
        after_compose(project, volumes)
    except Interrupted as error:
        signum = error.status - 128
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
        return error.status
    return 0


def compose(*args, **kwargs):
    project = os.environ["CHRONICLE_OPS_PROJECT"]
    volumes = before_compose(project, args)
    try:
        return run(["docker", "compose", "-p", project, *args], **kwargs)
    finally:
        after_compose(project, volumes)


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

