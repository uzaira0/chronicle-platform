"""Copy the publisher's operator inventory into isolated test installations."""

from contextlib import contextmanager
from dataclasses import dataclass
import functools
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import time
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_POSTGRES_PASSWORD = "synthetic-test-password"
FIXTURE_POSTGRES_APP_PASSWORD = "synthetic-app-test-password"


def context_sources(dockerfile):
    """The build-context paths a Dockerfile reads (its COPY/ADD sources and RUN --mount=type=bind sources),
    as the dependency gate runner reads them (scripts/dependency-gate-runner.py copy_sources)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("dependency_gate_runner_sources", ROOT / "scripts/dependency-gate-runner.py")
    runner = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, runner)  # dataclasses look their module up here
    spec.loader.exec_module(runner)
    return runner.copy_sources(Path(dockerfile))


@functools.cache
def postgres_image():
    """The release Postgres image built from selfhost/Dockerfile.postgres, with only the context files it reads."""
    import io
    import tarfile
    tag = "chronicle-selfhost-postgres:test"
    context = io.BytesIO()
    with tarfile.open(fileobj=context, mode="w", format=tarfile.GNU_FORMAT) as archive:
        archive.add(ROOT / "selfhost/Dockerfile.postgres", arcname="Dockerfile")
        for source in context_sources(ROOT / "selfhost/Dockerfile.postgres"):
            archive.add(ROOT / "selfhost" / source, arcname=source)
    subprocess.run(["docker", "build", "-q", "-t", tag, "-"], input=context.getvalue(),
                   check=True, capture_output=True, timeout=600)
    return tag


def disposable_project_volumes(project):
    """Names of the volumes without a name that the containers of a harness's own disposable
    Compose project mount at image VOLUME paths, sorted: the ones Docker made for a container, and
    the ones Compose carried over to a recreated container, which mounts them by name
    (HostConfig.Mounts, no VolumeOptions).

    The operator code never removes a carried one (chronicle_ops.common volume_ownership): with
    Compose 2.17 an operator's own volume mounted with the long syntax is listed the same way. A
    harness owns what its project made, so it takes them. Left out: a volume the Compose file
    asked for in a way that shows, in HostConfig.Binds (Compose 5) or in HostConfig.Mounts with
    VolumeOptions (short syntax, Compose 2.17). This file is also what
    tests/security/lib/selfhost-python.sh remove_compose_project asks.
    Raises OSError, ValueError or subprocess.SubprocessError when Docker cannot be asked."""
    def docker(*args, check=True):
        return subprocess.run(["docker", *args], check=check, capture_output=True, text=True, timeout=120).stdout

    containers = docker("ps", "-a", "-q", "--filter", "label=com.docker.compose.project=" + project).split()
    asked, mounted = set(), set()
    # A container removed since the listing makes inspect exit 1 and still print the others.
    for container in json.loads(docker("inspect", *containers, check=False) or "[]") if containers else []:
        host = container.get("HostConfig") or {}
        asked.update(str(bind).split(":", 1)[0] for bind in host.get("Binds") or [])
        asked.update(mount.get("Source") for mount in host.get("Mounts") or [] if "VolumeOptions" in mount)
        declared = set((container.get("Config") or {}).get("Volumes") or {})
        mounted.update(mount["Name"] for mount in container.get("Mounts") or []
                       if mount.get("Type") == "volume" and mount.get("Name") and mount.get("Destination") in declared)
    names = sorted(mounted - asked)
    if not names:
        return []
    return sorted(volume["Name"] for volume in json.loads(docker("volume", "inspect", *names, check=False) or "[]")
                  if "com.docker.volume.anonymous" in (volume.get("Labels") or {}))


@contextmanager
def anonymous_volumes_removed(project):
    """Around a harness's removal of its own Compose project: when the block ends, the anonymous
    volumes the project's containers mounted are removed as well.

    The Percona image declares six VOLUME paths, so every container made from the Postgres or
    backup image has five or six anonymous volumes. `docker compose down --volumes` removes them
    only for a container that `up` never recreated: Compose mounts a recreated container's
    volumes by name, and neither `down --volumes` nor `docker rm --volumes` removes those
    (442 were left by one run of test_forward_drill on 2026-11-11). The operator's own Compose
    calls remove the ones Docker made for a container and leave the carried ones
    (chronicle_ops.common before_compose and after_compose); a harness that calls
    `docker compose down` directly wraps the call in this, which takes both
    (disposable_project_volumes). Nobody waits at a terminal for a harness, and a volume it
    leaves is the leak this exists for, so Docker gets the time of a single query for the whole
    step, not the operator's AFTER_COMPOSE_SECONDS."""
    from chronicle_ops.common import DOCKER_QUERY_TIMEOUT_SECONDS, after_compose
    try:
        volumes = disposable_project_volumes(project)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"warning: could not list the anonymous volumes of {project} ({error}); the ones its removal leaves stay",
              file=sys.stderr)
        volumes = []
    try:
        yield
    finally:
        after_compose(project, volumes, seconds=DOCKER_QUERY_TIMEOUT_SECONDS)


class AnonymousVolumeWatch:
    """Every anonymous volume that a container of one Compose project mounts, read from `docker events`.

    Once a container is removed nothing in Docker says which project its anonymous volumes
    belonged to, so a test that asserts its commands left none has to see them being mounted.
    start() before the project's first container; unattached() names the ones that still exist
    and that no container uses, which is what the commands so far left behind. A container that
    is created and never started is not seen: Docker reports a mount only when a container starts.
    A volume someone made without a name and mounted into the project counts as well."""

    def __init__(self, project, folder):
        self.project = project
        self.path = Path(folder) / ("docker-events-" + uuid.uuid4().hex + ".jsonl")
        self.process = None

    def start(self):
        with self.path.open("wb") as output:
            self.process = subprocess.Popen(
                ["docker", "events", "--format", "{{json .}}", "--filter", "type=container", "--filter", "type=volume",
                 "--filter", "event=create", "--filter", "event=mount"], stdout=output, stderr=subprocess.DEVNULL)
        self.wait_for_events()

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=30)
            self.process = None

    def wait_for_events(self):
        """Return once every event Docker has reported so far is in the file: a marker volume is
        made and its own event waited for. `docker events` has no ready signal, so the first
        marker after start() can precede the stream; another is made until one is reported."""
        if self.process is None:
            return
        deadline = time.monotonic() + 60
        while True:
            marker = subprocess.run(["docker", "volume", "create", "--label", "chronicle.test.volume-watch=" + self.project],
                                    check=True, capture_output=True, text=True, timeout=60).stdout.strip()
            try:
                reported = time.monotonic() + 3
                while time.monotonic() < reported:
                    if marker in self.path.read_text(errors="replace"):
                        return
                    if self.process.poll() is not None:
                        raise AssertionError("docker events stopped")
                    time.sleep(0.1)
            finally:
                subprocess.run(["docker", "volume", "rm", marker], capture_output=True, timeout=60)
            if time.monotonic() > deadline:
                raise AssertionError("docker events did not report the watch's marker volume")

    def mounted(self):
        """Names of the anonymous volumes the project's containers have mounted since start(), sorted."""
        self.wait_for_events()
        containers, mounts = set(), []
        for line in self.path.read_text(errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            actor = event.get("Actor") or {}
            attributes = actor.get("Attributes") or {}
            if event.get("Type") == "container" and attributes.get("com.docker.compose.project") == self.project:
                containers.add(actor.get("ID"))
            elif event.get("Type") == "volume" and event.get("Action") == "mount":
                mounts.append((actor.get("ID", ""), attributes.get("container")))
        return sorted({volume for volume, container in mounts
                       if container in containers and re.fullmatch(r"[0-9a-f]{64}", volume)})

    def unattached(self):
        """The mounted ones that still exist, carry Docker's anonymous label and that no container uses."""
        names = self.mounted()
        existing = set()
        for start in range(0, len(names), 100):
            found = subprocess.run(["docker", "volume", "inspect", *names[start:start + 100]],
                                   capture_output=True, text=True, timeout=120).stdout
            existing.update(volume["Name"] for volume in json.loads(found or "[]")
                            if "com.docker.volume.anonymous" in (volume.get("Labels") or {}))
        if not existing:
            return []
        unused = subprocess.run(["docker", "volume", "ls", "-q", "--filter", "dangling=true"],
                                check=True, capture_output=True, text=True, timeout=120).stdout.split()
        return sorted(existing.intersection(unused))


def run_cert_init(tls_dir, *, script=ROOT / "selfhost/cert-init.sh", base=None, timeout=60, **settings):
    """Run cert-init.sh on this host into tls_dir. It runs as root in its container; a no-op chown stands in
    for the group-0 ownership step, the only one that needs root. Defaults: internal dashboard, behind proxy."""
    tls_dir = Path(tls_dir)
    commands = tls_dir.parent / (tls_dir.name + "-commands")
    commands.mkdir(exist_ok=True)
    (commands / "chown").write_text("#!/bin/sh\nexit 0\n")
    (commands / "chown").chmod(0o755)
    environment = dict(os.environ if base is None else base, DASHBOARD_EXPOSURE="internal", TLS_MODE="behind-proxy",
                       POSTGRES_TLS_DIR="", BACKEND_TLS_DIR="", MONITORING_ENABLED="false")
    environment.update(settings, TLS_DIR=str(tls_dir), PATH=str(commands) + os.pathsep + os.environ["PATH"])
    return subprocess.run(["bash", str(script)], env=environment, capture_output=True, text=True, timeout=timeout)


def bundle_fixture_files(builder):
    return set(builder['operator_files']()) | {
        path.relative_to(ROOT / 'selfhost').as_posix()
        for directory in builder['BUNDLE_DIRECTORIES']
        for path in (ROOT / 'selfhost' / directory).rglob('*') if path.is_file()
    }


def copy_selfhost_fixture(destination, *, preserve_existing=False):
    destination = Path(destination)
    with patch.object(sys, 'path', sys.path[:]):
        builder = runpy.run_path(str(ROOT / 'scripts/build-selfhost-release.py'))
    for name in builder['operator_files']():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not preserve_existing or not target.exists():
            shutil.copy2(ROOT / 'selfhost' / name, target)


@dataclass
class MobileCanaryFixture:
    path: Path
    requests: dict
    credential: str


def mobile_canary_fixture(directory, public):
    from chronicle_ops.mobile_canary import API_KEY_HEADER, CANARY_ROUTES
    from chronicle_ops.receipts import write_json
    credential = 'synthetic-' + uuid.uuid4().hex
    base = public + '/chronicle/v4/study/' + str(uuid.uuid4()) + '/participant/smoke-' + uuid.uuid4().hex
    requests = {name: dict(url=base + suffix, body=[{'synthetic': True}], headers={API_KEY_HEADER: credential})
                for name, suffix in CANARY_ROUTES.items()}
    path = Path(directory) / 'mobile-canary.json'
    write_json(path, dict(requests, credential=credential))
    return MobileCanaryFixture(path=path, requests=requests, credential=credential)


@dataclass
class RotationFixture:
    host: Path
    commands: Path
    environment: dict


def rotation_fixture(root):
    host = root / 'selfhost'
    copy_selfhost_fixture(host)
    (host / '.env').write_text('COMPOSE_PROJECT_NAME=fixture\nCOMPOSE_FILE=overlays/backups.yml\n'
                             'ENABLE_ENCRYPTION=true\nPOSTGRES_PASSWORD=' + FIXTURE_POSTGRES_PASSWORD + '\n'
                             'POSTGRES_APP_PASSWORD=' + FIXTURE_POSTGRES_APP_PASSWORD + '\n'
                             'METRICS_PASSWORD=synthetic-metrics-password\n')
    (host / '.env').chmod(0o600)
    commands = root / 'commands'
    shutil.copytree(ROOT / 'tests/security/fixtures/selfhost-secret-rotation/commands', commands)
    for command in commands.iterdir():
        command.chmod(0o755)
    environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'], STATE_ROOT=str(host),
                       SELFHOST_ROTATION_TEST_REAL_PYTHON=sys.executable,
                       SELFHOST_ROTATION_TEST_ARGS_LOG=str(root / 'args'))
    for key, content in (('OLD_POSTGRES', FIXTURE_POSTGRES_PASSWORD), ('GENERATED', 'a' * 64),
                         ('OLD_POSTGRES_APP', FIXTURE_POSTGRES_APP_PASSWORD),
                         ('DB_APP_PASSWORD', FIXTURE_POSTGRES_APP_PASSWORD),
                         ('DASHBOARD', 'synthetic-dashboard-password'), ('DB_PASSWORD', FIXTURE_POSTGRES_PASSWORD),
                         ('TDE_STATE', 'chronicle_key|chronicle_keyring')):
        fixture = root / key
        fixture.write_text(content)
        environment['SELFHOST_ROTATION_TEST_' + key + '_FILE'] = str(fixture)
    environment['SELFHOST_ROTATION_TEST_KEYRING_BACKUP_FILE'] = str(host / 'backups/keyring/chronicle-keyring.per')
    environment['SELFHOST_ROTATION_TEST_MONITORING_LOG'] = str(root / 'monitoring.log')
    return RotationFixture(host=host, commands=commands, environment=environment)


if __name__ == '__main__':
    copy_selfhost_fixture(sys.argv[1])
