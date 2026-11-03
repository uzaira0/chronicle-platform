"""Release inventory, ownership and deployment operations."""

from pathlib import Path, PurePosixPath
import gzip
import fcntl
import json
import os
import re
import shutil
import shlex
import subprocess
from typing import NamedTuple

from .reconcile import RECOVERY_FILE, UPGRADE_LOCK

from .common import before_compose, require, run
from . import envfile
from .dump import backup_release_header, CATALOG_GATE_SQL, DUMP_EXCLUDE_OPTIONS, file_sha256, validate_dump, installed_backup_version
from .receipts import write_text


def free_disk_floor(settings):
    # Same precedence as need_env: .env, then the inherited environment, then 5 GiB. Empty is unset.
    return envfile.value(settings, "MIN_FREE_DISK_GIB") or os.environ.get("MIN_FREE_DISK_GIB") or "5"


def record_source_images(values):
    path = Path('.env')
    from .images import SOURCE_IMAGES
    required = {image.variable for image in SOURCE_IMAGES if not image.overlay}
    text = envfile.set_env_values(path.read_text(encoding='utf-8'),
                                  {key: pin for key, pin in values.items() if key in required}, require_existing=True)
    text = envfile.set_env_values(text, {key: pin for key, pin in values.items() if key not in required}, require_existing=False)
    write_text(path, text)


version_re = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
revision_re = re.compile(r"^[0-9a-f]{40}$")
digest_re = re.compile(r"^[0-9a-f]{64}$")
RELEASE_KEEP_COUNT = 3
UPDATE_DIRECTORY_PREFIX = "chronicle-update-"
RELEASE_SIGNER = "chronicle-release"
UPDATE_AVAILABLE_EXIT = 3
UPGRADE_FROM_MINIMUM = "2026.10.18"
UPGRADE_FLOOR_KEY = "upgrade_from_minimum"
ANDROID_COMPATIBILITY = dict(minimum_version_code=80, version_name="2026.10.31-internal.open.1", play_track="internal")
MIGRATIONS_KEY = "migrations"
FRESH_INSTALL_REQUIRED = "fresh install required for pre-reset releases; see docs/UPGRADE-ROLLBACK.md"
OWNER_FILE = ".chronicle-owner"


def compose_projects():
    rows = json.loads(run(["docker", "compose", "ls", "--all", "--format", "json"],
                          capture=True, check=True).stdout)
    require(isinstance(rows, list), "invalid Compose project inventory")
    return rows


def foreign_project(directory, project):
    owners = {Path(directory).resolve()}
    for row in compose_projects():
        if row.get("Name") != project:
            continue
        configs = [path for path in (row.get("ConfigFiles") or "").split(",") if path]
        if configs and not any(Path(path).resolve().parent in owners for path in configs):
            return ",".join(configs)
    return ""


def set_current_owner(directory, state):
    marker = Path(state) / OWNER_FILE
    require(not marker.is_symlink(), "unsafe release ownership marker")
    write_text(marker, str(Path(directory).resolve()) + "\n")
    # Ownership is not secret; predecessors scan the state directory for unreadable files.
    marker.chmod(0o644)


def require_current_owner(directory, state, project):
    directory, state = Path(directory).resolve(), Path(state).resolve()
    recovery = state / UPGRADE_LOCK / RECOVERY_FILE
    if recovery.is_file() and json.loads(recovery.read_text()).get("owner") == str(directory):
        return
    marker = state / OWNER_FILE
    require(not marker.is_symlink(), "unsafe release ownership marker")
    if marker.exists():
        owner = marker.read_text().strip()
        require(owner and Path(owner).is_absolute() and Path(owner).resolve() == directory,
                f"this release was superseded; use the active selfhost directory: {owner or marker}")
    require(not foreign_project(directory, project),
            "this release does not own the live Compose project; use the active selfhost directory")
    if not marker.exists():
        script = state / "reconcile.sh"
        if script.exists():
            owner = next((shlex.split(line)[1] for line in script.read_text().splitlines()
                          if line.startswith("cd ")), None)
            require(owner is not None and Path(owner).resolve() == directory,
                    f"this release was superseded; use the active selfhost directory: {owner or script}")
        set_current_owner(directory, state)


def release_bundles(parent):
    """Every unpacked release bundle under parent, with its validated manifest."""
    bundles = []
    candidates = [*parent.glob("chronicle-selfhost-*"), *parent.glob(f"{UPDATE_DIRECTORY_PREFIX}*/chronicle-selfhost-*")]
    for path in candidates:
        manifest = path / "release-manifest.json"
        if path.is_symlink() or not manifest.is_file():
            continue
        data = json.loads(manifest.read_text())
        version = data["release_version"]
        require(path.name == "chronicle-selfhost-" + version, "unexpected release directory name")
        require(all(isinstance(pin, str) and "@sha256:" in pin
                    and digest_re.fullmatch(pin.rsplit("@sha256:", 1)[1])
                    for pin in data.get("images", {}).values()), "invalid cleanup image pin")
        bundles.append((parse_version(version, manifest), path, data))
    return bundles


def protected_releases(bundles, state, active, rollback_target):
    """Bundles cleanup must keep: active, rollback and recovery owners, state holders, live Compose
    projects, and the newest RELEASE_KEEP_COUNT."""
    protected = {active}
    if rollback_target is not None:
        protected.add(Path(rollback_target).resolve())
    marker = state / UPGRADE_LOCK / RECOVERY_FILE
    if marker.exists():
        protected.add(Path(json.loads(marker.read_text())["owner"]).resolve().parent)
    protected.update(path for _, path, _ in bundles if path == state or path in state.parents)
    live_directories = {Path(config).resolve().parent for row in compose_projects()
                        for config in (row.get("ConfigFiles") or "").split(",") if config}
    for _, path, _ in bundles:
        host = path / "selfhost"
        if (os.path.lexists(host / ".env") or any(os.path.lexists(host / name) and
                (not (host / name).is_dir() or any((host / name).iterdir()))
                for name in ("backups", "tls", "operator-receipts", "upgrade-receipts"))
                or any(directory == path or path in directory.parents for directory in live_directories)):
            protected.add(path)
            print(f"Keeping {path}: deployment configuration, private state or Compose ownership")
    newest = sorted(bundles, key=lambda row: row[0], reverse=True)
    protected.update(path for _, path, _ in newest[:RELEASE_KEEP_COUNT])
    return protected


def retained_image_pins(bundles, owners):
    """Image pins the owning bundles' manifests and deployment settings still reference."""
    retained = {pin for _, path, data in bundles if path in owners for pin in data.get("images", {}).values()}
    for owner in owners:
        env = owner / "selfhost" / ".env"
        if env.is_file() and not env.is_symlink():
            settings = envfile.read_env(env)
            retained.update(envfile.value(settings, key) for key in settings if key.endswith("_IMAGE"))
    return retained


def cleanup_releases(parent, state, apply=False, rollback_target=None):
    parent, state, active = Path(parent).resolve(), Path(state).resolve(), Path.cwd().resolve().parent
    owner = state / OWNER_FILE
    if owner.is_file() and not owner.is_symlink():
        active = Path(owner.read_text().strip()).resolve().parent
    bundles = release_bundles(parent)
    protected = protected_releases(bundles, state, active, rollback_target)
    bundles.sort(key=lambda row: row[0], reverse=True)
    retained_images = retained_image_pins(bundles, protected)
    for _, path, data in bundles:
        if path in protected:
            continue
        print(f"{'Removing' if apply else 'Would remove'} {path} and its archive/checksum/signature")
        if apply:
            shutil.rmtree(path)
            for suffix in (".tar.gz", ".tar.gz.sha256", ".tar.gz.sha256.sig"):
                path.with_name(path.name + suffix).unlink(missing_ok=True)
            wrapper = path.parent
            if wrapper.name.startswith(UPDATE_DIRECTORY_PREFIX) and not any(wrapper.iterdir()):
                wrapper.rmdir()
    obsolete_images = {pin for _, _, data in bundles for pin in data.get("images", {}).values()} - retained_images
    for pin in sorted(obsolete_images):
        print(f"{'Removing unused' if apply else 'Would remove unused'} image {pin}")
        if apply:
            # Docker refuses removal while any container still references the image.
            run(["docker", "image", "rm", "--", pin], quiet=True, timeout=60)



def parse_version(version, manifest_path):
    match = version_re.fullmatch(version)
    if not match:
        raise ValueError(f"invalid release version in {manifest_path}: {version!r}")
    prerelease = match.group(4)
    if prerelease is None:
        pre_key = (1,)
    else:
        identifiers = []
        for part in prerelease.split("."):
            if part.isdigit():
                if len(part) > 1 and part.startswith("0"):
                    raise ValueError(
                        f"invalid numeric prerelease identifier in {manifest_path}: {part!r}"
                    )
                identifiers.append((0, int(part)))
            else:
                identifiers.append((1, part))
        pre_key = (0, *identifiers)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)), pre_key)


def require_upgrade(current, candidate):
    current_key = parse_version(current, "current release")
    floor = parse_version(candidate.get(UPGRADE_FLOOR_KEY, ""), "upgrade floor")
    require(current_key >= max(floor, parse_version(UPGRADE_FROM_MINIMUM, "reset floor")),
            FRESH_INSTALL_REQUIRED)
    require(current_key <= parse_version(candidate["release_version"], "candidate release"),
            "downgrade refused; use guarded rollback with its pre-update dump")


def require_release_files(bundle, manifest_path, files):
    for relative_text, expected in sorted(files.items()):
        if not isinstance(relative_text, str) or not isinstance(expected, str):
            raise ValueError(f"malformed file inventory entry in {manifest_path}")
        relative = PurePosixPath(relative_text)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != relative_text:
            raise ValueError(f"unsafe file path in {manifest_path}: {relative_text!r}")
        if not digest_re.fullmatch(expected):
            raise ValueError(f"invalid checksum for {relative_text} in {manifest_path}")
        candidate = bundle.joinpath(*relative.parts)
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"release file is missing or unsafe: {candidate}")
        actual = file_sha256(candidate)
        if actual != expected:
            raise ValueError(
                f"release file checksum mismatch: {candidate} (expected {expected}, got {actual})"
            )



def require_exact_inventory(bundle, manifest_path, files):
    actual_files = set()
    for entry in bundle.rglob("*"):
        if entry.is_symlink():
            raise ValueError(f"unsafe symlink in new release: {entry}")
        if entry.is_file():
            relative = entry.relative_to(bundle).as_posix()
            if relative != "release-manifest.json":
                actual_files.add(relative)
        elif not entry.is_dir():
            raise ValueError(f"unsupported file type in new release: {entry}")
    inventory_files = set(files)
    if actual_files != inventory_files:
        unlisted = sorted(actual_files - inventory_files)
        absent = sorted(inventory_files - actual_files)
        details = []
        if unlisted:
            details.append("unlisted files: " + ", ".join(unlisted[:10]))
        if absent:
            details.append("missing files: " + ", ".join(absent[:10]))
        raise ValueError(
            f"new release file inventory is not exact in {manifest_path}: "
            + "; ".join(details)
        )



def require_migration_inventory(manifest):
    migrations = manifest.get(MIGRATIONS_KEY)
    require(isinstance(migrations, dict) and bool(migrations) and all(
        isinstance(name, str) and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
        and PurePosixPath(name).as_posix() == name
        and re.fullmatch(r'V[0-9][0-9_]*__[^/]+\.sql', PurePosixPath(name).name)
        and isinstance(digest, str) and digest_re.fullmatch(digest) for name, digest in migrations.items()),
        'release manifest requires versioned migration hashes')


class ReleaseManifest(NamedTuple):
    manifest: dict
    version_key: tuple


def read_manifest(path, require_upgrade_script, *, discovery=False):
    manifest_path = Path(path)
    bundle = manifest_path.parent
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError(f"release manifest is missing or unsafe: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError(f"unsupported release manifest schema in {manifest_path}")
    parse_version(manifest.get(UPGRADE_FLOOR_KEY, ''), manifest_path)
    require_migration_inventory(manifest)
    version = manifest.get("release_version", "")
    version_key = parse_version(version, manifest_path)
    revision = manifest.get("source_revision", "")
    if not revision_re.fullmatch(revision):
        raise ValueError(f"invalid source revision in {manifest_path}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError(f"release manifest has no file inventory: {manifest_path}")
    required = {
        "selfhost/.env.example",
        "selfhost/chronicle",
        "selfhost/docker-compose.yml",
        "selfhost/restore.sh",
    }
    if discovery:
        required = {'selfhost/chronicle'}
    if require_upgrade_script and not discovery:
        required.update(
            {
                "selfhost/network-subnet.py",
                "selfhost/rotate-secret.sh",
                "selfhost/docs/DEPLOYMENT-COMPATIBILITY.md",
                "selfhost/docs/SECRET-ROTATION.md",
                "selfhost/docs/UNINSTALL-DATA-DELETION.md",
            }
        )
    missing = sorted(required - set(files))
    if missing:
        raise ValueError(
            f"release manifest omits required files in {manifest_path}: {', '.join(missing)}"
        )
    require_release_files(bundle, manifest_path, files)
    if require_upgrade_script:
        require_exact_inventory(bundle, manifest_path, files)
    if discovery:
        return ReleaseManifest(manifest, version_key)

    settings = envfile.read_env(bundle / "selfhost" / ".env.example")
    env = {key: envfile.value(settings, key) for key in settings}
    if env.get("RELEASE_VERSION") != version:
        raise ValueError(
            f"manifest version does not match selfhost/.env.example in {manifest_path}"
        )
    images = manifest.get("images")
    from .images import IMAGE_INPUTS_KEY, SOURCE_IMAGES
    expected_images = {image.component: env.get(image.variable) for image in SOURCE_IMAGES}
    if (not isinstance(images, dict) or not images or not expected_images.items() <= images.items()
            or any(not isinstance(pin, str) or not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", pin) for pin in images.values())):
        raise ValueError(
            f"manifest image inventory does not match selfhost/.env.example in {manifest_path}"
        )
    inputs = manifest.get(IMAGE_INPUTS_KEY)
    require(isinstance(inputs, dict) and bool(inputs) and set(inputs) == set(expected_images)
            and all(isinstance(tree, str) and revision_re.fullmatch(tree) for tree in inputs.values())
            and len(set(inputs.values())) == 1, 'first-party images require one immutable source inputs tree')
    return ReleaseManifest(manifest, version_key)



def release_command(directory, project, names):
    files = [directory / name for name in names]
    environment = os.environ.copy()
    env_file = directory / ".env"
    for path in [env_file, *files]:
        require(path.is_file() and not path.is_symlink(),
                f"validated Compose file is missing or unsafe: {path}")
        text = path.read_text()
        keys = re.findall(r"^\s*#?\s*([A-Z][A-Z0-9_]*)=", text, re.M)
        keys += re.findall(r"\$\{([A-Z][A-Z0-9_]*)", text)
        for key in keys:
            environment.pop(key, None)
    environment = {key: val for key, val in environment.items() if not key.startswith("COMPOSE_")}
    environment.update(CHRONICLE_HOST_UID=str(os.getuid()), CHRONICLE_HOST_GID=str(os.getgid()))
    return (["docker", "compose", "--env-file", str(env_file), "--project-name", project,
             *[arg for path in files for arg in ("-f", str(path))]], environment)


CERTIFICATE_MARKER = Path("tls") / ".applied-certificates"


def certificate_digest(state):
    """`sha256sum` lines for the certificates services load at start (the marker's format since 2026.9)."""
    lines = []
    for path in (Path(state) / "tls").rglob("*"):
        if path.is_symlink() or not path.is_file() or not (path.name.endswith("cert.pem") or path.suffix in (".crt", ".sha256")):
            continue
        try:
            lines.append(f"{file_sha256(path)}  {path}")
        except OSError:
            continue  # sha256sum skipped unreadable files too; services cannot load them either.
    return "\n".join(sorted(lines))


def certificates_changed(state, current):
    """Whether `current` differs in content from the digest recorded by the last verified start."""
    try:
        recorded = (Path(state) / CERTIFICATE_MARKER).read_text(encoding="utf-8")
    except OSError:
        return True
    # Hashes only: the same certificates under a differently spelled state path are still loaded.
    hashes = lambda digest: sorted(line.split()[0] for line in digest.splitlines() if line.strip())
    return hashes(recorded) != hashes(current)


def record_applied_certificates(state, digest):
    """Records the certificates a verified start loaded, so the next `up` does not recreate services."""
    write_text(Path(state) / CERTIFICATE_MARKER, digest)


def compose_release(directory, project, names, *args, **kwargs):
    command, environment = release_command(directory, project, names)
    before_compose(project, args)
    return run([*command, *args], cwd=directory, env=environment, **kwargs)


def postgres_major(version_text, image):
    match = re.search(r"PostgreSQL\)?\s+([0-9]+)", version_text)
    require(match, f"could not parse the PostgreSQL version in {image}")
    return int(match[1])


def postgres_sql(container, query):
    result = run(["docker", "exec", "-i", container, "/bin/bash", "-ceu",
                  'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 '
                  '-U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" -tAq -f -'],
                 capture=True, check=True, input=query)
    return result.stdout.strip()


ROLLBACK_CONNECTION = '-h 127.0.0.1 -U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" '
ROLLBACK_DUMP = ('export PGPASSWORD="$POSTGRES_PASSWORD"; psql -Xq -v ON_ERROR_STOP=1 ' + ROLLBACK_CONNECTION +
                 '-c ' + shlex.quote(CATALOG_GATE_SQL) + ' >/dev/null; exec pg_dump ' + ROLLBACK_CONNECTION +
                 '--no-owner ' + shlex.join(DUMP_EXCLUDE_OPTIONS))


def rollback_dump(command, path, **kwargs):
    with path.open("xb") as output:
        path.chmod(0o600)
        fcntl.flock(output, fcntl.LOCK_EX)
        with subprocess.Popen(command, stdout=subprocess.PIPE, **kwargs) as dump:
            try:
                with gzip.GzipFile(fileobj=output, mode="wb") as compressed:
                    version = kwargs.get('env', {}).get('RELEASE_VERSION') or installed_backup_version(Path(__file__).resolve().parents[1])
                    compressed.write(backup_release_header(version))
                    shutil.copyfileobj(dump.stdout, compressed)
                require(dump.wait() == 0, "database dump failed")
            finally:
                dump.stdout.close()
                if dump.poll() is None:
                    dump.terminate()
            dump.wait()
        output.flush()
        os.fsync(output.fileno())
    validate_dump(path)
    return file_sha256(path)
