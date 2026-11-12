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

from .common import DEFAULT_MIN_FREE_DISK_GIB, after_compose, before_compose, require, run, same_path
from . import envfile
from .dump import backup_release_header, CATALOG_GATE_SQL, DUMP_EXCLUDE_OPTIONS, file_sha256, validate_dump, installed_backup_version
from .receipts import write_text


def free_disk_floor(settings):
    # Same precedence as need_env: .env, then the inherited environment, then DEFAULT_MIN_FREE_DISK_GIB. Empty is unset.
    return envfile.value(settings, "MIN_FREE_DISK_GIB") or os.environ.get("MIN_FREE_DISK_GIB") or str(DEFAULT_MIN_FREE_DISK_GIB)


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
# The platform every first-party release image is built for (scripts/publish-images.sh release_platform,
# toolchain-manifest.yaml release_platform). Manifests since 2026.11.6 record it; earlier releases were
# linux/amd64 too, so a manifest without the key means linux/amd64.
RELEASE_PLATFORM = "linux/amd64"
PLATFORM_KEY = "platform"
platform_re = re.compile(r"^linux/[a-z0-9]+(?:/v[0-9]+)?$")


def manifest_platform(manifest):
    """The OS/architecture a release's images run on, from its manifest."""
    return manifest.get(PLATFORM_KEY, RELEASE_PLATFORM)
ANDROID_COMPATIBILITY = dict(minimum_version_code=80, version_name="2026.10.31-internal.open.1", play_track="internal")
MIGRATIONS_KEY = "migrations"
FRESH_INSTALL_REQUIRED = "fresh install required for pre-reset releases; see docs/UPGRADE-ROLLBACK.md"
OWNER_FILE = ".chronicle-owner"
# Updates since 2026.11.6 install each release at <root>/chronicle-releases/<version>/.
RELEASES_DIRECTORY = "chronicle-releases"
# The operator's original selfhost/ directory, recorded at the first update this release commits.
FRONT_DOOR_FILE = ".chronicle-front-door"
FRONT_DOOR_MARKER = "# chronicle-front-door"
# The front door's own launcher, kept so that release can run again after a rollback to it.
RELEASED_LAUNCHER = "chronicle.release"
FRONT_DOOR = """#!/usr/bin/env bash
# chronicle-front-door: written by ./chronicle update. Run ./chronicle from this directory as
# always: it runs the release that owns this deployment, recorded in {owner_file}.
set -eu
here=$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd -P)
owner=$(cat {owner_file} 2>/dev/null || true)
if [ "$owner" = "$here" ]; then
  exec "$here/{released}" ${{1+"$@"}}
fi
if [ -z "$owner" ] || [ ! -x "$owner/chronicle" ]; then
  # Never guess: an older release run against a newer stack starts the wrong configuration.
  echo "chronicle: no release owns this deployment: {owner_file} is ${{owner:+stale (}}${{owner:-missing}}${{owner:+)}}." >&2
  echo "Releases installed for it (run ./chronicle update from the one that last ran it):" >&2
  for release in {releases}/*/chronicle-selfhost-*/selfhost; do
    if [ -x "$release/chronicle" ]; then echo "  $release" >&2; fi
  done
  exit 1
fi
cd "$owner"
exec "$owner/chronicle" ${{1+"$@"}}
"""


def releases_root(selfhost):
    """The directory that holds the installed bundle, chronicle-update-* staging (2026.11.2's
    updater) and chronicle-releases/<version>/ (this one)."""
    parent = Path(selfhost).parent.parent
    while True:
        if parent.name.startswith(UPDATE_DIRECTORY_PREFIX):
            parent = parent.parent
        elif parent.parent.name == RELEASES_DIRECTORY:
            parent = parent.parent.parent
        else:
            return parent


def is_staging_directory(path):
    path = Path(path)
    return path.name.startswith(UPDATE_DIRECTORY_PREFIX) or path.parent.name == RELEASES_DIRECTORY


def is_front_door(launcher):
    try:
        with open(launcher, "rb") as handle:
            return FRONT_DOOR_MARKER.encode() in handle.read(512)
    except OSError:
        return False


def front_door_target(previous, state):
    """The directory whose ./chronicle the operator runs: the recorded front door while it still
    holds a launcher, else the release this update replaces (the first update, or a front door the
    operator moved or deleted; the record is rewritten when the update installs it)."""
    from .common import warn
    record = Path(state) / FRONT_DOOR_FILE
    require(not record.is_symlink(), "unsafe front door record")
    if record.is_file():
        front = Path(record.read_text().strip())
        if front.is_absolute() and (front / "chronicle").is_file():
            return front.resolve()
        warn(f"the recorded ./chronicle front door {front} no longer exists; "
             f"{Path(previous).resolve()} becomes the front door")
    return Path(previous).resolve()


def install_front_door(front, state):
    """Make front/chronicle forward to the owning release and record front as the front door.
    Idempotent, so a resumed committed update installs it again."""
    import shlex
    state, front = Path(state).resolve(), Path(front).resolve()
    record = state / FRONT_DOOR_FILE
    require(not record.is_symlink(), "unsafe front door record")
    launcher, released = front / "chronicle", front / RELEASED_LAUNCHER
    forwarder = FRONT_DOOR.format(owner_file=shlex.quote(str(state / OWNER_FILE)), released=RELEASED_LAUNCHER,
                                  releases=shlex.quote(str(releases_root(front) / RELEASES_DIRECTORY)))
    if not is_front_door(launcher):
        require(launcher.is_file() and not launcher.is_symlink(), f"no launcher to forward from in {front}")
        if not os.path.lexists(released):
            staged = released.with_name("." + RELEASED_LAUNCHER + ".partial")
            shutil.copy2(launcher, staged)
            os.replace(staged, released)
    if not is_front_door(launcher) or launcher.read_text() != forwarder:
        staged = launcher.with_name(".chronicle.front-door.partial")
        staged.write_text(forwarder)
        staged.chmod(0o755)
        os.replace(staged, launcher)
    if not record.is_file() or record.read_text().strip() != str(front):
        write_text(record, str(front) + "\n")
        record.chmod(0o644)
    return front


def current_owner(state):
    """The release directory .chronicle-owner names, or None."""
    marker = Path(state) / OWNER_FILE
    require(not marker.is_symlink(), "unsafe release ownership marker")
    if not marker.is_file():
        return None
    text = marker.read_text().strip()
    return Path(text).resolve() if text and Path(text).is_absolute() else None


def transfer_deployment(owner, front, state):
    """The commit step's ownership: .chronicle-owner names owner (checked by reading it back) and
    front/chronicle forwards to it. Both are mandatory; a failure here fails the update."""
    set_current_owner(owner, state)
    require(current_owner(state) == Path(owner).resolve(), f"could not record {owner} as the owning release")
    return install_front_door(front, state)


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
    if recovery.is_file() and same_path(json.loads(recovery.read_text()).get("owner"), directory):
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
    candidates = [*parent.glob("chronicle-selfhost-*"), *parent.glob(f"{UPDATE_DIRECTORY_PREFIX}*/chronicle-selfhost-*"),
                  *parent.glob(f"{RELEASES_DIRECTORY}/*/chronicle-selfhost-*")]
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
    front_door = state / FRONT_DOOR_FILE
    if front_door.is_file() and not front_door.is_symlink():
        protected.add(Path(front_door.read_text().strip()).resolve().parent)  # where the operator runs ./chronicle
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
    # Interrupted stagings leave <version>.<n> copies of one release: the newest distinct versions
    # are kept, each counted once, by a copy already kept for another reason or its first staging.
    copies: dict = {}
    for key, path, data in bundles:
        repeated = path.parent.parent.name == RELEASES_DIRECTORY and path.parent.name != data["release_version"]
        copies.setdefault(key, []).append((repeated, str(path), path))
    for key in sorted(copies, reverse=True)[:RELEASE_KEEP_COUNT]:
        if not any(path in protected for _, _, path in copies[key]):
            protected.add(min(copies[key])[2])
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
            if is_staging_directory(wrapper) and not any(wrapper.iterdir()):
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
    pre_key: tuple
    if prerelease is None:
        pre_key = (1,)
    else:
        identifiers: list[tuple[int, int | str]] = []
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


def require_release_files(bundle, manifest_path, files, *, installed=False):
    """Verify every listed file. For an installed release (installed=True) a file the operator
    edited or removed is returned as (relative path, path or None) instead of refused."""
    edits = []
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
            if installed:
                edits.append((relative_text, None))
                continue
            raise ValueError(f"release file is missing or unsafe: {candidate}")
        actual = file_sha256(candidate)
        if actual != expected:
            if installed:
                edits.append((relative_text, candidate))
                continue
            raise ValueError(
                f"release file checksum mismatch: {candidate} (expected {expected}, got {actual})"
            )
    return edits



LOCAL_EDITS_DIR = "local-edits"


def preserve_local_edits(previous_bundle, manifest, candidate_bundle, state):
    """Keep what the operator changed in the installed bundle: the update replaces the bundle, so
    each edited file is copied into the private state with a diff against the new release's copy."""
    import difflib
    from .common import warn
    from .receipts import write_text
    version = manifest["release_version"]
    target = Path(state) / LOCAL_EDITS_DIR / version
    found = require_release_files(previous_bundle, previous_bundle / "release-manifest.json", manifest["files"], installed=True)
    edits = []
    for relative, path in found:
        if relative == "selfhost/chronicle" and path is not None and is_front_door(path):
            # The front door forwarder is ours; the release's own launcher is kept beside it.
            path = path.with_name(RELEASED_LAUNCHER)
            if not path.is_file() or path.is_symlink():
                path = None
            elif file_sha256(path) == manifest["files"][relative]:
                continue
        edits.append((relative, path))
    for relative, path in edits:
        if path is None:
            warn(f"{relative} is missing or replaced by a link in {previous_bundle}; the update installs the new release's copy")
            continue
        replacement = Path(candidate_bundle).joinpath(*PurePosixPath(relative).parts)
        edited = path.read_bytes().decode("utf-8", errors="replace")
        released = replacement.read_bytes().decode("utf-8", errors="replace") if replacement.is_file() else ""
        kept = target.joinpath(*PurePosixPath(relative).parts)
        kept.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        write_text(kept, edited)
        write_text(kept.with_name(kept.name + ".diff"), "".join(difflib.unified_diff(
            released.splitlines(keepends=True), edited.splitlines(keepends=True),
            fromfile=f"{Path(candidate_bundle).name}/{relative}", tofile=f"edited {version}/{relative}")))
        warn(f"{relative} was edited in {previous_bundle}; the update installs the new release's copy. "
             f"Your copy and its diff against the new release are in {kept.parent}; reapply what you "
             "still need (deployment settings belong in .env).")
    return edits


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


def read_manifest(path, require_upgrade_script, *, discovery=False, installed=False):
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
    platform = manifest_platform(manifest)
    if not isinstance(platform, str) or not platform_re.fullmatch(platform):
        raise ValueError(f"invalid release platform {platform!r} in {manifest_path}")
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
    require_release_files(bundle, manifest_path, files, installed=installed)
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
    # Before anything is pulled: each first-party digest must carry the release's cosign signature and
    # provenance (releases from before 2026.11.6 ship none and pass unchanged).
    from .image_signatures import verify_release_images
    verify_release_images(bundle, manifest)
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
    # Derived from this release's .env on every call, never read from it (chronicle_ops/egress.py).
    from .egress import ALERT_EGRESS_ENV, environment_alert_egress
    environment[ALERT_EGRESS_ENV] = environment_alert_egress(env_file)
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
    volumes = before_compose(project, args)
    try:
        return run([*command, *args], cwd=directory, env=environment, **kwargs)
    finally:
        after_compose(project, volumes)


def postgres_major(version_text, image):
    match = re.search(r"PostgreSQL\)?\s+([0-9]+)", version_text)
    if match is None:
        raise ValueError(f"could not parse the PostgreSQL version in {image}")
    return int(match[1])


def postgres_sql(container, query):
    result = run(["docker", "exec", "-i", container, "/bin/bash", "-ceu",
                  'PGPASSWORD="${POSTGRES_PASSWORD:-$(cat "$POSTGRES_PASSWORD_FILE")}" exec psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 '
                  '-U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" -tAq -f -'],
                 capture=True, check=True, input=query)
    return result.stdout.strip()


ROLLBACK_CONNECTION = '-h 127.0.0.1 -U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" '
ROLLBACK_DUMP = ('export PGPASSWORD="${POSTGRES_PASSWORD:-$(cat "$POSTGRES_PASSWORD_FILE")}"; psql -Xq -v ON_ERROR_STOP=1 ' + ROLLBACK_CONNECTION +
                 '-c ' + shlex.quote(CATALOG_GATE_SQL) + ' >/dev/null; exec pg_dump ' + ROLLBACK_CONNECTION +
                 '--no-owner ' + shlex.join(DUMP_EXCLUDE_OPTIONS))


def rollback_dump(command, path, **kwargs):
    with path.open("xb") as output:
        path.chmod(0o600)
        fcntl.flock(output, fcntl.LOCK_EX)
        with subprocess.Popen(command, stdout=subprocess.PIPE, **kwargs) as dump:
            if dump.stdout is None:  # stdout=PIPE always opens it
                raise ValueError("database dump has no output pipe")
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
