"""Discover, verify and stage signed selfhost releases before upgrade."""

from dataclasses import dataclass
import json
import os
from .dump import file_sha256
from .release import RELEASE_SIGNER, UPDATE_AVAILABLE_EXIT, UPDATE_DIRECTORY_PREFIX, FRESH_INSTALL_REQUIRED, UPGRADE_FROM_MINIMUM, require_upgrade, free_disk_floor, parse_version, read_manifest, require_current_owner
from .envfile import read_env, value
from .common import acquire_operation_lock, compose_project, release_operation_lock, require_storage, run, transfer_timeout, warn, UPDATE_PEAK_BYTES
from .receipts import sync_directory, write_text, write_json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

def version_key(version):
    if not isinstance(version, str):
        raise ValueError("missing release_version or release tag")
    return parse_version(version.removeprefix("v"), "release metadata")


# Bound every download and the archive inventory before anything is parsed or extracted.
MAX_METADATA_BYTES = 1024 * 1024
MAX_CATALOG_BYTES = 16 * MAX_METADATA_BYTES
HANDOFF_FILE = ".chronicle-update-handoff.json"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20000
MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024

def curl(url, output=subprocess.PIPE, max_bytes=MAX_METADATA_BYTES):
    if not isinstance(url, str) or urlparse(url).scheme not in ("http", "https"):
        raise ValueError("release URL must use http or https")
    return run(
        ["curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--location",
         "--proto", "=http,https", "--proto-redir", "=http,https",
         "--max-filesize", str(max_bytes),
         "--connect-timeout", "30", "--max-time", str(transfer_timeout()), url],
        stdout=output, text=False, check=True).stdout

def extract_release(archive_path, name, version):
    asset_root = archive_path.parent
    extracted = asset_root / name
    with tarfile.open(archive_path, "r:gz") as archive:
        members = []
        unpacked = 0
        for member in archive:
            members.append(member)
            unpacked += member.size
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError(f"release archive has too many members (> {MAX_ARCHIVE_MEMBERS})")
            if unpacked > MAX_UNPACKED_BYTES:
                raise ValueError(f"release archive unpacks to more than {MAX_UNPACKED_BYTES} bytes")
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] != name or not (member.isdir() or member.isfile())
                    or path in seen):
                raise ValueError(f"unsafe or duplicate release archive member: {member.name!r}")
            seen.add(path)
        manifests = [m for m in members if m.name == f"{name}/release-manifest.json" and m.isfile()]
        if len(manifests) != 1:
            raise ValueError("missing new release manifest in archive")
        with archive.extractfile(manifests[0]) as source:
            new_manifest = json.load(source)
        if new_manifest.get("release_version") != version:
            raise ValueError("new release manifest does not match the requested release version")
        operators = [m for m in members if m.name == f"{name}/selfhost/chronicle" and m.isfile()]
        if len(operators) != 1 or not operators[0].mode & 0o111:
            raise ValueError("missing executable selfhost/chronicle in release archive")
        extracted.mkdir(mode=0o755)
        # This script runs under umask 077, so every mkdir would land at 0700. Compose
        # bind-mounts selfhost/ into containers running as their image's user (config-guard
        # as the postgres uid): an owner-only directory fails there as a bare "Permission
        # denied". Set directory modes explicitly; archive members keep their own mode.
        extracted.chmod(0o755)

        def ensure_dir(path):
            if not path.is_dir():
                ensure_dir(path.parent)
                path.mkdir()
                path.chmod(0o755)

        # Extract only ordinary files/directories after validating the entire inventory.
        for member in members:
            target = asset_root / member.name
            if member.isdir():
                ensure_dir(target)
                target.chmod(member.mode & 0o777)
            else:
                ensure_dir(target.parent)
                with archive.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                    target.chmod(member.mode & 0o777)
                    output.flush()
                    os.fsync(output.fileno())
    retained, _ = read_manifest(extracted / "release-manifest.json", True, discovery=True)
    if retained != new_manifest:
        raise ValueError("extraction does not match the verified archive manifest")
    return extracted

def show_changelog(extracted, current, version):
    current_key = version_key(current)
    latest_key = version_key(version)
    changelog = extracted / "CHANGELOG.md"
    if not changelog.is_file() or changelog.is_symlink():
        raise ValueError("release archive is missing a regular CHANGELOG.md")
    sections = []
    section_version = None
    section_lines = []
    heading = re.compile(r"^## \[([^\]]+)\]$")

    def save_section():
        if section_version is not None:
            sections.append((section_version, version_key(section_version), "\n".join(section_lines).strip()))

    for line in changelog.read_text(encoding="utf-8").splitlines():
        match = heading.fullmatch(line)
        if match:
            save_section()
            section_lines = []
            candidate = match[1]
            try:
                version_key(candidate)
            except ValueError:
                section_version = None
            else:
                section_version = candidate
        elif section_version is not None:
            section_lines.append(line)
    save_section()

    target_sections = [section for section in sections if section[1] == latest_key]
    if len(target_sections) != 1:
        raise ValueError("verified CHANGELOG.md must contain exactly one entry for the target release")
    applicable_sections = [section for section in sections if current_key <= section[1] <= latest_key]
    applicable_keys = [section[1] for section in applicable_sections]
    if applicable_keys != sorted(applicable_keys, reverse=True):
        raise ValueError("verified CHANGELOG.md release entries are not ordered newest first")
    print(f"Verified bundle changelog ({current} through {version}):", flush=True)
    for section_version, _, section_text in applicable_sections:
        print(f"\n## [{section_version}]", flush=True)
        print(section_text or "(no release notes)", flush=True)


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    url: str


@dataclass(frozen=True)
class ReleaseAssets:
    archive: ReleaseAsset
    checksum: ReleaseAsset
    signature: ReleaseAsset

    def all(self) -> tuple[ReleaseAsset, ...]:
        return (self.archive, self.checksum, self.signature)


def release_assets(release, archive_name) -> ReleaseAssets:
    checksum_name = archive_name + ".sha256"
    signature_name = checksum_name + ".sig"
    def asset(name: str) -> ReleaseAsset:
        matches = [a for a in release.get("assets", []) if a.get("name") == name]
        if len(matches) != 1 or not matches[0].get("browser_download_url"):
            kind = "release signature asset" if name == signature_name else "release asset"
            raise ValueError(f"missing or ambiguous {kind}: {name}")
        return ReleaseAsset(name=name, url=matches[0]["browser_download_url"])
    return ReleaseAssets(archive=asset(archive_name), checksum=asset(checksum_name), signature=asset(signature_name))

def verify_download(asset_root, assets: ReleaseAssets, key, *, directory):
    checksum = asset_root / assets.checksum.name
    with tempfile.TemporaryDirectory(prefix=".chronicle-signature-", dir=directory) as signature_directory:
        allowed = Path(signature_directory) / "allowed_signers"
        write_text(allowed, f"{RELEASE_SIGNER} {key}\n")
        with checksum.open("rb") as message:
            try:
                run(
                    ["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", RELEASE_SIGNER,
                     "-n", RELEASE_SIGNER, "-s", str(asset_root / assets.signature.name)],
                    stdin=message, capture=True, stderr=subprocess.PIPE, timeout=30, check=True)
            except subprocess.CalledProcessError:
                raise ValueError("invalid release signature; nothing extracted or executed") from None
    # Restrict the checksum file to exactly this archive, then verify it in-process:
    # Use the same stdlib hash on Linux and macOS.
    entry = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]" + re.escape(assets.archive.name) + r"\n?",
                         checksum.read_text())
    if not entry:
        raise ValueError("bad checksum file: expected one SHA-256 entry for the release archive")
    if file_sha256(asset_root / assets.archive.name) != entry[1].lower():
        raise ValueError("bad checksum: release archive verification failed; nothing extracted")


def download_assets(assets: ReleaseAssets, asset_root):
    for asset in assets.all():
        path = asset_root / asset.name
        with path.open("xb") as output:
            try:
                curl(asset.url, output, MAX_ARCHIVE_BYTES if asset == assets.archive else MAX_METADATA_BYTES)
            except subprocess.CalledProcessError:
                if asset == assets.signature:
                    raise ValueError("missing or unavailable release signature; nothing extracted or executed")
                raise
            output.flush()
            os.fsync(output.fileno())

# GitHub's documented maximum page size; enumerate all pages before choosing a version.
RELEASES_PAGE_SIZE = 100


def latest_stable_release(releases):
    if any(not isinstance(release, dict) or type(release.get('draft')) is not bool
           or type(release.get('prerelease')) is not bool for release in releases):
        raise ValueError("release catalog requires explicit draft and prerelease flags")
    candidates = [release for release in releases if not release['draft'] and not release['prerelease']
                  and is_stable_release(release["tag_name"])]
    if not candidates:
        raise ValueError("no published stable releases")
    return max(candidates, key=lambda release: version_key(release["tag_name"]))


def fetch_published_releases():
    url = os.environ.get("CHRONICLE_RELEASES_URL", f"https://api.github.com/repos/uzaira0/methodic/releases?per_page={RELEASES_PAGE_SIZE}")
    releases = []
    page = 1
    while True:
        rows = json.loads(curl(url, max_bytes=MAX_CATALOG_BYTES))
        if not isinstance(rows, list):
            raise ValueError("release catalog must be an array")
        releases.extend(rows)
        if len(rows) < RELEASES_PAGE_SIZE:
            return releases
        page += 1
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query), per_page=str(RELEASES_PAGE_SIZE), page=str(page))
        url = urlunsplit(parts._replace(query=urlencode(query)))




def is_stable_release(version):
    return version_key(version)[3][0] == 1




def apply_update(selfhost, settings, assets, version, current):
    state = (selfhost / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve()
    public_key = selfhost / 'release-signing.pub'
    if not public_key.is_file() or public_key.is_symlink():
        raise ValueError('missing installed release-signing.pub')
    key = public_key.read_text().strip()
    if not key.startswith('ssh-ed25519 ') or '\n' in key or '\r' in key:
        raise ValueError('invalid installed release-signing.pub')
    require_storage(state, compose_project(settings),
                    free_disk_floor(settings), UPDATE_PEAK_BYTES)
    # A repair gets its own directory, so the active operator package is never overwritten.
    parent = selfhost.parent.parent
    while parent.name.startswith(UPDATE_DIRECTORY_PREFIX):
        parent = parent.parent
    directory = Path(tempfile.mkdtemp(prefix=UPDATE_DIRECTORY_PREFIX, dir=parent))
    staged = False
    try:
        download_assets(assets, directory)
        verify_download(directory, assets, key, directory=directory)
        extracted = extract_release(directory / assets.archive.name,
                                    f'chronicle-selfhost-{version}', version)
        candidate, _ = read_manifest(extracted / 'release-manifest.json', True, discovery=True)
        require_upgrade(current, candidate)
        for path in [extracted, *(p for p in extracted.rglob('*') if p.is_dir())]:
            sync_directory(path)
        write_json(state / HANDOFF_FILE, dict(previous=str(selfhost), owner=str(extracted / 'selfhost')))
        staged = True
        exec_candidate(extracted / 'selfhost', selfhost)  # os.execv: returns only by raising OSError
    finally:
        # A successful exec replaces this process. Only staging/exec failures return here;
        # process death instead leaves the durable handoff for the next invocation.
        if staged:
            (state / HANDOFF_FILE).unlink(missing_ok=True)
        shutil.rmtree(directory)


def exec_candidate(candidate, previous):
    from .common import LOCK_FD_ENV
    descriptor = os.environ.get(LOCK_FD_ENV, '')
    if descriptor.isdigit():
        os.set_inheritable(int(descriptor), True)
    launcher = str(candidate / 'chronicle')
    os.execv(launcher, [launcher, 'update', '--apply-from', str(previous)])


def apply_candidate(previous):
    from .upgrade import recover_update, upgrade
    from .reconcile import UPGRADE_LOCK, RECOVERY_FILE
    from .release import cleanup_releases
    from .common import require
    previous, candidate = Path(previous).resolve(), Path.cwd().resolve()
    settings = read_env(previous / '.env')
    state = (previous / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve()
    descriptor = acquire_operation_lock(state)
    try:
        record = state / UPGRADE_LOCK / RECOVERY_FILE
        handoff = state / HANDOFF_FILE
        data = json.loads((record if record.exists() else handoff).read_text())
        require(data['previous'] == str(previous) and data['owner'] == str(candidate),
                'candidate does not match the verified update handoff')
        status = 0 if recover_update(state) else upgrade(previous, candidate)
        if not record.exists():
            handoff.unlink(missing_ok=True)
            if status:
                os.chdir(previous)
                wrapper = candidate.parent.parent
                require(wrapper.name.startswith(UPDATE_DIRECTORY_PREFIX), 'unexpected candidate staging directory')
                (candidate / '.env').unlink(missing_ok=True)
            parent = candidate.parent.parent
            while parent.name.startswith(UPDATE_DIRECTORY_PREFIX):
                parent = parent.parent
            try:
                cleanup_releases(parent, state, apply=True, rollback_target=previous.parent)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                warn(f'release cleanup incomplete: {error}; retry ./chronicle cleanup')
            if status and wrapper.exists():
                shutil.rmtree(wrapper)
        return status
    finally:
        release_operation_lock(descriptor)


def select_release(releases, version=None):
    if version is None:
        return latest_stable_release(releases)
    version_key(version)
    matches = [release for release in releases if not release.get('draft', True)
               and release.get('tag_name', '').removeprefix('v') == version.removeprefix('v')]
    if len(matches) != 1:
        raise ValueError('requested release is missing or ambiguous')
    return matches[0]


def update(check=False, version=None):
    descriptor = None
    try:
        selfhost = Path.cwd().resolve()
        manifest = selfhost.parent / 'release-manifest.json'
        if not manifest.is_file() or manifest.is_symlink():
            raise ValueError(f'missing current release manifest: {manifest}')
        current = json.loads(manifest.read_text()).get('release_version')
        current_key = version_key(current)
        env_file = selfhost / '.env'
        if not env_file.is_file() or env_file.is_symlink() or env_file.stat().st_mode & 0o777 != 0o600:
            raise ValueError("update requires the active release's regular .env with mode 0600")
        settings = read_env(env_file)
        state = (selfhost / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve()
        if not check:
            if current_key < version_key(UPGRADE_FROM_MINIMUM):
                raise ValueError(FRESH_INSTALL_REQUIRED)
            descriptor = acquire_operation_lock(state)
            from .reconcile import UPGRADE_LOCK, RECOVERY_FILE
            recovery = state / UPGRADE_LOCK / RECOVERY_FILE
            handoff = state / HANDOFF_FILE
            if recovery.exists() or handoff.exists():
                record = json.loads((recovery if recovery.exists() else handoff).read_text())
                exec_candidate(Path(record['owner']), Path(record['previous']))
            settings = read_env(env_file)
            if (selfhost / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve() != state:
                raise ValueError('state changed while acquiring lock; retry update')
        require_current_owner(selfhost, state, compose_project(settings))
        release = select_release(fetch_published_releases(), version)
        latest = release['tag_name']
        latest_key = version_key(latest)
        print(f'Current: {current}; selected: {latest}', flush=True)
        if check:
            return UPDATE_AVAILABLE_EXIT if latest_key > current_key else 0
        if latest_key < current_key:
            raise ValueError('downgrade refused; use guarded rollback with its pre-update dump')
        version = latest.removeprefix('v')
        assets = release_assets(release, f'chronicle-selfhost-{version}.tar.gz')
        return apply_update(selfhost, settings, assets, version, current)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        raise ValueError(f'update failed: {error}') from None
    finally:
        release_operation_lock(descriptor)
