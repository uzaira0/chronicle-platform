"""Discover, verify and stage signed selfhost releases before upgrade."""

from dataclasses import dataclass
import json
import os
from .dump import file_sha256
from .release import RELEASE_SIGNER, RELEASES_DIRECTORY, UPDATE_AVAILABLE_EXIT, FRESH_INSTALL_REQUIRED, releases_root, UPGRADE_FROM_MINIMUM, require_upgrade, free_disk_floor, parse_version, read_manifest, require_current_owner
from .envfile import read_env, value
from .common import acquire_operation_lock, compose_project, release_operation_lock, require_storage, run, same_path, transfer_timeout, warn, UPDATE_PEAK_BYTES
from .receipts import sync_directory, write_text, write_json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlsplit, urlunsplit

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

# Waits between attempts of one release download; all attempts share transfer_timeout().
RETRY_DELAYS = (1, 2, 4, 8)
# curl exits a retry cannot change: unsupported protocol, bad URL, redirect loop, file too large.
PERMANENT_CURL_EXITS = frozenset({1, 3, 47, 63})


def curl(url, output=subprocess.PIPE, max_bytes=MAX_METADATA_BYTES):
    """Fetch one release catalog or asset. This is the only egress in the bundle, so it alone
    honours the operator's proxy (curl reads https_proxy/HTTPS_PROXY and no_proxy); every probe
    of the deployment passes --noproxy. Failed attempts retry with backoff until the overall
    transfer deadline; a file output is rewritten from the start on each attempt."""
    if not isinstance(url, str) or urlparse(url).scheme not in ("http", "https"):
        raise ValueError("release URL must use http or https")
    deadline = time.monotonic() + transfer_timeout()
    delays = iter(RETRY_DELAYS)
    while True:
        remaining = int(deadline - time.monotonic())
        if hasattr(output, "seek"):
            output.seek(0)
            output.truncate()
        try:
            return run(
                ["curl", "--fail", "--silent", "--show-error", "--location",
                 "--proto", "=http,https", "--proto-redir", "=http,https",
                 "--max-filesize", str(max_bytes),
                 "--connect-timeout", "30", "--max-time", str(max(1, remaining)), url],
                stdout=output, text=False, check=True).stdout
        except subprocess.CalledProcessError as error:
            delay = next(delays, None)
            if (delay is None or error.returncode in PERMANENT_CURL_EXITS
                    or time.monotonic() + delay >= deadline):
                raise
            warn(f"download from {urlsplit(url).hostname} failed (curl exit {error.returncode}); retrying in {delay} s")
            time.sleep(delay)

def member_file(archive, member):
    """The open file of a regular archive member; tarfile returns None only for other kinds."""
    source = archive.extractfile(member)
    if source is None:
        raise ValueError(f"release archive member is not a regular file: {member.name!r}")
    return source


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
        with member_file(archive, manifests[0]) as source:
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
                with member_file(archive, member) as source, target.open("xb") as output:
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
    sections: list = []
    section_version = None
    section_lines: list[str] = []
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


# Key rotation (CI-U7). A release signed by a new key carries the new public key and a signature
# over it by the key installed servers trust, in its own namespace: a checksum signature (namespace
# RELEASE_SIGNER) can never be replayed as an endorsement. Maintainer: scripts/endorse-release-key.sh.
KEY_ROTATION_NAMESPACE = "chronicle-release-key"
ROTATED_KEY_ASSET = "release-signing.pub"
ROTATION_ENDORSEMENT_ASSET = ROTATED_KEY_ASSET + ".sig"


@dataclass(frozen=True)
class ReleaseAssets:
    archive: ReleaseAsset
    checksum: ReleaseAsset
    signature: ReleaseAsset
    rotated_key: "ReleaseAsset | None" = None
    endorsement: "ReleaseAsset | None" = None

    def all(self) -> tuple[ReleaseAsset, ...]:
        rotation = (self.rotated_key, self.endorsement) if self.rotated_key and self.endorsement else ()
        return (self.archive, self.checksum, self.signature, *rotation)


def release_assets(release, archive_name) -> ReleaseAssets:
    checksum_name = archive_name + ".sha256"
    signature_name = checksum_name + ".sig"
    rows = release.get("assets", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("malformed release asset list")
    def asset(name: str) -> ReleaseAsset:
        matches = [a for a in rows if a.get("name") == name]
        if len(matches) != 1 or not matches[0].get("browser_download_url"):
            kind = "release signature asset" if name == signature_name else "release asset"
            raise ValueError(f"missing or ambiguous {kind}: {name}")
        return ReleaseAsset(name=name, url=matches[0]["browser_download_url"])
    def optional(name: str) -> "ReleaseAsset | None":
        return asset(name) if any(row.get("name") == name for row in rows) else None
    rotated_key, endorsement = optional(ROTATED_KEY_ASSET), optional(ROTATION_ENDORSEMENT_ASSET)
    if bool(rotated_key) != bool(endorsement):
        raise ValueError(f"a key rotation needs both {ROTATED_KEY_ASSET} and {ROTATION_ENDORSEMENT_ASSET}")
    return ReleaseAssets(archive=asset(archive_name), checksum=asset(checksum_name), signature=asset(signature_name),
                         rotated_key=rotated_key, endorsement=endorsement)


def ssh_verifies(message, signature, key, namespace, directory):
    """Whether signature is key's signature over the file message in namespace."""
    with tempfile.TemporaryDirectory(prefix=".chronicle-signature-", dir=directory) as signature_directory:
        allowed = Path(signature_directory) / "allowed_signers"
        write_text(allowed, f"{RELEASE_SIGNER} namespaces=\"{namespace}\" {key}\n")
        with Path(message).open("rb") as stream:
            result = run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", RELEASE_SIGNER,
                          "-n", namespace, "-s", str(signature)],
                         stdin=stream, capture=True, stderr=subprocess.PIPE, timeout=30)
    return result.returncode == 0


def valid_public_key(key):
    return key.startswith("ssh-ed25519 ") and "\n" not in key and "\r" not in key


def endorsed_key(asset_root, assets: ReleaseAssets, key, directory):
    """The rotated key the release names, once the installed key's endorsement over it verifies."""
    if not (assets.rotated_key and assets.endorsement):
        return None
    path = asset_root / assets.rotated_key.name
    rotated = path.read_text().strip()
    if not valid_public_key(rotated) or rotated == key:
        raise ValueError(f"invalid rotated release key in {assets.rotated_key.name}; nothing extracted or executed")
    if not ssh_verifies(path, asset_root / assets.endorsement.name, key, KEY_ROTATION_NAMESPACE, directory):
        raise ValueError("the release's new signing key is not endorsed by the installed release key; "
                         "nothing extracted or executed")
    return rotated


def verify_download(asset_root, assets: ReleaseAssets, key, *, directory):
    """Verify the checksum signature and the archive; return the key that signed the release: the
    installed key, or a rotated key the installed key endorsed (the bundle must then ship it)."""
    checksum = asset_root / assets.checksum.name
    signature = asset_root / assets.signature.name
    signer = key
    if not ssh_verifies(checksum, signature, key, RELEASE_SIGNER, directory):
        signer = endorsed_key(asset_root, assets, key, directory)
        if signer is None or not ssh_verifies(checksum, signature, signer, RELEASE_SIGNER, directory):
            raise ValueError("invalid release signature; nothing extracted or executed")
    # Restrict the checksum file to exactly this archive, then verify it in-process:
    # Use the same stdlib hash on Linux and macOS.
    entry = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]" + re.escape(assets.archive.name) + r"\n?",
                         checksum.read_text())
    if not entry:
        raise ValueError("bad checksum file: expected one SHA-256 entry for the release archive")
    if file_sha256(asset_root / assets.archive.name) != entry[1].lower():
        raise ValueError("bad checksum: release archive verification failed; nothing extracted")
    return signer


def require_bundled_key(extracted, signer):
    """A release signed by a rotated key must install that key, or its own next update would fail."""
    bundled = extracted / "selfhost" / ROTATED_KEY_ASSET
    if bundled.is_symlink() or not bundled.is_file() or bundled.read_text().strip() != signer:
        raise ValueError("the release does not ship the key that signed it (selfhost/release-signing.pub); "
                         "nothing executed")


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
# 2,000 releases: decades of this project's cadence. A source that keeps returning full pages
# beyond that is broken, and the next source is tried instead of looping forever.
MAX_CATALOG_PAGES = 20


def release_problem(release):
    """Why a catalog row cannot be offered, or None. A malformed row is skipped, never fatal."""
    if not isinstance(release, dict):
        return "not a release object"
    if type(release.get('draft')) is not bool:
        return "no explicit draft flag"
    try:
        version_key(release.get('tag_name'))
    except ValueError:
        return "its tag is not a release version"
    return None


def offered(release):
    """The one eligibility rule for every release source: a published (not draft) release whose
    tag is a stable version, the version its signed manifest must carry. GitHub's pre-release flag
    is not consulted: the feed cannot show it, and publish-images.sh sets it from the tag."""
    return release_problem(release) is None and not release['draft'] and is_stable_release(release['tag_name'])


def describe(release):
    return repr(release.get('tag_name', '?')) if isinstance(release, dict) else 'entry'


# A catalog row built from the releases feed (feed_releases): GitHub lists every tag there.
FEED_ROW = "from_feed"
ASSET_PROBE_SECONDS = 60


def asset_missing(url):
    """Whether GitHub answers 404 for a release asset: one request, redirects followed, through
    the operator's proxy like curl(), nothing kept. A refusal, another status or no answer is not
    "missing"; only GitHub saying the asset does not exist is."""
    try:
        answer = run(["curl", "--silent", "--location", "--proto", "=http,https", "--proto-redir", "=http,https",
                      "--max-filesize", str(MAX_METADATA_BYTES), "--output", os.devnull, "--write-out", "%{http_code}",
                      "--connect-timeout", "30", "--max-time", str(ASSET_PROBE_SECONDS), url],
                     capture=True, quiet=True, timeout=ASSET_PROBE_SECONDS + 30)
    except (OSError, subprocess.SubprocessError):
        return False
    return (answer.stdout or "").strip() == "404"


def tag_without_release(release):
    """Whether a feed row is a git tag with no release behind it. GitHub's releases feed lists
    every tag, with or without a release (measured 2026-11-11: torvalds/linux has no release and
    its feed lists ten tags), and such a tag has no assets: its checksum answers 404. The tag is
    then skipped with a warning. API rows are releases and are never asked about."""
    if release.get(FEED_ROW) is not True:
        return False
    checksum = release_assets(release, f"chronicle-selfhost-{release['tag_name'].removeprefix('v')}.tar.gz").checksum
    if not asset_missing(checksum.url):
        return False
    warn(f"skipping tag {release['tag_name']!r}: the releases feed lists it, but it has no release "
         f"({checksum.name} answered 404)")
    return True


def latest_stable_release(releases, require_assets=False):
    candidates = []
    for release in releases:
        problem = release_problem(release)
        stable = offered(release)
        if stable and require_assets:
            # A release whose assets are still uploading is not offered yet.
            try:
                release_assets(release, f"chronicle-selfhost-{release['tag_name'].removeprefix('v')}.tar.gz")
            except ValueError as error:
                problem = str(error)
        if problem:
            warn(f"skipping published release {describe(release)}: {problem}")
        elif stable:
            candidates.append(release)
    # Newest first; a feed row is offered once its release is known to exist (tag_without_release).
    for release in sorted(candidates, key=lambda release: version_key(release["tag_name"]), reverse=True):
        if not (require_assets and tag_without_release(release)):
            return release
    raise ValueError("no published stable releases")


RELEASES_REPOSITORY = "uzaira0/chronicle-platform"
API_RELEASES_URL = f"https://api.github.com/repos/{RELEASES_REPOSITORY}/releases?per_page={RELEASES_PAGE_SIZE}"
# The releases feed and download URLs are served without the REST API's 60-requests-an-hour
# limit for unauthenticated hosts. The feed lists git tags: a published release has one, a draft
# has none until it is published, and a tag without a release is listed too (tag_without_release).
FEED_RELEASES_URL = f"https://github.com/{RELEASES_REPOSITORY}/releases.atom"
# The feed as GitHub serves it: the feed's own repository in its alternate link, then one <entry>
# per release whose <link> to the release comes before its <content>. The owner and name are
# whatever the feed says: GitHub redirects the feed of a renamed repository and every link in the
# answer then carries the new name, so a pattern holding RELEASES_REPOSITORY found no release once
# uzaira0/methodic was renamed (2026-11-10).
FEED_CDATA = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
FEED_REPOSITORY = re.compile(r'<link\b[^>]*\bhref="https://github\.com/([^"/?#]+/[^"/?#]+)/releases"')
FEED_ENTRY = re.compile(r"<entry\b[^>]*>(.*?)</entry>", re.DOTALL)
FEED_TAG = re.compile(r'<link\b[^>]*\bhref="https://github\.com/[^"/?#]+/[^"/?#]+/releases/tag/([^"/?#]+)"')


def catalog_releases(url):
    releases = []
    page = 1
    while True:
        rows = json.loads(curl(url, max_bytes=MAX_CATALOG_BYTES))
        if not isinstance(rows, list):
            raise ValueError("release catalog must be an array")
        releases.extend(rows)
        if len(rows) < RELEASES_PAGE_SIZE:
            return releases
        if page >= MAX_CATALOG_PAGES:
            raise ValueError(f"release catalog has more than {MAX_CATALOG_PAGES} pages")
        page += 1
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query), per_page=str(RELEASES_PAGE_SIZE), page=str(page))
        url = urlunsplit(parts._replace(query=urlencode(query)))


def feed_tags(feed):
    """The tag of each release in the feed, in the feed's order: the link an <entry> carries before
    its <content>, under the repository the feed names as its own. Release notes are written by
    whoever publishes and sit in <content>, so nothing from there on and nothing in a CDATA section
    is read: a link in the notes to another repository's tag is not a release of this one."""
    feed = FEED_CDATA.sub("", feed)
    repository = FEED_REPOSITORY.search(feed.partition("<entry")[0])
    if not repository:
        raise ValueError("release feed does not name its repository")
    own = f'"https://github.com/{repository[1]}/releases/tag/'
    links = (FEED_TAG.search(entry.partition("<content")[0]) for entry in FEED_ENTRY.findall(feed))
    return list(dict.fromkeys(link[1] for link in links if link and own in link[0]))


def feed_releases(url):
    """The same catalog rows the API returns, built from the releases feed: each release's three
    assets sit at GitHub's fixed download path, and their signature is still verified. The path is
    asked for under RELEASES_REPOSITORY; after a rename GitHub redirects it like the feed itself."""
    feed = curl(url, max_bytes=MAX_CATALOG_BYTES).decode("utf-8", errors="replace")
    releases = []
    for tag in feed_tags(feed):
        archive = f"chronicle-selfhost-{tag.removeprefix('v')}.tar.gz"
        releases.append({"tag_name": tag, "draft": False, FEED_ROW: True, "assets": [
            dict(name=name, browser_download_url=f"https://github.com/{RELEASES_REPOSITORY}/releases/download/{quote(tag)}/{quote(name)}")
            for name in (archive, archive + ".sha256", archive + ".sha256.sig")]})
    if not releases:
        raise ValueError("release feed lists no releases")
    return releases


def fetch_published_releases():
    """The catalog from the first source that answers: CHRONICLE_RELEASES_URL when set, then the
    GitHub API, then the GitHub releases feed. Signatures stay mandatory whatever the source."""
    sources = [(API_RELEASES_URL, catalog_releases), (FEED_RELEASES_URL, feed_releases)]
    configured = os.environ.get("CHRONICLE_RELEASES_URL")
    if configured:
        sources.insert(0, (configured, catalog_releases))
    failures = []
    for url, read in sources:
        try:
            return read(url)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            reason = f"curl exit {error.returncode}" if isinstance(error, subprocess.CalledProcessError) else str(error)
            failures.append(f"{urlsplit(url).hostname or url}: {reason}")
            if len(failures) < len(sources):
                warn(f"release source {failures[-1]}; trying the next release source")
    raise ValueError("no release source answered; " + "; ".join(failures))




def is_stable_release(version):
    return version_key(version)[3][0] == 1




def apply_update(selfhost, settings, assets, version, current):
    state = (selfhost / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve()
    public_key = selfhost / 'release-signing.pub'
    if not public_key.is_file() or public_key.is_symlink():
        raise ValueError('missing installed release-signing.pub')
    key = public_key.read_text().strip()
    if not valid_public_key(key):
        raise ValueError('invalid installed release-signing.pub')
    require_storage(state, compose_project(settings),
                    free_disk_floor(settings), UPDATE_PEAK_BYTES)
    # Each release installs at <root>/chronicle-releases/<version>/; a repair of the installed
    # version (or a leftover from an interrupted attempt) gets the next free <version>.<n>, so the
    # active operator package is never overwritten.
    releases = releases_root(selfhost) / RELEASES_DIRECTORY
    releases.mkdir(mode=0o755, exist_ok=True)
    directory, attempt = releases / version, 0
    while os.path.lexists(directory):
        attempt += 1
        directory = releases / f'{version}.{attempt}'
    directory.mkdir(mode=0o700)
    staged = False
    try:
        download_assets(assets, directory)
        signer = verify_download(directory, assets, key, directory=directory)
        extracted = extract_release(directory / assets.archive.name,
                                    f'chronicle-selfhost-{version}', version)
        if signer != key:
            require_bundled_key(extracted, signer)
            print('The release signing key changed; the installed key endorsed the new one, which this '
                  'release installs for the next update.', flush=True)
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


def clear_dead_handoff(handoff):
    """A handoff is written just before exec and changes nothing; without a recovery journal, one whose
    candidate launcher is gone (deleted, or staging cleaned up) is cleared so update starts again."""
    try:
        owner = Path(json.loads(handoff.read_text())['owner'])
        alive = (owner / 'chronicle').is_file()
    except (OSError, ValueError, KeyError, TypeError):
        owner, alive = None, False
    if not alive:
        handoff.unlink(missing_ok=True)
        warn(f'the staged update candidate {owner or "(unreadable handoff)"} no longer exists; starting the update again')


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
    from .release import FRONT_DOOR_FILE, cleanup_releases, current_owner, is_staging_directory, releases_root
    from .common import require
    previous, candidate = Path(previous).resolve(), Path.cwd().resolve()
    settings = read_env(previous / '.env')
    state = (previous / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve()
    descriptor = acquire_operation_lock(state)
    try:
        record = state / UPGRADE_LOCK / RECOVERY_FILE
        handoff = state / HANDOFF_FILE
        data = json.loads((record if record.exists() else handoff).read_text())
        require(same_path(data['previous'], previous) and same_path(data['owner'], candidate),
                'candidate does not match the verified update handoff')
        recovered = recover_update(state)
        if not recovered:
            status = upgrade(previous, candidate)
        elif Path(recovered).resolve() == candidate:
            status = 0  # the interrupted update had committed and is finished
        elif data.get('failed'):
            status = 1  # the update failed and its rollback is now finished: report the failure
        else:
            # The update was interrupted before its commit and is rolled back: one rerun of
            # ./chronicle update carries on to the update instead of asking for another.
            print(f'The interrupted update was rolled back; updating to {candidate} again.', flush=True)
            os.chdir(candidate)
            status = upgrade(previous, candidate)
        if not record.exists():
            handoff.unlink(missing_ok=True)
            # Never remove the release that owns the deployment, whatever the status says.
            discard = status and current_owner(state) != candidate
            wrapper = candidate.parent.parent
            if discard:
                os.chdir(previous)
                require(is_staging_directory(wrapper), 'unexpected candidate staging directory')
                (candidate / '.env').unlink(missing_ok=True)
            elif status:
                warn(f'{candidate} owns this deployment although the update reported a failure; it is kept')
            else:
                front = state / FRONT_DOOR_FILE
                front = front.read_text().strip() if front.is_file() and not front.is_symlink() else previous
                print(f'Keep running ./chronicle from {front}; it now runs {candidate}.')
            try:
                cleanup_releases(releases_root(candidate), state, apply=True, rollback_target=previous.parent)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                warn(f'release cleanup incomplete: {error}; retry ./chronicle cleanup')
            if discard and wrapper.exists():
                shutil.rmtree(wrapper)
        return status
    finally:
        release_operation_lock(descriptor)


def select_release(releases, version=None):
    if version is None:
        return latest_stable_release(releases, require_assets=True)
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
        if not env_file.is_file() or env_file.is_symlink():
            raise ValueError("update requires the active release's regular .env file")
        if env_file.stat().st_mode & 0o777 != 0o600:
            env_file.chmod(0o600)  # It holds deployment secrets; repair the mode rather than refuse.
            warn(f'{env_file} was readable by other accounts; its mode is now 0600')
        settings = read_env(env_file)
        state = (selfhost / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve()
        if not check:
            if current_key < version_key(UPGRADE_FROM_MINIMUM):
                raise ValueError(FRESH_INSTALL_REQUIRED)
            descriptor = acquire_operation_lock(state)
            from .reconcile import UPGRADE_LOCK, RECOVERY_FILE
            recovery = state / UPGRADE_LOCK / RECOVERY_FILE
            handoff = state / HANDOFF_FILE
            if handoff.exists() and not recovery.exists():
                clear_dead_handoff(handoff)
            if recovery.exists() or handoff.exists():
                record = json.loads((recovery if recovery.exists() else handoff).read_text())
                exec_candidate(Path(record['owner']), Path(record['previous']))
            settings = read_env(env_file)
            if (selfhost / value(settings, 'CHRONICLE_STATE_DIR', '.')).resolve() != state:
                raise ValueError('state changed while acquiring lock; retry update')
        require_current_owner(selfhost, state, compose_project(settings))
        if check:
            from .egress import report_first_unreachable
            report_first_unreachable()
        release = select_release(fetch_published_releases(), version)
        latest = release['tag_name']
        latest_key = version_key(latest)
        print(f'Current: {current}; selected: {latest}', flush=True)
        if check:
            return UPDATE_AVAILABLE_EXIT if latest_key > current_key else 0
        if latest_key < current_key:
            if version is None:
                # A withdrawn release leaves this server ahead of the catalog: nothing newer exists.
                print(f'Nothing to update: {current} is newer than the newest published release.', flush=True)
                return 0
            raise ValueError('downgrade refused; use guarded rollback with its pre-update dump')
        version = latest.removeprefix('v')
        assets = release_assets(release, f'chronicle-selfhost-{version}.tar.gz')
        return apply_update(selfhost, settings, assets, version, current)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        raise ValueError(f'update failed: {error}') from None
    finally:
        release_operation_lock(descriptor)
