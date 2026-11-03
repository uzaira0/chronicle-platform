#!/usr/bin/env python3
"""Build a deterministic, source-free Chronicle self-host release bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import NoReturn
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SELFHOST = ROOT / "selfhost"
sys.path.insert(0, str(SELFHOST))
from chronicle_ops.release import ANDROID_COMPATIBILITY, RELEASE_SIGNER, UPGRADE_FROM_MINIMUM, UPGRADE_FLOOR_KEY, parse_version, read_manifest, require_migration_inventory
from chronicle_ops.migrations import MIGRATIONS_KEY, require_immutable_migrations
from chronicle_ops.images import IMAGE_INPUTS_KEY, INPUTS_TREE_LABEL, SOURCE_IMAGES, archive_source, bundle_images, source_inputs_tree

# Accept the registry host:port form used by private/self-hosted OCI registries while still
# requiring an immutable digest. The final optional colon remains the image tag, not a port.
IMAGE_RE = re.compile(
    r"^[A-Za-z0-9._-]+(?::[0-9]{1,5})?"
    r"(?:/[A-Za-z0-9._-]+)*(?::[A-Za-z0-9._-]+)?"
    r"@sha256:[0-9a-f]{64}$"
)
VERSION_RE = re.compile(
    r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
BUNDLE_DIRECTORIES = ("caddy", "config", "docs", "monitoring", "overlays")
PLACEHOLDERS = {image.placeholder: image.component for image in SOURCE_IMAGES}

SMOKE_ARCHIVE_HASH_FIELD = "release_archive_sha256"
SMOKE_SAME_BUILD_RESTORE_FIELD = "same_build_backup_restore"
SMOKE_REQUIRED_EVIDENCE = dict.fromkeys((
    "source_free_archive", "fresh_install", "fresh_volume_restore", SMOKE_SAME_BUILD_RESTORE_FIELD,
    "tde_rotation_restart_continuity",
    "tde_rotated_keyring_backup", "external_boundary_verify", "restart_order_recovery",
    "study_restart_persistence", "credential_rotation_consumers", "certificate_renewal",
    "clean_restore", "disk_full_recovery", "inode_full_recovery", "dashboard_headers",
    "container_security_audit", "keyless_volume_fails", "internal_guard_rate_limit",
    "post_restore_verify", "monitoring_data_path",
), "pass") | {"monitoring": "true"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a self-host bundle that contains configuration only and pulls immutable images."
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-revision", required=True)
    # The private checkout's HEAD never exists in the public mirror; this is the public commit
    # the release tag points at, so a self-hoster can map the bundle to published source.
    parser.add_argument("--public-revision")
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--backend-image", required=True)
    parser.add_argument("--frontend-image", required=True)
    parser.add_argument("--caddy-image", required=True)
    parser.add_argument("--backup-image", required=True)
    parser.add_argument("--grafana-image", required=True)
    parser.add_argument("--fluentbit-image", required=True)
    parser.add_argument("--postgres-image", required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build" / "releases")
    return parser.parse_args()


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"self-host release build failed: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release_signature(checksum: Path, signature: Path, public_key: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="chronicle-release-signature-") as directory:
        allowed = Path(directory) / "allowed_signers"
        allowed.write_text(f"{RELEASE_SIGNER} {public_key.read_text().strip()}\n")
        with checksum.open("rb") as message:
            result = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", RELEASE_SIGNER,
                 "-n", RELEASE_SIGNER, "-s", str(signature)],
                stdin=message, capture_output=True, timeout=30)
        if result.returncode:
            fail("invalid release signature")


def require_archive_checksum(archive: Path, checksum: Path) -> None:
    entry = re.fullmatch(r"([0-9a-f]{64}) [ *]" + re.escape(archive.name) + r"\n?",
                         checksum.read_text(encoding="ascii"))
    if entry is None or entry[1] != sha256(archive):
        fail("release archive checksum does not match its sidecar")


def archive_manifest(source: tarfile.TarFile) -> dict:
    manifests = [member for member in source.getmembers()
                 if member.isfile() and member.name.endswith("/release-manifest.json")]
    if len(manifests) != 1:
        fail("release archive must contain one release manifest")
    with source.extractfile(manifests[0]) as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        fail("release manifest must be an object")
    try:
        parse_version(manifest.get(UPGRADE_FLOOR_KEY, ''), 'upgrade floor')
        require_migration_inventory(manifest)
    except ValueError as error:
        fail(str(error))
    return manifest


def inspect_release_archive(archive: Path, checksum: Path) -> dict:
    if not archive.is_file() or archive.is_symlink() or not checksum.is_file() or checksum.is_symlink():
        fail("release archive and checksum must be regular files")
    require_archive_checksum(archive, checksum)
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if len(members) > 20000 or sum(member.size for member in members) > 2 * 1024 * 1024 * 1024:
            fail("release archive exceeds the supported inventory bounds")
        manifest = archive_manifest(source)
        version = manifest.get("release_version", "")
        if not isinstance(version, str):
            fail("release manifest has an invalid version")
        parse_version(version, archive)
        revision = manifest.get("source_revision", "")
        if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
            fail("release manifest has an invalid source revision")
        images = manifest.get("images", {})
        backend = images.get("backend", "") if isinstance(images, dict) else ""
        if not isinstance(backend, str) or not IMAGE_RE.fullmatch(backend):
            fail("release manifest has no immutable backend image pin")
        root = f"chronicle-selfhost-{version}"
        if archive.name != f"{root}.tar.gz":
            fail("release archive name does not match its bundle root")
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != root
                    or not (member.isdir() or member.isfile())):
                fail("release archive contains an unsafe member")
            if any(part == ".env" or part.endswith((".pem", ".key", ".jks", ".p12"))
                   or part == "signing.properties" for part in path.parts):
                fail("release archive contains runtime-only material")
            if any(part in {"chronicle-server", "chronicle-web", "chronicle-api", "rhizome", "gradle", "Dockerfile"}
                   for part in path.parts[1:]):
                fail("release archive contains source or build tooling")
        operators = [member for member in members if member.name == f"{root}/selfhost/chronicle" and member.isfile()]
        if len(operators) != 1 or not operators[0].mode & 0o111:
            fail("release archive is missing its executable operator CLI")
    return manifest


def require_smoke_result(result: Path, archive: Path) -> None:
    rows = [line.split("=", 1) for line in result.read_text().splitlines()]
    if any(len(row) != 2 for row in rows) or len({row[0] for row in rows}) != len(rows):
        fail("malformed release smoke result")
    evidence = dict(rows)
    if evidence.get("status") != "passed" or evidence.get(SMOKE_ARCHIVE_HASH_FIELD) != sha256(archive):
        fail("release smoke did not pass for this signed archive")
    if any(evidence.get(key) != expected for key, expected in SMOKE_REQUIRED_EVIDENCE.items()):
        fail("release smoke is missing required passing coverage")


def require_public_archive_images(archive: Path) -> None:
    with tarfile.open(archive, "r:gz") as source:
        manifest = archive_manifest(source)
        images = manifest["images"]
        if not isinstance(images, dict) or not set(PLACEHOLDERS.values()) <= set(images) or any(
                not isinstance(pin, str) or not IMAGE_RE.fullmatch(pin) for pin in images.values()):
            fail("candidate has invalid runtime image pins")
    with tempfile.TemporaryDirectory(prefix="chronicle-anonymous-registry-") as directory:
        for pin in set(images.values()):
            result = subprocess.run(["docker", "manifest", "inspect", pin],
                                    env=dict(os.environ, DOCKER_CONFIG=directory),
                                    capture_output=True, timeout=60)
            if result.returncode:
                fail(f"release image is unavailable without registry credentials: {pin}")


def require_public_release_tag(remote: str, tag: str, revision: str) -> None:
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        fail("release has no valid public source revision")
    ref = f"refs/tags/{tag}"
    result = subprocess.run(["git", "ls-remote", remote, ref, ref + "^{}"],
                            check=True, capture_output=True, text=True, timeout=60)
    refs = {name: commit for commit, name in (line.split() for line in result.stdout.splitlines())}
    if refs and refs.get(ref + "^{}", refs.get(ref)) != revision:
        fail("existing public release tag does not match the verified public source revision")


def require_smoke_images(bundle: Path, images: dict[str, str], backup_image: str) -> None:
    manifest, _ = read_manifest(bundle / "release-manifest.json", True)
    if not images.items() <= manifest["images"].items():
        fail("candidate images do not match the smoke runtime images")
    if manifest["images"].get("backup") != backup_image:
        fail("candidate backup image does not match the smoke runtime image")


def require_changelog(path: Path, version: str) -> None:
    target = parse_version(version, path)
    versions = []
    for heading in re.findall(r"(?m)^## \[([^\]]+)\]$", path.read_text(encoding="utf-8")):
        try:
            versions.append(parse_version(heading, path))
        except ValueError:
            continue
    if versions.count(target) != 1:
        fail("CHANGELOG.md must contain exactly one entry for the target release")
    if versions != sorted(versions, reverse=True):
        fail("CHANGELOG.md release entries must be ordered newest first")


def resolve_within(root: Path, candidate: Path, *, strict: bool, description: str) -> Path:
    """Resolve a release path and reject traversal or symlink escape from its declared root."""
    resolved_root = root.resolve(strict=strict)
    resolved_candidate = candidate.resolve(strict=strict)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError:
        fail(f"{description} escapes its release root: {candidate}")
    return resolved_candidate


def require_committed_release_source(root: Path, revision: str) -> None:
    """Bind the claimed source revision to the bytes eligible for this bundle."""
    try:
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
        if revision != head:
            fail("release source revision does not match HEAD")
        inputs = ["selfhost", "docker/init-db-roles.sql", "LICENSE", "THIRD-PARTY.md", "CHANGELOG.md", "SECURITY.md"]
        state = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no", "--", *inputs],
                               check=True, capture_output=True, text=True).stdout
        if state.strip():
            fail("refusing modified tracked release inputs; release source must be committed")
    except subprocess.CalledProcessError:
        fail("Git source metadata is unavailable; use a complete source checkout with its committed release inputs")


def tracked_source_paths(root: Path) -> set[str]:
    """Return the repository index manifest used to define release source inputs."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--full-name", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        fail("could not read the tracked release source manifest")
    return {path.decode("utf-8") for path in result.stdout.split(b"\0") if path}


def require_tracked(path: Path, repository_root: Path, tracked_paths: set[str]) -> None:
    try:
        relative = path.resolve(strict=True).relative_to(repository_root.resolve(strict=True))
    except (OSError, ValueError):
        fail(f"release source is outside the repository: {path}")
    if relative.as_posix() not in tracked_paths:
        fail(f"refusing untracked release input: {relative.as_posix()}")


def copy_tree(
    source: Path,
    destination: Path,
    *,
    tracked_paths: set[str],
    repository_root: Path = ROOT,
) -> None:
    source_root = source.resolve(strict=True)
    destination_root = destination.resolve(strict=False)
    # Containers bind-mount these directories (config/ as the backend user); mkdir alone
    # would leave them owner-only under a private umask.
    destination_root.mkdir(parents=True, exist_ok=True)
    destination_root.chmod(0o755)
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            fail(f"refusing symlink in release input: {path}")
        safe_source = resolve_within(
            source_root, path, strict=True, description="release input"
        )
        target = resolve_within(
            destination_root,
            destination_root / relative,
            strict=False,
            description="release output",
        )
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(0o755)
        elif path.is_file():
            require_tracked(path, repository_root, tracked_paths)
            target.parent.mkdir(parents=True, exist_ok=True)
            copy_release_file(safe_source, target, 0o755 if os.access(path, os.X_OK) else 0o644)
        else:
            fail(f"unsupported release input type: {path}")


def add_to_tar(archive: tarfile.TarFile, path: Path, arcname: str, epoch: int) -> None:
    info = archive.gettarinfo(str(path), arcname=arcname)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = epoch
    if path.is_dir():
        archive.addfile(info)
        return
    with path.open("rb") as handle:
        archive.addfile(info, handle)


def copy_release_file(source: Path, target: Path, mode: int) -> None:
    # The mode is explicit so the bundle never depends on the builder's umask.
    with source.open("rb") as source_handle, target.open("xb") as target_handle:
        shutil.copyfileobj(source_handle, target_handle)
    target.chmod(mode)


def require_offline_links(bundle):
    for document in bundle.rglob('*.md'):
        for link in re.findall(r'\[[^\]]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)', document.read_text()):
            url = urlsplit(link.strip('<>'))
            if url.scheme or url.netloc or not url.path:
                continue
            target = resolve_within(bundle, document.parent / unquote(url.path), strict=False,
                                    description='offline documentation link')
            if not target.exists():
                fail(f'broken offline link in {document.relative_to(bundle)}: {link}')


def operator_files(selfhost=SELFHOST):
    root_files = [
        ".env.example",
        ".gitignore",
        "Caddyfile.split",
        "Caddyfile.split.local",
        "Caddyfile.split.tls",
        "README.md",
        "backend-entrypoint.sh",
        "backup-entrypoint.sh",
        "backup-prune-hook.sh",
        "ca-export.sh",
        "cert-init.sh",
        "chronicle",
        "doctor.sh",
        "release-signing.pub",
        "db-init.sh",
        "docker-compose.yml",
        "guard-config.sh",
        "network-policy.sh",
        "network-subnet.py",
        "init-tde.sh",
        "restore.sh",
        "restore-continuity.version",
        "chronicle_ops/restore-session.properties",
        "chronicle_ops/restore-table-policy.json",
        "rotate-secret.sh",
        "rotation-http.sh",
        "verify-config.sh",
    ]
    root_files.extend(path.name for path in sorted(selfhost.glob("*.sql")))
    root_files.extend(path.relative_to(selfhost).as_posix()
                      for path in sorted((selfhost / "chronicle_ops").rglob("*.py")))
    return root_files


def copy_operator_files(bundle, tracked_paths, *, source_root=ROOT):
    selfhost = source_root / "selfhost"
    for name in operator_files(selfhost):
        source = selfhost / name
        if not source.is_file() or source.is_symlink():
            fail(f"required bundle input is missing or unsafe: {source}")
        require_tracked(source, source_root, tracked_paths)
        target = bundle / "selfhost" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.parent.chmod(0o755)
        source = resolve_within(selfhost, source, strict=True, description="operator input")
        target = resolve_within(bundle, target, strict=False, description="operator output")
        # A self-hoster's documented `cp .env.example .env` must produce a private
        # secret file without relying on a favorable shell umask or an extra chmod.
        copy_release_file(source, target, 0o600 if name == ".env.example"
                          else 0o755 if os.access(source, os.X_OK) else 0o644)



def copy_bundle_inputs(bundle, args, tracked_paths, *, source_root=ROOT):
    # mkdir honours the caller's umask; Compose bind-mounts selfhost/ into containers
    # that run as their image's own user (config-guard as the postgres uid), so the
    # directories must be world-searchable whatever umask built the archive.
    bundle.mkdir(mode=0o755)
    bundle.chmod(0o755)
    (bundle / "selfhost").mkdir(mode=0o755)
    (bundle / "selfhost").chmod(0o755)
    for directory in BUNDLE_DIRECTORIES:
        copy_tree(source_root / "selfhost" / directory, bundle / "selfhost" / directory,
                  tracked_paths=tracked_paths, repository_root=source_root)
    copy_operator_files(bundle, tracked_paths, source_root=source_root)
    for name in ("tests/deployment/selfhost-platform.md", "tests/deployment/selfhost-client.py",
                 "generated/upload-limits.json", "ontology/chronicle.linkml.yaml"):
        source = source_root / name
        target = bundle / name
        for directory in reversed(list(target.relative_to(bundle).parents)[:-1]):
            (bundle / directory).mkdir(mode=0o755, exist_ok=True)
            (bundle / directory).chmod(0o755)
        copy_release_file(source, target, 0o644)

    # backups holds dumps, so it stays private; tls must be traversable by the
    # unprivileged config-guard/cert-init containers (cert-init locks key.pem down).
    (bundle / "selfhost" / "backups").mkdir(mode=0o700)
    (bundle / "selfhost" / "tls").mkdir(mode=0o755)
    (bundle / "selfhost" / "tls").chmod(0o755)

    docker_dir = bundle / "docker"
    docker_dir.mkdir(mode=0o755)
    docker_dir.chmod(0o755)
    role_sql = source_root / "docker" / "init-db-roles.sql"
    require_tracked(role_sql, source_root, tracked_paths)
    copy_release_file(role_sql, resolve_within(bundle, docker_dir / role_sql.name,
                                            strict=False, description="database role output"), 0o644)
    # Operators read release notes and the vulnerability-reporting policy offline.
    for name in ("LICENSE", "THIRD-PARTY.md", "CHANGELOG.md", "SECURITY.md"):
        source = source_root / name
        require_tracked(source, source_root, tracked_paths)
        copy_release_file(source, resolve_within(bundle, bundle / name,
                                              strict=False, description="release document output"), 0o644)



def render_bundle(bundle, args, images, normalized_version):
    from chronicle_ops.ingress import render_caddy_fence
    render_caddy_fence(bundle / 'selfhost/caddy/snippets.caddy')
    env_path = bundle / "selfhost" / ".env.example"
    env_text = env_path.read_text(encoding="utf-8")
    files = [env_path, *sorted((bundle / "selfhost/overlays").glob("*.yml"))]
    seen = set()
    for path in files:
        text = path.read_text()
        for placeholder, image_name in PLACEHOLDERS.items():
            if placeholder in text:
                seen.add(placeholder)
                text = text.replace(placeholder, images[image_name])
        path.write_text(text)
    if seen != set(PLACEHOLDERS):
        fail("source image registry does not match the bundle placeholders")
    env_text = env_path.read_text()
    env_text = re.sub(
        r"(?m)^RELEASE_VERSION=.*$", f"RELEASE_VERSION={normalized_version}", env_text, count=1
    )
    if "__CHRONICLE_" in env_text:
        fail("unresolved Chronicle image placeholder remains in generated .env.example")
    env_path.write_text(env_text, encoding="utf-8")

    compose_text = (bundle / "selfhost" / "docker-compose.yml").read_text(encoding="utf-8")
    if re.search(r"(?m)^\s*build\s*:", compose_text):
        fail("generated Compose still contains a local build block")
    if "context: .." in compose_text or "dockerfile:" in compose_text:
        fail("generated Compose still references the source workspace")

    backup_overlay = bundle / "selfhost/overlays/backups.yml"
    overlay = backup_overlay.read_text()
    backup_environment = '      PGSSLMODE:'
    if overlay.count(backup_environment) != 1:
        fail('backup service environment must expose its release provenance')
    overlay = overlay.replace(backup_environment, f'      RELEASE_VERSION: "{normalized_version}"\n{backup_environment}', 1)
    backup_overlay.write_text(overlay)
    runtime_images = bundle_images(bundle / "selfhost")
    if any("__CHRONICLE_" in image for image in runtime_images):
        fail("every first-party runtime image requires its release digest")
    images = dict(images, **{f"runtime-{index}": pin for index, pin in enumerate(sorted(runtime_images - set(images.values())))})
    file_hashes: dict[str, str] = {}
    for path in sorted(bundle.rglob("*")):
        if path.is_file():
            file_hashes[path.relative_to(bundle).as_posix()] = sha256(path)
    manifest = {
        "schema_version": 1,
        "android_compatibility": ANDROID_COMPATIBILITY,
        UPGRADE_FLOOR_KEY: UPGRADE_FROM_MINIMUM,
        MIGRATIONS_KEY: args.migrations,
        "release_version": normalized_version,
        "source_revision": args.source_revision,
        **({"public_revision": args.public_revision} if args.public_revision else {}),
        "source_date_epoch": args.source_date_epoch,
        "images": images,
        IMAGE_INPUTS_KEY: {image.component: args.inputs_tree for image in SOURCE_IMAGES},
        "files": file_hashes,
    }
    manifest_path = bundle / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.chmod(0o644)



def validate_inputs(args):
    version_match = VERSION_RE.fullmatch(args.version)
    if not version_match:
        fail("--version must be a semantic release version such as v1.2.3 or v1.2.3-rc.1")
    prerelease = version_match.group(4)
    if prerelease is not None:
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                fail("--version numeric prerelease identifiers must not contain leading zeroes")
    if not REVISION_RE.fullmatch(args.source_revision):
        fail("--source-revision must be a full lowercase Git SHA")
    if args.public_revision is not None and not REVISION_RE.fullmatch(args.public_revision):
        fail("--public-revision must be a full lowercase Git SHA")
    if not 0 <= args.source_date_epoch <= 0xFFFFFFFF:
        fail("--source-date-epoch must fit the gzip timestamp range (0 through 4294967295)")

    images = {image.component: getattr(args, image.component + "_image") for image in SOURCE_IMAGES}
    args.inputs_tree = source_inputs_tree(ROOT, args.source_revision)
    for name, image in images.items():
        if not IMAGE_RE.fullmatch(image):
            fail(f"{name} image must be an immutable name@sha256 reference")
        label = subprocess.run(['docker', 'image', 'inspect', '--format',
                                '{{index .Config.Labels "' + INPUTS_TREE_LABEL + '"}}', image],
                               capture_output=True, text=True, check=False)
        if label.returncode or label.stdout.strip() != args.inputs_tree:
            fail(f"{name} image was not built from the declared source inputs tree")

    return images


def publish_bundle(bundle, args, final_directory, archive_path, checksum_path):
    staging_parent = bundle.parent
    bundle_name = bundle.name
    # Build every byte before publishing any final path. The previous ordering moved the
    # directory first and only then created the tarball; a tar/gzip/disk failure left a
    # release-looking directory plus a partial archive and made a clean retry impossible.
    staged_archive = staging_parent / archive_path.name
    staged_checksum = staging_parent / checksum_path.name
    with staged_archive.open("xb") as raw_archive:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw_archive, mtime=args.source_date_epoch
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                add_to_tar(archive, bundle, bundle_name, args.source_date_epoch)
                for path in sorted(bundle.rglob("*")):
                    add_to_tar(
                        archive,
                        path,
                        f"{bundle_name}/{path.relative_to(bundle).as_posix()}",
                        args.source_date_epoch,
                    )

    archive_digest = sha256(staged_archive)
    staged_checksum.write_text(
        f"{archive_digest}  {archive_path.name}\n", encoding="ascii"
    )

    for output in (final_directory, archive_path, checksum_path):
        if output.exists() or output.is_symlink():
            fail(f"refusing to replace output created during this build: {output}")

    published: list[Path] = []
    try:
        # Directory rename is atomic on the output filesystem. Hard-linking the two files
        # gives no-replace publication semantics (staging is deliberately under output_dir).
        os.rename(bundle, final_directory)
        published.append(final_directory)
        os.link(staged_archive, archive_path)
        published.append(archive_path)
        staged_archive.unlink()
        os.link(staged_checksum, checksum_path)
        published.append(checksum_path)
        staged_checksum.unlink()
    except BaseException:
        # These are exact paths this invocation successfully published after proving they
        # were absent. Remove only those paths so an ordinary exception is retryable.
        for output in reversed(published):
            if output == final_directory:
                shutil.rmtree(output)
            else:
                output.unlink(missing_ok=True)
        raise


def main() -> None:
    args = parse_args()
    require_committed_release_source(ROOT, args.source_revision)
    tracked_paths = tracked_source_paths(ROOT)
    images = validate_inputs(args)

    normalized_version = args.version.removeprefix("v")
    bundle_name = f"chronicle-selfhost-{normalized_version}"
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    final_directory = output_dir / bundle_name
    archive_path = output_dir / f"{bundle_name}.tar.gz"
    checksum_path = output_dir / f"{bundle_name}.tar.gz.sha256"
    for output in (final_directory, archive_path, checksum_path):
        if output.exists() or output.is_symlink():
            fail(f"refusing to replace existing output: {output}")

    staging_parent = Path(tempfile.mkdtemp(prefix=".selfhost-release-", dir=output_dir))
    try:
        source_root = staging_parent / "source"
        source_root.mkdir()
        with tempfile.TemporaryFile() as snapshot:
            archive_source(ROOT, args.source_revision, '.', snapshot,
                           submodules=tuple(dict.fromkeys(module for image in SOURCE_IMAGES for module in image.submodules)))
            snapshot.seek(0)
            with tarfile.open(fileobj=snapshot) as archive:
                archive.extractall(source_root, filter='data')
        require_changelog(source_root / "CHANGELOG.md", normalized_version)
        if parse_version(normalized_version, 'release') < parse_version(UPGRADE_FROM_MINIMUM, 'reset floor'):
            fail('new release predates the reset upgrade floor')
        args.migrations = require_immutable_migrations(ROOT, source_root)
        bundle = staging_parent / bundle_name
        copy_bundle_inputs(bundle, args, tracked_paths, source_root=source_root)

        render_bundle(bundle, args, images, normalized_version)
        require_offline_links(bundle)

        publish_bundle(bundle, args, final_directory, archive_path, checksum_path)
    finally:
        if staging_parent.exists():
            shutil.rmtree(staging_parent)
    print(archive_path)
    print(checksum_path)


if __name__ == "__main__":
    main()
