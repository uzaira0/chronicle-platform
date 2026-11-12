"""The publication ledger owns the append-only Flyway migration contract."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from .receipts import write_json
from .release import MIGRATIONS_KEY, UPGRADE_FROM_MINIMUM, parse_version, require_migration_inventory

MIGRATION_DIRECTORY = 'src/main/resources/db/migration'
SERVER_DIRECTORY = 'chronicle-server'
MIGRATION_LEDGER = Path('selfhost/published-migrations.json')


def migration_hashes(root):
    directory = Path(root) / SERVER_DIRECTORY / MIGRATION_DIRECTORY
    return {path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.rglob('V*__*.sql'))}


def require_published_migrations(published, candidate):
    for name, digest in published.items():
        if candidate.get(name) != digest:
            raise ValueError(f'published migration changed or removed: {name}; add a new V<n> migration')


def published_migrations(root):
    path = Path(root) / MIGRATION_LEDGER
    if not path.exists():
        return {}
    ledger = json.loads(path.read_text())
    if not isinstance(ledger, dict):
        raise ValueError('publication ledger must map release versions to migration hashes')
    for version, hashes in ledger.items():
        parse_version(version, path)
        require_migration_inventory({MIGRATIONS_KEY: hashes})
    return ledger


def require_immutable_migrations(root, source_root=None):
    candidate = migration_hashes(source_root or root)
    for hashes in published_migrations(root).values():
        require_published_migrations(hashes, candidate)
    return candidate


# The PostgreSQL major is the base image's tag in this file; the data and keyring volumes are the
# ones mounted at these paths in docker-compose.yml (upgrade.DATABASE_MOUNTS).
POSTGRES_DOCKERFILE = 'selfhost/Dockerfile.postgres'
COMPOSE_FILE = 'selfhost/docker-compose.yml'
POSTGRES_MAJOR = re.compile(r'^FROM\s+\S*postgresql:(\d+)[.:@-]', re.MULTILINE)
DATABASE_VOLUME = re.compile(r'^\s*-\s*"?([A-Za-z0-9_.-]+):(?:/data/db|/var/lib/postgresql/tde-keyring)(?::[a-zA-Z,]+)?"?\s*$', re.MULTILINE)


def database_layout(dockerfile, compose):
    """(PostgreSQL major, database volume names) of one release's sources."""
    major, volumes = POSTGRES_MAJOR.search(dockerfile), set(DATABASE_VOLUME.findall(compose))
    if not major or not volumes:
        raise ValueError('could not read the PostgreSQL major and database volumes from the release sources')
    return int(major[1]), volumes


def layout_conflict(version, published, candidate):
    """Why `./chronicle update` from the published release would refuse this one, or None: the same
    major must keep the same database volumes, and a new major must name new ones."""
    (old, kept), (new, fresh) = published, candidate
    if old == new and kept != fresh:
        return (f'{version} runs PostgreSQL {old} on {", ".join(sorted(kept))}; this release keeps major {new} '
                f'but names {", ".join(sorted(fresh))}, so the update would start it on another database')
    if old != new and kept & fresh:
        return (f'PostgreSQL {old} in {version} becomes {new} here, but the database volumes '
                f'{", ".join(sorted(kept & fresh))} keep their names; a new major needs new volume names '
                f'(for example postgres_data_{new})')
    return None


def require_database_volume_continuity(root, source_root):
    """Every supported published release can update to this one without an operator step."""
    from .release import UPGRADE_FROM_MINIMUM
    source_root = Path(source_root)
    candidate = database_layout((source_root / POSTGRES_DOCKERFILE).read_text(), (source_root / COMPOSE_FILE).read_text())
    floor = parse_version(UPGRADE_FROM_MINIMUM, 'reset floor')
    for version in published_migrations(root):
        if parse_version(version, MIGRATION_LEDGER) < floor:
            continue
        texts = []
        for path in (POSTGRES_DOCKERFILE, COMPOSE_FILE):
            shown = subprocess.run(['git', '-C', str(root), 'show', f'refs/tags/{version}:{path}'],
                                   capture_output=True, text=True, check=False)
            if shown.returncode:
                # Promotion fetches the tag when it records the release (scripts/publish-images.sh);
                # a clone that has the ledger entry without the tag fetches it the same way.
                raise ValueError(f'published release {version} has no git tag here to compare its database with; '
                                 f'fetch it: git fetch --no-tags public refs/tags/{version}:refs/tags/{version}')
            texts.append(shown.stdout)
        problem = layout_conflict(version, database_layout(*texts), candidate)
        if problem:
            raise ValueError(problem)


def ledger_with(root, manifest):
    """The ledger as it reads once the manifest's release is recorded. Refuses a release without a
    migration that an earlier publication shipped, or with a changed one, and a second inventory
    for a version already recorded. Writes nothing."""
    require_migration_inventory(manifest)
    version = manifest['release_version']
    parse_version(version, 'published release')
    hashes = manifest[MIGRATIONS_KEY]
    ledger = published_migrations(root)
    for published in ledger.values():
        require_published_migrations(published, hashes)
    if version in ledger and ledger[version] != hashes:
        raise ValueError('publication ledger cannot replace a release inventory')
    ledger[version] = hashes
    return ledger


def unrecorded_publications(root, releases):
    """The tags of the published releases at or above the upgrade floor that the ledger has no entry
    for. `releases` are the rows of GitHub's release list for the public repository; a draft is not
    a publication, and a tag that is no release version is not one of ours. The ledger freezes
    migrations only for the releases recorded in it, so scripts/publish-images.sh cuts and publishes
    nothing while this is not empty. Releases below the floor cannot update to a new release and
    were never recorded."""
    floor = parse_version(UPGRADE_FROM_MINIMUM, 'upgrade floor')
    ledger = published_migrations(root)
    missing = []
    for row in releases:
        if not isinstance(row, dict) or row.get('draft') is not False:
            continue
        tag = str(row.get('tag_name', ''))
        try:
            version = parse_version(tag.removeprefix('v'), 'published release')
        except ValueError:
            continue
        if version >= floor and tag.removeprefix('v') not in ledger:
            missing.append(tag)
    return missing


def record_publication(root, manifest):
    """Record a release that is public. `scripts/publish-images.sh <release> --promote` calls this
    once GitHub says the release is public (after its own `gh release edit --draft=false`, or when
    an earlier run published the release and did not record it), with the manifest of the bundle it
    verified, after fetching the release's tag from the public repository: require_database_volume_continuity
    reads every recorded release from refs/tags/<version>. A draft is never recorded. It is not a
    publication: it can be replaced or deleted, and GitHub creates its tag only when it publishes it."""
    ledger = ledger_with(root, manifest)
    (Path(root) / MIGRATION_LEDGER).parent.mkdir(parents=True, exist_ok=True)
    write_json(Path(root) / MIGRATION_LEDGER, ledger)


if __name__ == '__main__':
    # python3 -m chronicle_ops.migrations [--check] <root> <release-manifest.json>
    # --check is what promotion runs while the release is still a draft: the same refusals, no write.
    arguments = sys.argv[1:]
    check = arguments[:1] == ['--check']
    root, manifest = arguments[check:]
    try:
        (ledger_with if check else record_publication)(Path(root), json.loads(Path(manifest).read_text()))
    except (OSError, ValueError) as error:
        sys.exit(f'error: {type(error).__name__}: {error}')
