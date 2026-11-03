"""The publication ledger owns the append-only Flyway migration contract."""
import hashlib
import json
from pathlib import Path
import sys

from .receipts import write_json
from .release import MIGRATIONS_KEY, parse_version, require_migration_inventory

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


def record_publication(root, manifest):
    """Called by publish-images only after GitHub has created the signed release."""
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
    (Path(root) / MIGRATION_LEDGER).parent.mkdir(parents=True, exist_ok=True)
    write_json(Path(root) / MIGRATION_LEDGER, ledger)


if __name__ == '__main__':
    record_publication(Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text()))
