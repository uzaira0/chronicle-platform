#!/usr/bin/env bash
# postgres-backup-local hook, mounted as /hooks/50-prune-pre-operation-dumps and run by
# run-parts with the phase as $1 (pre-backup, post-backup or error).
#
# pre-backup: reclaim expired safety dumps before backup.sh checks MIN_FREE_DISK_GIB.
# post-backup: also make published dumps private.
#
# chronicle adopt, upgrade.sh and restore.sh write full-database safety dumps (pre-adopt-*.sql.gz,
# pre-upgrade-*.sql.gz, pre-restore-*.sql.gz and their .continuity.sql.gz companions) into the backups root. The
# image's rotation only prunes last/daily/weekly/monthly, so without this those copies, and
# every row deleted since they were taken, would stay on disk forever. Restore and upgrade
# stop this sidecar while they run, so a dump in active use is never pruned here.
set -euo pipefail

[[ "${1:-}" == pre-backup || "${1:-}" == post-backup ]] || exit 0

# The image writes every dump 0644 and ignores UMASK. The 0700 parent is the access control;
# this keeps a dump private after it is copied or synced out of that directory. Only files
# this account owns: the keyring copy belongs to postgres and keeps its own mode.
[[ "${1:-}" != post-backup ]] || find "${BACKUP_DIR:-/backups}" -path "${BACKUP_DIR:-/backups}/keyring" -prune -o \
  -type f -user "$(id -u)" -exec chmod 600 {} +

# The operator chose this in ./chronicle setup; "all" keeps every safety dump.
keep_days="${PRE_OP_BACKUP_KEEP_DAYS:-}"
[[ "$keep_days" == all || "$keep_days" =~ ^[1-9][0-9]{0,3}$ ]] || {
  echo "ERROR: PRE_OP_BACKUP_KEEP_DAYS must be all or a whole number of days from 1 to 9999" >&2
  exit 1
}
[[ "$keep_days" != all ]] || exit 0

find "${BACKUP_DIR:-/backups}" -maxdepth 1 -type f \
  \( -name 'pre-adopt-*.sql.gz' -o -name 'pre-upgrade-*.sql.gz' -o -name 'pre-restore-*.sql.gz' -o -name '.reviewed-restore.*.sql.gz' \) \
  -mtime "+${keep_days}" -print -delete |
  sed 's/^/Pruned pre-operation safety dump older than '"${keep_days}"' days: /'

if [[ -d "${BACKUP_DIR:-/backups}/secret-rotation" ]]; then
  find "${BACKUP_DIR:-/backups}/secret-rotation" -maxdepth 1 -type f -name '*.sql.gz' \
    -mtime "+${keep_days}" -print -delete |
    sed 's/^/Pruned secret-rotation dump older than '"${keep_days}"' days: /'
fi

# Writers hold the fragment's flock, which also works across the backup bind mount.
# A crash releases that lock, so old fragments can expire without deleting a live dump.
python3 - "${BACKUP_DIR:-/backups}" "$keep_days" <<'PY'
import fcntl
import os
from pathlib import Path
import stat
import sys
import time

root, keep_days = Path(sys.argv[1]), int(sys.argv[2])
SECONDS_PER_DAY = 24 * 60 * 60
now = time.time()
for directory, pattern in ((root, "pre-upgrade-*.sql.gz.partial"),
                           (root / "secret-rotation", "*.sql.gz.partial")):
    for path in directory.glob(pattern):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            with path.open("rb") as fragment:
                try:
                    fcntl.flock(fragment, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                metadata = os.fstat(fragment.fileno())
                if stat.S_ISREG(metadata.st_mode) and (now - metadata.st_mtime) // SECONDS_PER_DAY > keep_days:
                    path.unlink()
                    print(f"Pruned interrupted safety dump older than {keep_days} days: {path}")
        except FileNotFoundError:
            continue  # The writer can finish and rename a fragment during enumeration.
PY
