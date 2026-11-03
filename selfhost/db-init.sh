#!/usr/bin/env bash
# Everything that must be true before the backend first connects, run as a one-shot compose
# service so `docker compose up -d` is the whole deployment command.
#
# It runs on every `up`, not just the first: Flyway keeps adding tables, and the encryption
# sweep has to see them. Every step below is idempotent.
#
# Ordering matters and is the reason this runs BEFORE the backend rather than after it, the
# way the old host-side `./chronicle up` did. init-tde.sh sets the database's default access
# method to tde_heap, so once it has run, every table Flyway creates is encrypted at
# creation. Sweeping afterwards also works but rewrites each table it missed, which on a
# first boot meant converting the whole schema instead of creating it encrypted.

set -euo pipefail

BACKUPS_DIR=/backups
REFERENCE_DIR=/selfhost
KEYRING_SRC=/var/lib/postgresql/tde-keyring/chronicle-keyring.per
KEYRING_DEST="${BACKUPS_DIR}/keyring/chronicle-keyring.per"

# Each dump is the whole database in one file, written by the backup image as 0644 -- that
# image never calls umask, so the file mode cannot be changed from compose. Access is denied
# one level up instead: at 0700 no other local account can traverse in.
#
# Ownership runs the whole way down, not just the top directory. The backup image used to run
# as root, which left every dump and every rotation subdirectory root:root inside an
# operator-owned 0700 parent. The operator could read a dump but could not delete one, move
# one, or prune the tree -- `rm` answered "Permission denied" on their own backups, and the
# only way to reclaim the disk was sudo. db-backup now runs as the operator (see
# overlays/backups.yml), and this reclaims anything a previous root-owned run left behind, so
# an existing deployment is repaired by the next `./chronicle up` rather than needing a manual
# chown.
#
# The owner must be the OPERATOR, not root, for a second reason: Docker creates a missing
# bind-mount source as root, and root-owned 0700 locks the operator out too, which breaks the
# backend image build -- its context is the repository root, and the context sender runs as the
# operator and dies with "permission denied" rather than skipping the directory. Nothing here
# knows the operator's uid, so take it from the bundle directory itself, which they own.
prepare_backups_dir() {
  mkdir -p "$BACKUPS_DIR"
  if [[ -d "$REFERENCE_DIR" ]]; then
    chown -R "$(stat -c %u "$REFERENCE_DIR")":"$(stat -c %g "$REFERENCE_DIR")" "$BACKUPS_DIR"
  fi
  chmod 700 "$BACKUPS_DIR"
}

# The keyring is the single point of total loss: without it the data volume is scrap and
# pg_dump cannot rescue it. Two things stand between the operator and that. First, the dumps
# beside this copy are plain SQL written through the running server, so they need no key at
# all. Second, this copy lets the volume itself be remounted rather than only rebuilt from
# SQL. Storing it next to the dumps adds no exposure those dumps do not already carry; what
# stays apart is the key and the *encrypted volume*, and it does.
copy_keyring() {
  local destination_dir temporary source_digest destination_digest
  [[ -s "$KEYRING_SRC" ]] || {
    echo "  WARNING: no keyring at ${KEYRING_SRC} — the data volume is not recoverable without it" >&2
    return 0
  }
  destination_dir="$(dirname "$KEYRING_DEST")"
  temporary="${destination_dir}/.chronicle-keyring.per.copy-$$"
  mkdir -p "$destination_dir"
  rm -f -- "$temporary"
  cp "$KEYRING_SRC" "$temporary"
  chmod 600 "$temporary"
  if [[ -d "$REFERENCE_DIR" ]]; then
    chown -R "$(stat -c %u "$REFERENCE_DIR")":"$(stat -c %g "$REFERENCE_DIR")" \
      "$destination_dir"
  fi
  mv -f "$temporary" "$KEYRING_DEST"
  source_digest="$(sha256sum "$KEYRING_SRC")"
  source_digest="${source_digest%% *}"
  destination_digest="$(sha256sum "$KEYRING_DEST")"
  destination_digest="${destination_digest%% *}"
  [[ -n "$source_digest" && "$source_digest" == "$destination_digest" ]] || {
    echo "  ERROR: copied keyring does not match the live keyring" >&2
    return 1
  }
  echo "  ok   keyring copied into ./backups/keyring (back this directory up as one unit)"
}

# Hazelcast's empty-map fallback writes all 65,536 ID partitions through MapStore one row at
# a time. On encrypted or modest disks that turns first boot into tens of thousands of durable
# transactions and can outlive every bounded startup wait. Seed the exact same zeroed ranges in
# one database transaction before the backend starts; its eager MapStore load then performs only
# reads. Never repair a partial set by resetting missing ranges to zero, because those ranges may
# already have issued IDs and doing so could create duplicates.
psql_run() {
  PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}" psql \
    -h "${POSTGRES_HOST:-postgres}" -p "${POSTGRES_PORT:-5432}" \
    -U "${POSTGRES_USER:-chronicle}" -d "${POSTGRES_DB:-chronicle}" \
    -v ON_ERROR_STOP=1 "$@"
}

bootstrap_id_generation_ranges() {
  psql_run >/dev/null <<'SQL'
CREATE TABLE IF NOT EXISTS public.id_gen (
  partition_index bigint PRIMARY KEY,
  msb bigint NOT NULL,
  lsb bigint NOT NULL
);

DO $$
DECLARE
  partition_count bigint;
  first_partition bigint;
  last_partition bigint;
BEGIN
  SELECT count(*), min(partition_index), max(partition_index)
    INTO partition_count, first_partition, last_partition
    FROM public.id_gen;
  IF partition_count = 0 THEN
    INSERT INTO public.id_gen (partition_index, msb, lsb)
    -- Range(base) starts at msb=0, lsb=Long.MIN_VALUE. The base is derived from
    -- partition_index when rows are read back by ResultSetAdapters.range().
    SELECT partition_index, 0, -9223372036854775808
      FROM generate_series(0, 65535) AS partition_index;
  ELSIF partition_count <> 65536 OR first_partition <> 0 OR last_partition <> 65535 THEN
    RAISE EXCEPTION
      'partial id_gen bootstrap: expected partitions 0..65535, found count %, range %..%',
      partition_count, first_partition, last_partition;
  END IF;
END
$$;
SQL
  echo "  ok   ID generation ranges ready (65,536 partitions)"
}

prepare_backups_dir

if [[ "${ENABLE_ENCRYPTION:-true}" == true ]]; then
  /selfhost/init-tde.sh
else
  uses_tde="$(psql_run -Atc "SELECT current_setting('default_table_access_method') LIKE 'tde%' OR EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_am a ON a.oid = c.relam WHERE a.amname LIKE 'tde%');")"
  [[ "$uses_tde" == f ]] || {
    echo 'ERROR: ENABLE_ENCRYPTION=false requires a plain database; the existing database still uses TDE. Follow the TDE-to-plain database migration in docs/BACKUP-RESTORE.md#tde-to-plain-database-migration; keep ENABLE_ENCRYPTION=true until then.' >&2
    exit 1
  }
  echo "  --   encryption at rest is OFF (ENABLE_ENCRYPTION=false)"
fi

bootstrap_id_generation_ranges
psql_run -q -f /selfhost/database-app-role.sql

if [[ "${ENABLE_ENCRYPTION:-true}" != true ]]; then
  exit 0
fi

copy_keyring
