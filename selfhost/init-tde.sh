#!/usr/bin/env bash
# Enable encryption at rest (Percona pg_tde) and keep it enabled.
#
# Called by `./chronicle up` on every start, not just the first one, because it has to be
# idempotent anyway and because Flyway keeps adding tables. Running it every time is what
# stops the production failure mode where init-db-encryption.sh runs only at database
# initialisation and every table added by a later migration silently stays unencrypted.
#
# WHAT THIS PROTECTS, AND WHAT IT DOES NOT
#   Protects encrypted table files copied without their separate keyring.
#   WAL is plaintext until server-key and recovery support are validated for the image.
#   Use encrypted backing storage for the database volume.
#   Does not protect: anyone with root on this running box. The key is on the box by
#             design -- that is the price of not having a passphrase that can be lost.
#
# ON BEING LOCKED OUT
#   Losing the keyring is unrecoverable. Verified directly: delete the keyring file,
#   restart, and the server answers
#       ERROR: key "..." not found in key provider "..."
#   and pg_dump cannot rescue it either. The protection against that is NOT a second copy
#   of the key -- it is the plain-SQL dumps in ./backups, which are written through the
#   running server and therefore contain no encryption at all. A dump taken while the key
#   was alive needs no old keyring. Recover with `./chronicle restore`, which prepares the
#   required extensions and replays with ON_ERROR_STOP. Raw replay into stock Postgres can
#   miss tables and functions even when some row counts match.
#
#   That is why `./chronicle up` refuses to enable encryption when backups are disabled.

set -euo pipefail

KEYRING_DIR="/var/lib/postgresql/tde-keyring"
KEYRING_FILE="${KEYRING_DIR}/chronicle-keyring.per"
PROVIDER="chronicle_keyring"
KEY_NAME="chronicle_key"

database_tde_sql() {
  local POSTGRES_DB="$1" purpose="${2:-initializer}" temporary="" evidence_schema=chronicle_secret_generation
  case "$purpose" in
    initializer) echo "CREATE SCHEMA IF NOT EXISTS ${evidence_schema};" ;;
    restore-check) temporary=TEMP; evidence_schema=pg_temp ;;
    *) echo 'unknown TDE bootstrap purpose' >&2; return 1 ;;
  esac
  echo "CREATE EXTENSION IF NOT EXISTS pg_tde;"

  # A restored database can carry an older extension version.
  echo "ALTER EXTENSION pg_tde UPDATE;"

  # The provider and bootstrap key are created only when no principal key is active. An online
  # rotation deliberately gives the active key a timestamped name; forcing KEY_NAME on every
  # db-init run would silently undo that rotation after the next `down`/`up` or release upgrade.
  cat <<SQL
-- Key creation date, read by ./chronicle doctor for the key's age until its first rotation receipt.
CREATE ${temporary} TABLE IF NOT EXISTS ${evidence_schema}.chronicle_generated_key (
  key_name text PRIMARY KEY, generated_at timestamptz NOT NULL
) USING heap;
-- pg_tde_list_all_database_key_providers() returns (id, name, type, options): the column
-- is "name", not "provider_name".
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_tde_list_all_database_key_providers()
                 WHERE name = '${PROVIDER}') THEN
    PERFORM pg_tde_add_database_key_provider_file('${PROVIDER}', '${KEYRING_FILE}');
    RAISE NOTICE 'created key provider ${PROVIDER}';
  END IF;
END
\$\$;

-- A restored database may need to adopt an existing keyring key. Only successful
-- key creation records evidence; adoption must not invent a generation date.
DO \$\$
BEGIN
  IF (SELECT key_name FROM pg_tde_key_info()) IS NULL THEN
    BEGIN
      PERFORM pg_tde_create_key_using_database_key_provider('${KEY_NAME}', '${PROVIDER}');
      INSERT INTO ${evidence_schema}.chronicle_generated_key VALUES ('${KEY_NAME}', clock_timestamp())
        ON CONFLICT (key_name) DO UPDATE SET generated_at = EXCLUDED.generated_at;
      RAISE NOTICE 'created principal key ${KEY_NAME}';
    EXCEPTION WHEN OTHERS THEN
      -- Narrow on purpose: only "it is already there" is survivable. A missing provider or
      -- an unreadable keyring file must still stop the deployment.
      IF SQLERRM NOT LIKE '%already exists%' THEN
        RAISE;
      END IF;
      RAISE NOTICE 'adopting principal key ${KEY_NAME} already present in ${PROVIDER}';
    END;
    PERFORM pg_tde_set_key_using_database_key_provider('${KEY_NAME}', '${PROVIDER}');
    RAISE NOTICE 'set principal key ${KEY_NAME}';
  ELSE
    RAISE NOTICE 'preserving the active principal key selected by the database';
  END IF;
END
\$\$;
SQL

  # Make tde_heap the default for this database so tables created by future Flyway
  # migrations are encrypted on creation rather than waiting for the next sweep.
  echo "ALTER DATABASE \"${POSTGRES_DB}\" SET default_table_access_method = 'tde_heap';"
}

# Reuse exactly this database bootstrap for the backup scratch restore.
if [[ "${1:-}" == --database-sql ]]; then
  database_tde_sql "${2:?database name is required}" restore-check
  exit 0
fi

# Runs INSIDE the db-init service, not on the host, so that `docker compose up -d` performs
# encryption setup with no wrapper script and no access to the Docker socket. It reaches
# Postgres over the compose network and prepares the keyring through the same
# postgres_tde_keyring volume, mounted here as well.
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-chronicle}"
POSTGRES_DB="${POSTGRES_DB:-chronicle}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}"

# The path pg_tde writes to is the one Postgres sees, which is the same volume mounted at
# the same path in both containers. Keep them identical or the provider records a path that
# does not exist in the server.
psql_run() {
  PGPASSWORD="$POSTGRES_PASSWORD" psql \
    -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v ON_ERROR_STOP=1 "$@"
}

psql_q() { psql_run -Atc "$1"; }

# Docker creates the keyring volume owned by root, but the server runs as uid 26 (postgres)
# and cannot create the keyring file inside a root-owned directory. This container runs as
# root with CHOWN, so it hands the directory over before pg_tde is asked to write a key.
# 26:26 rather than the name: this image resolves `postgres` to the same uid, but the
# numeric form cannot be wrong if that ever changes.
mkdir -p "$KEYRING_DIR" \
  && chown 26:26 "$KEYRING_DIR" \
  && chmod 700 "$KEYRING_DIR" \
  || { echo "could not prepare $KEYRING_DIR" >&2; exit 1; }

# Postgres reports ready before it accepts connections in some startup paths; the compose
# healthcheck gates this service, but retry briefly rather than fail the whole `up` on a race.
for _ in $(seq 1 30); do
  PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc 'SELECT 1' >/dev/null 2>&1 && break
  sleep 2
done

database_tde_sql "$POSTGRES_DB" | psql_run -q

# Convert anything still on plain heap. ALTER TABLE ... SET ACCESS METHOD rewrites the
# table, so this is the expensive step on first run and a no-op on every run after.
pending=$(psql_q "
  SELECT count(*) FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_am a        ON a.oid = c.relam
  WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname <> 'tde_heap';")

if [[ "$pending" -gt 0 ]]; then
  echo "  encrypting ${pending} table(s) — this rewrites them, so first run takes a while"
  psql_run >/dev/null <<'SQL'
DO $$
DECLARE t text;
BEGIN
  FOR t IN
    SELECT c.relname FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_am a        ON a.oid = c.relam
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname <> 'tde_heap'
  LOOP
    EXECUTE format('ALTER TABLE public.%I SET ACCESS METHOD tde_heap', t);
  END LOOP;
END
$$;
SQL
fi

enc=$(psql_q "
  SELECT count(*) FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_am a        ON a.oid = c.relam
  WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname = 'tde_heap';")
plain=$(psql_q "
  SELECT count(*) FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_am a        ON a.oid = c.relam
  WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname <> 'tde_heap';")

echo "  encryption at rest: ${enc} table(s) encrypted, ${plain} on plain heap"
[[ "$plain" -eq 0 ]] || { echo "  WARNING: ${plain} table(s) could not be converted" >&2; exit 1; }
