#!/usr/bin/env bash
# Restore a dump over an EXISTING database, run as a one-shot compose service so the whole
# procedure is owned by `./chronicle restore` rather than a hand-assembled psql pipeline.
#
# Why this exists rather than the operator piping a dump into psql: piping a dump into a
# database that already has the schema does not fail, it CORRUPTS. Every CREATE fails with
# "already exists" and is skipped, and then each COPY appends its rows into the table that is
# already there. Tables with a primary key reject the duplicates -- noisily, but harmlessly.
# Tables WITHOUT one silently end up with every row twice. `audit` is such a table, so the
# compliance trail is precisely what doubles. psql still exits 0 through all of it, so the
# operator is told the restore succeeded. Measured on a real bundle dump: 568 errors,
# exit code 0, audit 216 rows -> 432.
#
# Schema replacement and its postconditions share one transaction with ON_ERROR_STOP so a
# rejected restore rolls back to the live data.
#
#   ./chronicle restore --trusted-sha256=REVIEWED_SHA256 /backups/path/to/dump.sql.gz
#
# The CLI stops the backend, dashboard proxy, database-initialization job, and backup
# sidecar before invoking this one-shot service. It holds a state-directory operation lock
# against upgrade and secret rotation, verifies that the writers really stopped, and starts
# the stack only after this script succeeds. db-init then re-encrypts anything that arrived
# on plain heap (a dump from an unencrypted instance restores as unencrypted tables;
# init-tde.sh fixes that).

set -euo pipefail
umask 077

if [[ "${CHRONICLE_RESTORE_ORCHESTRATED:-}" != true ]]; then
  echo "  FAIL direct restore-service execution is disabled because application writers may still be running" >&2
  echo "       run the guarded operator command instead:" >&2
  echo "         ./chronicle restore [--yes] --trusted-sha256=REVIEWED_SHA256 /backups/path/to/dump.sql.gz" >&2
  exit 1
fi
unset CHRONICLE_RESTORE_ORCHESTRATED

BACKUPS_DIR="${BACKUPS_DIR:-/backups}"
DEFAULT_DUMP="${BACKUPS_DIR}/last/chronicle-latest.sql.gz"
RESTORE_FILE="${RESTORE_FILE:-$DEFAULT_DUMP}"

psql_q() {
  PGPASSWORD="$POSTGRES_PASSWORD" psql \
    -h "${POSTGRES_HOST:-postgres}" -p "${POSTGRES_PORT:-5432}" \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -X -v ON_ERROR_STOP=1 -tAq "$@"
}

verify_restore_dump() {
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/selfhost python3 -m chronicle_ops.dump "$@"
}

RESTORE_SQL_DIR="$(dirname "${BASH_SOURCE[0]}")"
# Read before any mutation so a missing file fails here. The backend reconciler runs the same
# containment files (chronicle-server processResources), so both runtimes share one contract.
WITHDRAWAL_CONTAINMENT_SQL=$(cat "$RESTORE_SQL_DIR/restore-withdrawal-containment.sql")
RESTRICTIONS_CONTAINMENT_SQL=$(cat "$RESTORE_SQL_DIR/restore-restrictions-containment.sql")
RESTRICTIONS_VERIFICATION_SQL=$(cat "$RESTORE_SQL_DIR/restore-restrictions-verify.sql")
TOKEN_KEY_CONTINUITY_SQL=$(cat "$RESTORE_SQL_DIR/restore-token-key-continuity.sql")
RESTORE_CONTINUITY_CONTRACT_VERSION=$(cat "$RESTORE_SQL_DIR/restore-continuity.version")
readonly RESTORE_CONTINUITY_CONTRACT_VERSION
DATABASE_PRIVILEGES_SQL=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/selfhost python3 -c \
  'from chronicle_ops.verify import DATABASE_PRIVILEGES_SQL; print(DATABASE_PRIVILEGES_SQL)')
EXIT_RESTORE_TRANSACTION_ROLLED_BACK=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/selfhost python3 -c \
  'from chronicle_ops.dump import EXIT_RESTORE_TRANSACTION_ROLLED_BACK; print(EXIT_RESTORE_TRANSACTION_ROLLED_BACK)')
EXIT_REJECTED_BEFORE_MUTATION=$(PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/selfhost python3 -c \
  'from chronicle_ops.dump import EXIT_REJECTED_BEFORE_MUTATION; print(EXIT_REJECTED_BEFORE_MUTATION)')
DUMP_SCHEMA_EXCLUDES=$(verify_restore_dump --dump-excludes)
mapfile -t DUMP_SCHEMA_OPTIONS <<<"$DUMP_SCHEMA_EXCLUDES"
CATALOG_GATE_SQL=$(verify_restore_dump --catalog-gate)
CATALOG_CAPTURE_SQL=$(verify_restore_dump --capture-catalog)
CATALOG_VERIFY_LIVE_SQL=$(verify_restore_dump --verify-live-catalog)
RESTORE_PREPARE_SQL=$(verify_restore_dump --prepare-restore)
RESTORE_RECOVER_SCHEMAS_SQL=$(verify_restore_dump --recover-schemas)
RESTORE_EXTENSIONS_SQL=$(verify_restore_dump --restore-extensions)
SESSION_CUTOFF_SQL=$(verify_restore_dump --session-cutoff)

# ---------------------------------------------------------------------------------------
# 1. The dump must exist and be readable BEFORE anything is dropped.
# ---------------------------------------------------------------------------------------
if [[ ! -s "$RESTORE_FILE" ]]; then
  echo "  FAIL no dump at ${RESTORE_FILE}" >&2
  echo "       pass one explicitly:" >&2
  echo "         ./chronicle restore --trusted-sha256=REVIEWED_SHA256 /backups/daily/chronicle-YYYYMMDD.sql.gz" >&2
  echo "       available:" >&2
  find "$BACKUPS_DIR" -name '*.sql.gz' -type f 2>/dev/null | sed 's|^|         |' >&2 || true
  exit 1
fi

# RESTORE_FILE is already the private copy ./chronicle restore pinned and rechecked
# (chronicle_ops/restore.py pin_input); this service refuses any other caller above.
verify_restore_dump "$RESTORE_FILE" "${CHRONICLE_RESTORE_TRUSTED_SHA256:-}" || exit "$?"

echo "  ok   ${RESTORE_FILE} passes its gzip integrity check"
psql_q -c "$CATALOG_GATE_SQL" >/dev/null || exit "$EXIT_REJECTED_BEFORE_MUTATION"

# ---------------------------------------------------------------------------------------
# 2. Snapshot what is about to be replaced. This is not optional: a restore is the one
#    operation whose whole purpose is to discard the current contents, and an operator who
#    restores the wrong dump has no other way back.
# ---------------------------------------------------------------------------------------
command -v mktemp >/dev/null 2>&1 || {
  echo "  FAIL mktemp is unavailable; refusing to create an overwrite-prone safety dump" >&2
  exit 1
}
SAFETY_DUMP="$(mktemp "${BACKUPS_DIR}/pre-restore-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX.sql.gz")" || {
  echo "  FAIL unable to reserve a unique pre-restore safety dump" >&2
  exit 1
}
if PGPASSWORD="$POSTGRES_PASSWORD" pg_dump \
     -h "${POSTGRES_HOST:-postgres}" -p "${POSTGRES_PORT:-5432}" \
     -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner \
     "${DUMP_SCHEMA_OPTIONS[@]}" 2>/dev/null \
     | gzip > "$SAFETY_DUMP" && [[ -s "$SAFETY_DUMP" ]] &&
     verify_restore_dump "$SAFETY_DUMP" 2>/dev/null &&
     verify_restore_dump --stamp-installed "$SAFETY_DUMP" "$RESTORE_SQL_DIR" && /bin/chmod 0600 "$SAFETY_DUMP"; then
  echo "  ok   current database saved to ${SAFETY_DUMP}"
else
  /bin/rm -f "$SAFETY_DUMP"
  echo "  FAIL unable to create pre-restore safety dump; refusing to drop the existing schema" >&2
  echo "       verify database connectivity, credentials, free space, and backup-directory permissions" >&2
  exit 1
fi

# ---------------------------------------------------------------------------------------
# 3. Preserve post-backup security authorities outside public.
#
#    A restore can move the public schema backward in time. Without this checkpoint, a
#    backup taken before withdrawal could reactivate the participant, their mobile key,
#    and the data that a later deletion proof had already erased. The backend consumes this
#    owner-only schema during its blocking initialization task and drops it only after a
#    fresh reconciliation receipt and any replacement deletion proof commit atomically. It
#    also preserves collection-settings revisions and enrollment-invitation state so an older
#    backup cannot roll back containment or resurrect a consumed/revoked/deleted invitation.
# ---------------------------------------------------------------------------------------
application_schema_exists=$(psql_q -c "SELECT to_regclass('public.flyway_schema_history') IS NOT NULL")
if [[ "$application_schema_exists" == t ]]; then
continuity_schema_exists=$(psql_q -c \
  "SELECT CASE WHEN to_regnamespace('chronicle_restore_continuity') IS NULL THEN 0 ELSE 1 END")
if [[ "$continuity_schema_exists" == "0" ]]; then
  echo "  --   capturing withdrawal and erasure continuity checkpoint"
  psql_q -1 < "$RESTORE_SQL_DIR/restore-checkpoint-capture.sql" >/dev/null
  echo "  ok   withdrawal and erasure continuity checkpoint captured"
else
  checkpoint_rows=$(psql_q -c \
    "SELECT count(*) FROM chronicle_restore_continuity.checkpoint")
  [[ "$checkpoint_rows" == "1" ]] || {
    echo "  FAIL incomplete restore continuity state cannot be resumed safely" >&2
    echo "       Chronicle remains stopped; recover the existing checkpoint before retrying" >&2
    exit 1
  }
  checkpoint_contract=$(psql_q -c \
    "SELECT contract_version FROM chronicle_restore_continuity.checkpoint")
  [[ "$checkpoint_contract" == "$RESTORE_CONTINUITY_CONTRACT_VERSION" ]] || {
    echo "  FAIL unresolved continuity checkpoint uses unsupported contract ${checkpoint_contract}" >&2
    echo "       Chronicle remains stopped and the database is unchanged; preserve the checkpoint and restore lock for recovery" >&2
    exit 1
  }
  echo "  --   reusing the unresolved withdrawal and erasure continuity checkpoint"
fi

# Treat a resumed checkpoint as hostile until its privilege boundary has been reasserted.
# This is intentionally unconditional: a failed/manual recovery attempt must not be able to
# leave the evidence readable or writable by either runtime role before a retry continues.
psql_q <<'SQL' >/dev/null
REVOKE ALL ON SCHEMA chronicle_restore_continuity
    FROM PUBLIC, chronicle_app, chronicle_admin;
REVOKE ALL ON ALL TABLES IN SCHEMA chronicle_restore_continuity
    FROM PUBLIC, chronicle_app, chronicle_admin;
SQL

# Bind the transient evidence to the pre-restore safety backup as a separate protected SQL
# artifact. It is excluded from the main dump so restoring that dump cannot collide with the
# live owner-only schema; the companion is the recovery source if the database volume is lost
# before server reconciliation completes.
CONTINUITY_DUMP="${SAFETY_DUMP%.sql.gz}.continuity.sql.gz"
if PGPASSWORD="$POSTGRES_PASSWORD" pg_dump \
     -h "${POSTGRES_HOST:-postgres}" -p "${POSTGRES_PORT:-5432}" \
     -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner \
     --schema=chronicle_restore_continuity 2>/dev/null \
     | gzip > "$CONTINUITY_DUMP" && [[ -s "$CONTINUITY_DUMP" ]] &&
     verify_restore_dump "$CONTINUITY_DUMP" 2>/dev/null &&
     verify_restore_dump --stamp-installed "$CONTINUITY_DUMP" "$RESTORE_SQL_DIR" && /bin/chmod 0600 "$CONTINUITY_DUMP"; then
  echo "  ok   continuity companion saved to ${CONTINUITY_DUMP}"
else
  /bin/rm -f -- "$CONTINUITY_DUMP"
  echo "  FAIL could not preserve the restore continuity companion" >&2
  echo "       application data is untouched; the owner-only checkpoint remains in PostgreSQL" >&2
  echo "       ${SAFETY_DUMP} holds the pre-restore public data" >&2
  exit 1
fi

else
  echo "  --   empty application database; no live continuity to capture"
fi

# ---------------------------------------------------------------------------------------
# 4. Drop the application schema.
#
#    Objects OWNED BY AN EXTENSION are left alone, which is why this drops objects one by
#    one instead of the obvious `DROP SCHEMA public CASCADE`. pg_tde installs into public,
#    so dropping the schema takes the tde_heap access method with it -- and then the restore
#    below lands every table on plain heap, unencrypted, while reporting success.
# ---------------------------------------------------------------------------------------
echo "  --   dropping the existing schema (pg_tde and other extensions are preserved)"
# DDL, dump replay and rollback proof commit together. An error or producer interruption
# closes this session without COMMIT, preserving the live public schema and its data.
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/selfhost python3 - "$BACKUPS_DIR" <<'PY_MARKER'
from pathlib import Path
import sys
from chronicle_ops.dump import RESTORE_MUTATION_MARKER
from chronicle_ops.receipts import write_text
write_text(Path(sys.argv[1]) / RESTORE_MUTATION_MARKER, "mutation started\n")
PY_MARKER
if {
# Live extensions the dump leaves out exist before the catalog capture, so they count as live.
printf 'BEGIN;\n%s\n%s\n' "$RESTORE_EXTENSIONS_SQL" "$CATALOG_CAPTURE_SQL"
cat <<'SQL'
-- pg_dump ACLs describe grants relative to standard creation ACLs. Clear the runtime
-- bootstrap additions first; the dump restores its saved defaults after its ACLs.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM chronicle_app, chronicle_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM chronicle_app, chronicle_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM chronicle_app, chronicle_admin;
-- Other sessions still holding the old schema would block the drops. The backend should be
-- stopped already; this covers anything else that reconnected in the meantime.
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
 WHERE datname = current_database() AND pid <> pg_backend_pid();
SQL
echo "$RESTORE_PREPARE_SQL"

# ---------------------------------------------------------------------------------------
# 5. Restore. ON_ERROR_STOP is the entire point: without it psql reports success no matter
#    what happened, which is the failure this script exists to prevent.
# ---------------------------------------------------------------------------------------
echo "  --   restoring ${RESTORE_FILE}" >&2
# stdout is the dump echoing its own SET/COPY results back; only stderr carries anything the
# operator needs, and ON_ERROR_STOP plus the exit status carry the verdict.
gzip -dc "$RESTORE_FILE" || exit 1
# pg_dump empties search_path for the rest of the session. The restored schema's trigger
# functions name tables unqualified, as the application's sessions resolve them in public, so
# every write below would fail inside those triggers. Pinned rather than RESET: the default
# "$user" entry would let a schema in the dump named after this role shadow public tables.
echo 'SET LOCAL search_path = pg_catalog, public, pg_temp;'
echo "$RESTORE_RECOVER_SCHEMAS_SQL"
echo "$CATALOG_VERIFY_LIVE_SQL"
# Invalidate every older researcher JWT in the same transaction, including a fresh target.
echo "$SESSION_CUTOFF_SQL"

# ---------------------------------------------------------------------------------------
# 6. Reapply the non-negotiable containment decision before any application starts.
#
#    The current backend later replays immutable receipts and deletion operations, but an
#    older restored schema must never have a window where a withdrawn participant or mobile
#    credential is active. This owner transaction also satisfies V68's mutation guard through
#    the same explicit deletion-worker context used by the canonical erasure worker.
# ---------------------------------------------------------------------------------------
if [[ "$application_schema_exists" == t ]]; then
echo "$TOKEN_KEY_CONTINUITY_SQL"
echo "  --   applying post-backup withdrawal containment" >&2
cat <<SQL
DO \$\$
BEGIN
    IF to_regclass('public.api_keys') IS NULL
       OR to_regclass('public.study_participants') IS NULL THEN
        RAISE EXCEPTION 'Restored schema predates the supported withdrawal containment contract';
    END IF;
END \$\$;

SET LOCAL app.is_admin = 'true';
SET LOCAL app.current_user_id = 'chronicle-deletion-worker';
SET LOCAL app.is_deletion_worker = 'true';
$WITHDRAWAL_CONTAINMENT_SQL
$RESTRICTIONS_CONTAINMENT_SQL
$RESTRICTIONS_VERIFICATION_SQL
SQL

# Rollback only (set by chronicle_ops Rollback, never by --no-start): consume only a complete
# current-contract checkpoint whose every fact is already protected by the rollback dump. Proof
# and consumption are one owner transaction. Unsupported, missing, corrupt, or newer evidence
# stays available to the current backend reconciler.
if [[ "${CHRONICLE_RESTORE_ROLLBACK:-false}" == true ]]; then
  echo "  --   verifying rollback backup already contains protected continuity evidence" >&2
  cat "$RESTORE_SQL_DIR/restore-checkpoint-verify.sql"
fi
fi
cat <<SQL
DO \$\$
BEGIN
    IF NOT ($DATABASE_PRIVILEGES_SQL) THEN
        RAISE EXCEPTION 'restored database violates audit/restore least privilege; use a backup that preserves ACLs';
    END IF;
END \$\$;
COMMIT;
SQL
} | psql_q >/dev/null; then
  echo "  ok   restore, containment and database privileges committed together"
else
  restore_status=("${PIPESTATUS[@]}")
  echo "  FAIL restore transaction did not complete; safety dump: ${SAFETY_DUMP}" >&2
  if [[ "${restore_status[1]}" == 3 || "${restore_status[1]}" == 0 ]]; then
    echo "       the live database was preserved; the current release can resume" >&2
    exit "$EXIT_RESTORE_TRANSACTION_ROLLED_BACK"
  fi
  echo "       connection outcome is uncertain; preserve the lock and inspect PostgreSQL before recovery" >&2
  exit 1
fi

# ---------------------------------------------------------------------------------------
# 7. Report what landed, including whether it is encrypted. A dump taken from an
#    unencrypted instance restores as plain heap; that is expected and db-init's sweep
#    converts it on the next `docker compose up -d`.
# ---------------------------------------------------------------------------------------
psql_q -c "ANALYZE" >/dev/null
tables=$(psql_q -c "SELECT count(*) FROM pg_stat_user_tables WHERE schemaname = 'public'")
rows=$(psql_q -c "SELECT coalesce(sum(n_live_tup),0) FROM pg_stat_user_tables WHERE schemaname = 'public'")
echo "  ok   restored ${tables} table(s), ${rows} row(s)"

psql_q -F' ' -c "
  SELECT '  ok   storage: ' || a.amname || ' x ' || count(*)
    FROM pg_class c
    JOIN pg_am a ON a.oid = c.relam
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind = 'r'
   GROUP BY a.amname"

if [[ "${ENABLE_ENCRYPTION:-true}" == true ]]; then
  plain=$(psql_q -c "
    SELECT count(*) FROM pg_class c
      JOIN pg_am a ON a.oid = c.relam
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.amname <> 'tde_heap'")
  if [[ "$plain" != "0" ]]; then
    echo "  --   ${plain} table(s) are on plain heap; \`docker compose up -d\` encrypts them"
  fi
fi

echo "  ok   database restore complete; the guarded operator command will start Chronicle"
if [[ "$application_schema_exists" == t ]]; then
  echo "       Startup remains blocked until the server consumes the continuity checkpoint."
fi
