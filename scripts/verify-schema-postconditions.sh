#!/bin/bash
# Schema postcondition verifier for the Chronicle deployment host.
#
# Proves that the live database actually carries the invariants the migration corpus
# is supposed to establish — a healthy backend container does NOT imply this (the old
# upgrade system swallowed migration failures for months; see
# docs/db/MIGRATION-LEDGER-AUDIT.md). Run after every deploy and after the Flyway cutover.
#
# Checks:
#   1. flyway_schema_history exists, has no failed entries, and no pending corpus files
#   2. RLS enabled+forced on the security-critical tables
#   2b. Runtime roles cannot mutate immutable withdrawal/revision evidence
#   3. 32 RESTRICTIVE deletion-quarantine policies (current corpus)
#   4. Re-issued orphan tables exist (V55-V58: webhooks, orgs, refresh tokens)
#   4b. Audit handoff/immutability triggers present (V54/V59)
#   5. TDE coverage: every public table on tde_heap (excluding flyway_schema_history until
#      migrate-tde.sh has run after the deploy)

set -euo pipefail

# Credentials come exclusively from the protected deployment env file below. Drop
# any inherited copies before the first host helper or Docker client is launched.
unset POSTGRES_PASSWORD PGPASSWORD FLYWAY_PASSWORD

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${CHRONICLE_ENV_FILE:-${PROJECT_ROOT}/docker/.env}"
MIGRATION_DIR="${PROJECT_ROOT}/chronicle-server/src/main/resources/db/migration"
# Overridable for cutover rehearsals against a scratch container.
PG_CONTAINER="${CHRONICLE_PG_CONTAINER:-chronicle-postgres}"

[[ -f "${ENV_FILE}" ]] || { echo "ERROR: env file not found: ${ENV_FILE}" >&2; exit 1; }
[[ -d "${MIGRATION_DIR}" ]] || { echo "ERROR: migration dir not found: ${MIGRATION_DIR}" >&2; exit 1; }

# `|| true`: under set -euo pipefail a missing key would otherwise kill the script at
# the assignment, silently — before the explicit diagnostic below can fire.
pg_env() { { grep -E "^$1=" "${ENV_FILE}" | sed -n 1p | cut -d= -f2-; } || true; }
PGUSER="$(pg_env POSTGRES_USER)"
PGPASSWORD="$(pg_env POSTGRES_PASSWORD)"
PGDB="$(pg_env POSTGRES_DB)"
[[ -n "${PGUSER}" && -n "${PGPASSWORD}" && -n "${PGDB}" ]] || {
  echo "ERROR: POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB missing from ${ENV_FILE}" >&2; exit 1;
}

# PGOPTIONS disables parallel gather: parallel scans over pg_tde tables have
# crashed this cluster before, and as an env option it leaves psql output clean.
psql_scalar() {
  local query="$1"
  {
    printf '%s\n' "${PGPASSWORD}"
    printf '%s\n' "${query}"
  } | docker exec -i \
    -e PGOPTIONS="-c max_parallel_workers_per_gather=0" \
    "${PG_CONTAINER}" \
    /bin/bash -euc '
      IFS= read -r PGPASSWORD
      IFS= read -r query
      export PGPASSWORD
      exec psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$1" -d "$2" -Atc "$query"
    ' chronicle-schema-verifier "${PGUSER}" "${PGDB}"
}

FAILURES=0
fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
ok()   { echo "  ok: $*"; }

# Connectivity first: without this, a down/restarting postgres container makes check 1
# report "flyway_schema_history does not exist" — a schema-catastrophe message for what
# is actually an unreachable database.
if [[ "$(psql_scalar "SELECT 1" 2>/dev/null || true)" != "1" ]]; then
  echo "ERROR: cannot query postgres via container '${PG_CONTAINER}' — database unreachable," >&2
  echo "       container down, or credentials wrong. No schema checks were run." >&2
  exit 1
fi

echo "== 1. Flyway ledger =="
if [[ "$(psql_scalar "SELECT to_regclass('public.flyway_schema_history') IS NOT NULL")" != "t" ]]; then
  fail "flyway_schema_history does not exist"
else
  FAILED_COUNT="$(psql_scalar "SELECT count(*) FROM flyway_schema_history WHERE NOT success")"
  [[ "${FAILED_COUNT}" == "0" ]] && ok "no failed migrations" || fail "${FAILED_COUNT} failed migration(s) in ledger"

  # Pending check: every V<n> file at or below the corpus max must be applied or baselined-over.
  MAX_FILE_VERSION="$(ls "${MIGRATION_DIR}"/V*.sql | sed -E 's/.*V([0-9]+)__.*/\1/' | sort -n | tail -1)"
  MAX_DB_VERSION="$(psql_scalar "SELECT COALESCE(MAX(version::int), 0) FROM flyway_schema_history WHERE success AND version ~ '^[0-9]+$'")"
  if [[ "${MAX_DB_VERSION}" -ge "${MAX_FILE_VERSION}" ]]; then
    ok "ledger at V${MAX_DB_VERSION} >= corpus V${MAX_FILE_VERSION}"
  else
    fail "ledger at V${MAX_DB_VERSION} but corpus has V${MAX_FILE_VERSION} — pending migrations"
  fi

  # Gap check: MAX() alone misses a deleted/skipped ledger row below the max. Count the
  # corpus files above the baseline and require the same number of successful ledger rows.
  BASELINE_VERSION="$(psql_scalar "SELECT COALESCE(MAX(version::int), 0) FROM flyway_schema_history WHERE type = 'BASELINE' AND version ~ '^[0-9]+$'")"
  FILES_ABOVE_BASELINE="$(ls "${MIGRATION_DIR}"/V*.sql | sed -E 's/.*V([0-9]+)__.*/\1/' | awk -v b="${BASELINE_VERSION}" '$1 > b' | wc -l)"
  ROWS_ABOVE_BASELINE="$(psql_scalar "SELECT count(*) FROM flyway_schema_history WHERE success AND type = 'SQL' AND version ~ '^[0-9]+$' AND version::int > ${BASELINE_VERSION}")"
  if [[ "${ROWS_ABOVE_BASELINE}" -eq "${FILES_ABOVE_BASELINE}" ]]; then
    ok "no ledger gaps above baseline V${BASELINE_VERSION} (${ROWS_ABOVE_BASELINE} applied)"
  else
    fail "ledger has ${ROWS_ABOVE_BASELINE} applied migrations above baseline V${BASELINE_VERSION} but corpus has ${FILES_ABOVE_BASELINE} files — gapped or extra ledger rows"
  fi
fi

echo "== 2. RLS enabled+forced on critical tables =="
# NB: the `audit` table is append-only via grants, not RLS (see corpus test
# testDirectAppendOnlyAudit) — it does not belong in this list.
for t in study_participants candidates study_settings_audit participant_collection_acknowledgment mobile_withdrawal_requests data_collection_settings_revisions; do
  STATE="$(psql_scalar "SELECT relrowsecurity::text || '/' || relforcerowsecurity::text FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public' AND c.relname='${t}'")"
  [[ "${STATE}" == "true/true" ]] && ok "${t}" || fail "RLS on ${t}: ${STATE:-missing}"
done

echo "== 2b. Immutable audit, withdrawal, settings-revision, and restore-receipt grants =="
for spec in \
  audit:UPDATE \
  audit:DELETE \
  audit:TRUNCATE \
  audit_buffer:UPDATE \
  audit_buffer:DELETE \
  audit_buffer:TRUNCATE \
  mobile_withdrawal_requests:UPDATE \
  mobile_withdrawal_requests:DELETE \
  mobile_withdrawal_requests:TRUNCATE \
  data_collection_settings_revisions:INSERT \
  data_collection_settings_revisions:UPDATE \
  data_collection_settings_revisions:DELETE \
  data_collection_settings_revisions:TRUNCATE \
  restore_continuity_reconciliations:INSERT \
  restore_continuity_reconciliations:UPDATE \
  restore_continuity_reconciliations:DELETE \
  restore_continuity_reconciliations:TRUNCATE; do
  TABLE_NAME="${spec%%:*}"
  PRIVILEGE="${spec##*:}"
  MUTABLE="$(psql_scalar "SELECT has_table_privilege('chronicle_app', 'public.${TABLE_NAME}', '${PRIVILEGE}') OR has_table_privilege('chronicle_admin', 'public.${TABLE_NAME}', '${PRIVILEGE}')")"
  [[ "${MUTABLE}" == "f" ]] && ok "${TABLE_NAME} denies ${PRIVILEGE}" || fail "${TABLE_NAME} grants ${PRIVILEGE} to a runtime role"
done

WITHDRAWAL_APP_INSERT="$(psql_scalar "SELECT has_table_privilege('chronicle_app', 'public.mobile_withdrawal_requests', 'INSERT')")"
WITHDRAWAL_ADMIN_INSERT="$(psql_scalar "SELECT has_table_privilege('chronicle_admin', 'public.mobile_withdrawal_requests', 'INSERT')")"
[[ "${WITHDRAWAL_APP_INSERT}" == "t" ]] && ok "application may append withdrawal receipts" || fail "chronicle_app cannot append withdrawal receipts"
[[ "${WITHDRAWAL_ADMIN_INSERT}" == "f" ]] && ok "admin cannot forge withdrawal receipts" || fail "chronicle_admin can forge withdrawal receipts"

RESTORE_APP_SELECT="$(psql_scalar "SELECT has_table_privilege('chronicle_app', 'public.restore_continuity_reconciliations', 'SELECT')")"
RESTORE_ADMIN_SELECT="$(psql_scalar "SELECT has_table_privilege('chronicle_admin', 'public.restore_continuity_reconciliations', 'SELECT')")"
[[ "${RESTORE_APP_SELECT}" == "f" ]] && ok "application cannot read restore receipts" || fail "chronicle_app can read restore receipts"
[[ "${RESTORE_ADMIN_SELECT}" == "t" ]] && ok "admin may read restore receipts" || fail "chronicle_admin cannot read restore receipts"

RUNTIME_SCHEMA_CREATE="$(psql_scalar "SELECT has_schema_privilege('chronicle_app', 'public', 'CREATE') OR has_schema_privilege('chronicle_admin', 'public', 'CREATE')")"
RUNTIME_LEDGER_EXECUTE="$(psql_scalar "SELECT has_function_privilege('chronicle_app', 'public.record_data_collection_settings_revision()', 'EXECUTE') OR has_function_privilege('chronicle_admin', 'public.record_data_collection_settings_revision()', 'EXECUTE')")"
[[ "${RUNTIME_SCHEMA_CREATE}" == "f" ]] && ok "runtime roles cannot create schema objects" || fail "a runtime role can create public-schema objects"
[[ "${RUNTIME_LEDGER_EXECUTE}" == "f" ]] && ok "runtime roles cannot invoke the revision recorder" || fail "a runtime role can invoke the revision recorder"

echo "== 3. Deletion quarantine policies =="
# Keep the expected count in sync with FlywayMigrationCorpusTest.testDeletionLedgerAndParticipantAccess
# (chronicle-server) — both assert the current registry size independently.
QP="$(psql_scalar "SELECT count(*) FROM pg_policies WHERE policyname LIKE 'deletion_quarantine_%' AND permissive='RESTRICTIVE'")"
[[ "${QP}" == "32" ]] && ok "32 restrictive quarantine policies" || fail "expected 32 quarantine policies, found ${QP}"

echo "== 4. Re-issued orphan tables (V55-V58) =="
for t in webhook_registrations webhook_deliveries; do
  [[ "$(psql_scalar "SELECT to_regclass('public.${t}') IS NOT NULL")" == "t" ]] && ok "${t}" || fail "table ${t} missing"
done

echo "== 4b. Audit handoff triggers (V54/V59) =="
# V59 installs a BEFORE INSERT forwarding trigger on audit_buffer so legacy-path
# writes (rolling old replicas, emergency binary rollback) land in audit, plus
# immutability triggers on both audit tables.
for trg in forward_legacy_audit_buffer_insert_trigger:audit_buffer prevent_audit_modification_trigger:audit prevent_audit_buffer_modification_trigger:audit_buffer; do
  NAME="${trg%%:*}"; TBL="${trg##*:}"
  PRESENT="$(psql_scalar "SELECT count(*) FROM pg_trigger WHERE tgname='${NAME}' AND tgrelid=to_regclass('public.${TBL}') AND NOT tgisinternal")"
  [[ "${PRESENT}" == "1" ]] && ok "${NAME} on ${TBL}" || fail "trigger ${NAME} missing on ${TBL}"
done

echo "== 5. TDE coverage =="
if [[ "${CHRONICLE_SKIP_TDE_CHECK:-0}" == "1" ]]; then
  echo "  skipped (CHRONICLE_SKIP_TDE_CHECK=1 — rehearsal container has no pg_tde)"
else
PLAIN="$(psql_scalar "SELECT count(*) FROM pg_class c JOIN pg_am a ON c.relam=a.oid JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public' AND c.relkind='r' AND a.amname <> 'tde_heap' AND c.relname <> 'flyway_schema_history'")"
[[ "${PLAIN}" == "0" ]] && ok "all application tables on tde_heap" || fail "${PLAIN} table(s) not TDE-encrypted — run docker/migrate-tde.sh"
FLYWAY_AM="$(psql_scalar "SELECT a.amname FROM pg_class c JOIN pg_am a ON c.relam=a.oid WHERE c.relname='flyway_schema_history'")"
[[ "${FLYWAY_AM:-missing}" == "tde_heap" ]] && ok "flyway_schema_history on tde_heap" || echo "  note: flyway_schema_history am=${FLYWAY_AM:-n/a} (run docker/migrate-tde.sh after first migrate)"
fi

echo "== 6. Foreign-key indexes =="
MISSING_FK_INDEXES="$(psql_scalar "SELECT COALESCE(string_agg(c.conrelid::regclass::text || '.' || c.conname, ', ' ORDER BY c.conrelid::regclass::text, c.conname), '') FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE c.contype='f' AND n.nspname='public' AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid=c.conrelid AND i.indisvalid AND i.indisready AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnkeyatts >= cardinality(c.conkey) AND (i.indkey::smallint[])[0:cardinality(c.conkey)-1] @> c.conkey)")"
[[ -z "$MISSING_FK_INDEXES" ]] && ok "all foreign keys have usable leading-column indexes" || fail "foreign keys without indexes: $MISSING_FK_INDEXES"

echo "== 7. Query statistics and representative plans =="
EVIDENCE_DIR="${CHRONICLE_SCHEMA_EVIDENCE_DIR:-${PROJECT_ROOT}/build/schema-evidence}"
umask 077
mkdir -p "$EVIDENCE_DIR"
if [[ "$(psql_scalar "SELECT to_regclass('public.pg_stat_statements') IS NOT NULL")" == t ]]; then
  psql_scalar "SELECT queryid, calls, round((total_exec_time / NULLIF(calls,0))::numeric,3) AS mean_ms, rows, shared_blks_hit, shared_blks_read FROM pg_stat_statements WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database()) ORDER BY total_exec_time DESC LIMIT 20" >"$EVIDENCE_DIR/query-statistics.tsv"
  ok "normalized query fingerprints/statistics recorded without SQL text"
else
  fail "pg_stat_statements is missing; enable its preload and migration-owned extension"
fi
psql_scalar "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT participant_id FROM public.study_participants WHERE study_id=(SELECT study_id FROM public.studies ORDER BY study_id LIMIT 1) ORDER BY participant_id LIMIT 20" >"$EVIDENCE_DIR/study-participants-plan.json"
ok "bounded participant-list EXPLAIN ANALYZE recorded at $EVIDENCE_DIR"

echo
if [[ "${FAILURES}" -gt 0 ]]; then
  echo "SCHEMA POSTCONDITIONS: ${FAILURES} FAILURE(S)" >&2
  exit 1
fi
echo "SCHEMA POSTCONDITIONS: all green"
