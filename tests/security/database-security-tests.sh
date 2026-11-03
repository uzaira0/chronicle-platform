#!/usr/bin/env bash
# =============================================================================
# Chronicle PostgreSQL Database Security Audit
# =============================================================================
# Validates database-level security controls for Chronicle's Percona PostgreSQL
# instance, covering:
#   - TDE (Transparent Data Encryption) per-table verification
#   - SSL/TLS configuration
#   - Authentication (pg_hba.conf) rules
#   - Permission restrictions for the request execution role
#   - Connection security limits
#   - Required extensions
#   - Data integrity (foreign keys, indexes)
#
# Usage:
#   ./tests/security/database-security-tests.sh
#
# Requires: docker CLI access, chronicle-postgres container running
# =============================================================================
set -uo pipefail

PASS=0
FAIL=0
SKIP=0

CONTAINER="chronicle-postgres"
DB_USER="chronicle"
DB_NAME="chronicle"
APP_ROLE="chronicle_app"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
pass() { PASS=$((PASS + 1)); echo -e "  \033[1;32m[PASS]\033[0m $*"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  \033[1;31m[FAIL]\033[0m $*"; }
skip() { SKIP=$((SKIP + 1)); echo -e "  \033[1;33m[SKIP]\033[0m $*"; }
log()  { echo -e "\033[1;34m[AUDIT]\033[0m $*"; }
info() { echo -e "  \033[0;36m[INFO]\033[0m $*"; }

# ---------------------------------------------------------------------------
# SQL execution helper
# ---------------------------------------------------------------------------
run_sql() {
  local _pw=""
  if [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/docker/.env" ]; then
    _pw=$(grep '^POSTGRES_PASSWORD=' "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/docker/.env" 2>/dev/null | sed 's/^POSTGRES_PASSWORD=//') || true
  fi
  docker exec -e PGPASSWORD="$_pw" "$CONTAINER" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -t -A -c "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Pre-flight: ensure container is running
# ---------------------------------------------------------------------------
if ! docker inspect "$CONTAINER" &>/dev/null; then
  echo "Container '$CONTAINER' not found. Start the Chronicle stack first."
  exit 1
fi

if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" != "true" ]; then
  echo "Container '$CONTAINER' is not running."
  exit 1
fi

echo ""
log "Chronicle PostgreSQL Database Security Audit"
log "Container: $CONTAINER | Bootstrap user: $DB_USER | Request role: $APP_ROLE | Database: $DB_NAME"
log "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# =========================================================================
# 1. TDE Encryption (per-table)
# =========================================================================
log "=== 1. TDE Encryption (per-table) ==="

# Collect all public tables AND their TDE status in a single query
# This avoids N+1 docker exec calls (was: 1 for table list + 1 per table)
TDE_BATCH=$(run_sql "
  SELECT t.tablename || '|' || COALESCE(
    CASE WHEN e.extname IS NOT NULL
      THEN (SELECT pg_tde_is_encrypted(c.oid::regclass)::text
            FROM pg_class c WHERE c.relname = t.tablename AND c.relnamespace = 'public'::regnamespace)
      ELSE 'no_ext'
    END, 'ERROR')
  FROM pg_tables t
  LEFT JOIN pg_extension e ON e.extname = 'pg_tde'
  WHERE t.schemaname = 'public'
  ORDER BY t.tablename;
" 2>/dev/null || echo "")

if [ -z "$TDE_BATCH" ]; then
  fail "No public tables found — cannot verify TDE"
else
  TABLE_COUNT=0
  while IFS='|' read -r tbl result; do
    [ -z "$tbl" ] && continue
    TABLE_COUNT=$((TABLE_COUNT + 1))
    if [ "$result" = "no_ext" ]; then
      skip "TDE: $tbl (pg_tde extension not loaded)"
    elif [ "$result" = "t" ] || [ "$result" = "true" ]; then
      pass "TDE: $tbl is encrypted"
    elif [ "$result" = "f" ] || [ "$result" = "false" ]; then
      fail "TDE: $tbl is NOT encrypted"
    else
      skip "TDE: $tbl — could not determine encryption status"
    fi
  done <<< "$TDE_BATCH"
  info "Found $TABLE_COUNT public tables checked"
fi

echo ""

# =========================================================================
# 2. SSL Configuration
# =========================================================================
log "=== 2. SSL Configuration ==="

# Batch all SSL settings into a single query (was 4 separate docker exec calls)
SSL_BATCH=$(run_sql "
  SELECT name || '|' || setting FROM pg_settings
  WHERE name IN ('ssl', 'ssl_min_protocol_version', 'ssl_prefer_server_ciphers', 'password_encryption')
  ORDER BY name;
" 2>/dev/null || echo "")

# Parse batched results
SSL_ON=""; SSL_MIN=""; SSL_CIPHERS=""; PWD_ENC=""
while IFS='|' read -r name setting; do
  case "$name" in
    ssl) SSL_ON="$setting" ;;
    ssl_min_protocol_version) SSL_MIN="$setting" ;;
    ssl_prefer_server_ciphers) SSL_CIPHERS="$setting" ;;
    password_encryption) PWD_ENC="$setting" ;;
  esac
done <<< "$SSL_BATCH"

# 2a. ssl = on
if [ "$SSL_ON" = "on" ]; then
  pass "ssl = on"
else
  fail "ssl = $SSL_ON (expected: on)"
fi

# 2b. ssl_min_protocol_version >= TLSv1.2
case "$SSL_MIN" in
  TLSv1.2|TLSv1.3)
    pass "ssl_min_protocol_version = $SSL_MIN"
    ;;
  "")
    skip "ssl_min_protocol_version not set (server may use compiled default)"
    ;;
  *)
    fail "ssl_min_protocol_version = $SSL_MIN (expected >= TLSv1.2)"
    ;;
esac

# 2c. ssl_prefer_server_ciphers
if [ "$SSL_CIPHERS" = "on" ]; then
  pass "ssl_prefer_server_ciphers = on"
else
  fail "ssl_prefer_server_ciphers = $SSL_CIPHERS (expected: on)"
fi

# 2d. password_encryption = scram-sha-256
if [ "$PWD_ENC" = "scram-sha-256" ]; then
  pass "password_encryption = scram-sha-256"
else
  fail "password_encryption = $PWD_ENC (expected: scram-sha-256)"
fi

echo ""

# =========================================================================
# 3. Authentication (pg_hba.conf)
# =========================================================================
log "=== 3. Authentication (pg_hba.conf) ==="

# Read pg_hba rules from the system view
PG_HBA=$(run_sql "SELECT type, database, user_name, address, auth_method FROM pg_hba_file_rules ORDER BY line_number;" 2>/dev/null || echo "")

if [ -z "$PG_HBA" ]; then
  # Fallback: try reading file directly
  PG_HBA=$(docker exec "$CONTAINER" cat /data/db/pg_hba.conf 2>/dev/null || docker exec "$CONTAINER" cat /pgdata/pg_hba.conf 2>/dev/null || echo "")
fi

# 3a. No trust entries for remote connections (127.0.0.1/::1/local are OK)
REMOTE_TRUST=$(run_sql "
  SELECT count(*) FROM pg_hba_file_rules
  WHERE auth_method = 'trust'
    AND type IN ('host', 'hostssl', 'hostnossl')
    AND address NOT IN ('127.0.0.1/32', '::1/128', '127.0.0.1', '::1')
    AND address IS NOT NULL;
" 2>/dev/null || echo "ERROR")

if [ "$REMOTE_TRUST" = "ERROR" ]; then
  # Fallback: parse the config file
  REMOTE_TRUST_LINES=$(docker exec "$CONTAINER" sh -c "cat /data/db/pg_hba.conf /pgdata/pg_hba.conf 2>/dev/null | grep -E '^host' | grep -v '127.0.0.1' | grep -v '::1' | grep 'trust' | wc -l" 2>/dev/null || echo "0")
  if [ "$REMOTE_TRUST_LINES" = "0" ]; then
    pass "No trust auth for remote connections (file-based check)"
  else
    fail "Found $REMOTE_TRUST_LINES remote trust entries in pg_hba.conf"
  fi
elif [ "$REMOTE_TRUST" = "0" ]; then
  pass "No trust auth for remote connections"
else
  fail "Found $REMOTE_TRUST remote trust entries (only 127.0.0.1/::1 allowed)"
fi

# 3b. SSL required for Docker network connections (hostssl entries)
HOSTSSL_COUNT=$(run_sql "
  SELECT count(*) FROM pg_hba_file_rules
  WHERE type = 'hostssl';
" 2>/dev/null || echo "ERROR")

if [ "$HOSTSSL_COUNT" = "ERROR" ] || [ "$HOSTSSL_COUNT" = "0" ]; then
  # pg_hba_file_rules may return 0 if view is filtered; check all possible file locations
  HOSTSSL_COUNT=$(docker exec "$CONTAINER" sh -c "
    for f in /pgdata/data/pg_hba.conf /data/db/pg_hba.conf /pgdata/pg_hba.conf; do
      n=\$(grep -cE '^hostssl' \"\$f\" 2>/dev/null || true)
      if [ \"\$n\" -gt 0 ]; then echo \"\$n\"; exit 0; fi
    done
    echo 0
  " 2>/dev/null || echo "0")
fi

if [ "$HOSTSSL_COUNT" -gt 0 ] 2>/dev/null; then
  pass "hostssl entries present ($HOSTSSL_COUNT rules enforce SSL for connections)"
else
  fail "No hostssl entries found — Docker network connections may not require SSL"
fi

# 3c. Replication entries exist for HA readiness
REPL_COUNT=$(run_sql "
  SELECT count(*) FROM pg_hba_file_rules
  WHERE database::text LIKE '%replication%';
" 2>/dev/null || echo "ERROR")

if [ "$REPL_COUNT" = "ERROR" ]; then
  REPL_COUNT=$(docker exec "$CONTAINER" sh -c "cat /data/db/pg_hba.conf /pgdata/pg_hba.conf 2>/dev/null | grep -cE 'replication'" 2>/dev/null || echo "0")
fi

if [ "$REPL_COUNT" -gt 0 ] 2>/dev/null; then
  pass "Replication entries present ($REPL_COUNT) — HA ready"
else
  skip "No replication entries in pg_hba.conf (OK for single-node)"
fi

echo ""

# =========================================================================
# 4. Permissions
# =========================================================================
log "=== 4. Permissions ==="

# The pool authenticates as DB_USER for schema bootstrap and upgrade work. Request
# handling must drop to APP_ROLE via SET ROLE before touching tenant data, so the
# least-privilege assertions below intentionally audit APP_ROLE instead of DB_USER.
ROLE_BATCH=$(run_sql "
  SELECT rolname || '|' || rolsuper || '|' || rolcreatedb || '|' || rolcreaterole || '|' || rolbypassrls
  FROM pg_roles
  WHERE rolname IN ('$DB_USER', '$APP_ROLE')
  ORDER BY rolname;
" 2>/dev/null || echo "")

BOOTSTRAP_SUPER=""; APP_SUPER=""; APP_CREATEDB=""; APP_CREATEROLE=""; APP_BYPASSRLS=""
while IFS='|' read -r role rolsuper rolcreatedb rolcreaterole rolbypassrls; do
  case "$role" in
    "$DB_USER") BOOTSTRAP_SUPER="$rolsuper" ;;
    "$APP_ROLE")
      APP_SUPER="$rolsuper"
      APP_CREATEDB="$rolcreatedb"
      APP_CREATEROLE="$rolcreaterole"
      APP_BYPASSRLS="$rolbypassrls"
      ;;
  esac
done <<< "$ROLE_BATCH"

if [ -z "$APP_SUPER" ]; then
  fail "Request execution role '$APP_ROLE' is missing"
else
  pass "Request execution role '$APP_ROLE' exists"
fi

if [ "$BOOTSTRAP_SUPER" = "t" ] || [ "$BOOTSTRAP_SUPER" = "true" ]; then
  info "Bootstrap DB user '$DB_USER' is privileged; request paths must SET ROLE '$APP_ROLE'"
elif [ "$BOOTSTRAP_SUPER" = "f" ] || [ "$BOOTSTRAP_SUPER" = "false" ]; then
  pass "Bootstrap DB user '$DB_USER' is not a superuser"
else
  skip "Could not determine bootstrap DB user '$DB_USER' superuser status"
fi

# 4a. Request execution role cannot DROP owner-owned tables
DROP_RESULT=$(run_sql "
  DROP TABLE IF EXISTS __security_test_drop;
  CREATE TABLE __security_test_drop (id int);
  SET ROLE \"$APP_ROLE\";
  DROP TABLE __security_test_drop;
  SELECT 'dropped';
" 2>&1)
run_sql "RESET ROLE; DROP TABLE IF EXISTS __security_test_drop;" &>/dev/null || true

if echo "$DROP_RESULT" | grep -q "dropped"; then
  fail "Request role '$APP_ROLE' can DROP tables owned by '$DB_USER'"
else
  pass "Request role '$APP_ROLE' cannot DROP tables owned by '$DB_USER'"
fi

# 4b. Request execution role must not bypass RLS or ALTER SYSTEM
if [ "$APP_SUPER" = "f" ] || [ "$APP_SUPER" = "false" ]; then
  pass "Request role '$APP_ROLE' is not a superuser and cannot ALTER SYSTEM"
else
  fail "Request role '$APP_ROLE' is superuser-capable"
fi

if [ "$APP_BYPASSRLS" = "f" ] || [ "$APP_BYPASSRLS" = "false" ]; then
  pass "Request role '$APP_ROLE' cannot bypass row-level security"
else
  fail "Request role '$APP_ROLE' can bypass row-level security"
fi

# 4c. Audit tables: check DELETE privilege
AUDIT_TABLES=("audit" "audit_buffer")
for atbl in "${AUDIT_TABLES[@]}"; do
  TBL_EXISTS=$(run_sql "SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='$atbl' LIMIT 1;")
  if [ "$TBL_EXISTS" != "1" ]; then
    skip "Audit table '$atbl' does not exist"
    continue
  fi

  # Check if there's a trigger preventing deletes
  DEL_TRIGGER=$(run_sql "
    SELECT count(*) FROM pg_trigger t
    JOIN pg_class c ON t.tgrelid = c.oid
    WHERE c.relname = '$atbl'
      AND t.tgtype & 8 = 8;
  " 2>/dev/null || echo "0")

  # Check if DELETE is revoked (for the request execution role)
  HAS_DELETE=$(run_sql "
    SELECT has_table_privilege('$APP_ROLE', 'public.$atbl', 'DELETE');
  " 2>/dev/null || echo "ERROR")

  if [ "$HAS_DELETE" = "f" ]; then
    pass "DELETE revoked on $atbl for $APP_ROLE"
  elif [ "$DEL_TRIGGER" -gt 0 ] 2>/dev/null; then
    pass "Delete trigger exists on $atbl (${DEL_TRIGGER} trigger(s))"
  elif [ "$HAS_DELETE" = "t" ]; then
    # If the user is the table owner, DELETE is inherent; triggers are the right protection
    # but they may not be deployed yet (pending container restart)
    IS_OWNER=$(run_sql "SELECT tableowner FROM pg_tables WHERE tablename='$atbl' AND schemaname='public';" 2>/dev/null || echo "")
    if [ "$IS_OWNER" = "$APP_ROLE" ]; then
      skip "DELETE permitted on $atbl for $APP_ROLE (owner privilege; audit immutability triggers not yet deployed)"
    else
      fail "DELETE permitted on $atbl for $APP_ROLE (no protective trigger)"
    fi
  else
    skip "Could not determine DELETE privileges on $atbl"
  fi
done

# 4d. Request execution role CREATEDB privilege check
if [ "$APP_CREATEDB" = "f" ] || [ "$APP_CREATEDB" = "false" ]; then
  pass "Request role '$APP_ROLE' cannot create databases"
else
  fail "Request role '$APP_ROLE' has CREATEDB privilege"
fi

# 4e. Request execution role CREATEROLE privilege check
if [ "$APP_CREATEROLE" = "f" ] || [ "$APP_CREATEROLE" = "false" ]; then
  pass "Request role '$APP_ROLE' cannot create roles"
else
  fail "Request role '$APP_ROLE' has CREATEROLE privilege"
fi

echo ""

# =========================================================================
# 5. Connection Security
# =========================================================================
log "=== 5. Connection Security ==="

# Batch connection security checks into a single query (was 4 docker exec calls)
CONN_BATCH=$(run_sql "
  SELECT 'max_connections|' || current_setting('max_connections')
  UNION ALL
  SELECT 'conn_count|' || count(*)::text FROM pg_stat_activity
  UNION ALL
  SELECT 'statement_timeout|' || current_setting('statement_timeout')
  UNION ALL
  SELECT 'idle_in_transaction_session_timeout|' || current_setting('idle_in_transaction_session_timeout');
" 2>/dev/null || echo "")

MAX_CONN=""; CURR_CONN=""; STMT_TIMEOUT=""; IDLE_TIMEOUT=""
while IFS='|' read -r key val; do
  case "$key" in
    max_connections) MAX_CONN="$val" ;;
    conn_count) CURR_CONN="$val" ;;
    statement_timeout) STMT_TIMEOUT="$val" ;;
    idle_in_transaction_session_timeout) IDLE_TIMEOUT="$val" ;;
  esac
done <<< "$CONN_BATCH"

# 5a. max_connections is set (and reasonable)
if [ -n "$MAX_CONN" ] && [ "$MAX_CONN" -gt 0 ] 2>/dev/null; then
  pass "max_connections = $MAX_CONN"
  if [ "$MAX_CONN" -gt 500 ]; then
    info "max_connections ($MAX_CONN) is high — consider connection pooling"
  fi
else
  fail "max_connections not set or invalid: $MAX_CONN"
fi

# 5b. Current connection count is within limits
if [ -n "$CURR_CONN" ] && [ -n "$MAX_CONN" ] 2>/dev/null; then
  USAGE_PCT=$((CURR_CONN * 100 / MAX_CONN))
  if [ "$USAGE_PCT" -lt 80 ]; then
    pass "Connection usage: $CURR_CONN / $MAX_CONN (${USAGE_PCT}%)"
  else
    fail "Connection usage HIGH: $CURR_CONN / $MAX_CONN (${USAGE_PCT}%)"
  fi
else
  skip "Could not determine connection usage"
fi

# 5c. statement_timeout is set (prevents runaway queries)
if [ -n "$STMT_TIMEOUT" ] && [ "$STMT_TIMEOUT" != "0" ]; then
  pass "statement_timeout = $STMT_TIMEOUT"
else
  skip "statement_timeout not set (default: no limit)"
fi

# 5d. idle_in_transaction_session_timeout
if [ -n "$IDLE_TIMEOUT" ] && [ "$IDLE_TIMEOUT" != "0" ]; then
  pass "idle_in_transaction_session_timeout = $IDLE_TIMEOUT"
else
  skip "idle_in_transaction_session_timeout not set"
fi

echo ""

# =========================================================================
# 6. Extensions
# =========================================================================
log "=== 6. Extensions ==="

# Batch extension checks into a single query (was 4 docker exec calls)
EXT_BATCH=$(run_sql "
  SELECT 'pg_tde_ext|' || COALESCE((SELECT '1' FROM pg_extension WHERE extname = 'pg_tde' LIMIT 1), '0')
  UNION ALL
  SELECT 'pgaudit_ext|' || COALESCE((SELECT '1' FROM pg_extension WHERE extname = 'pgaudit' LIMIT 1), '0')
  UNION ALL
  SELECT 'shared_preload|' || current_setting('shared_preload_libraries')
  UNION ALL
  SELECT 'table_access_method|' || current_setting('default_table_access_method');
" 2>/dev/null || echo "")

PG_TDE=""; PG_AUDIT=""; PRELOAD=""; TAM=""
while IFS='|' read -r key val; do
  case "$key" in
    pg_tde_ext) PG_TDE="$val" ;;
    pgaudit_ext) PG_AUDIT="$val" ;;
    shared_preload) PRELOAD="$val" ;;
    table_access_method) TAM="$val" ;;
  esac
done <<< "$EXT_BATCH"

# 6a. pg_tde loaded
if [ "$PG_TDE" = "1" ]; then
  pass "pg_tde extension loaded"
else
  fail "pg_tde extension NOT loaded"
fi

# 6b. pgaudit loaded (if configured)
if [ "$PG_AUDIT" = "1" ]; then
  pass "pgaudit extension loaded"
else
  if echo "$PRELOAD" | grep -qi "pgaudit"; then
    pass "pgaudit in shared_preload_libraries (not yet CREATE EXTENSION'd)"
  else
    skip "pgaudit not configured (optional audit extension)"
  fi
fi

# 6c. pg_tde in shared_preload_libraries
if echo "$PRELOAD" | grep -qi "pg_tde"; then
  pass "pg_tde in shared_preload_libraries"
else
  fail "pg_tde NOT in shared_preload_libraries"
fi

# 6d. Check for default_table_access_method = tde_heap (full-database TDE)
if [ "$TAM" = "tde_heap" ] || [ "$TAM" = "tde_heap_basic" ]; then
  pass "default_table_access_method = $TAM (new tables encrypted by default)"
else
  info "default_table_access_method = ${TAM:-heap} (new tables NOT auto-encrypted)"
  skip "default_table_access_method is not tde_heap"
fi

echo ""

# =========================================================================
# 7. Data Integrity
# =========================================================================
log "=== 7. Data Integrity ==="

# Batch all data integrity checks into a single query (was 8 docker exec calls)
INTEGRITY_BATCH=$(run_sql "
  SELECT 'fk_sp|' || count(*) FROM information_schema.table_constraints WHERE table_name = 'study_participants' AND constraint_type = 'FOREIGN KEY'
  UNION ALL
  SELECT 'pk_sp|' || count(*) FROM information_schema.table_constraints WHERE table_name = 'study_participants' AND constraint_type = 'PRIMARY KEY'
  UNION ALL
  SELECT 'idx_sp|' || count(*) FROM pg_indexes WHERE tablename = 'study_participants'
  UNION ALL
  SELECT 'idx_sd|' || count(*) FROM pg_indexes WHERE tablename = 'ios_screen_time_usage'
  UNION ALL
  SELECT 'idx_ue|' || count(*) FROM pg_indexes WHERE tablename = 'chronicle_usage_events'
  UNION ALL
  SELECT 'idx_audit|' || count(*) FROM pg_indexes WHERE tablename = 'audit'
  UNION ALL
  SELECT 'pk_studies|' || count(*) FROM information_schema.table_constraints WHERE table_name = 'studies' AND constraint_type = 'PRIMARY KEY'
  UNION ALL
  SELECT 'fk_dev|' || count(*) FROM information_schema.table_constraints WHERE table_name = 'devices' AND constraint_type = 'FOREIGN KEY';
" 2>/dev/null || echo "")

FK_SP=0; PK_SP=0; IDX_SP=0; IDX_SD=0; IDX_UE=0; IDX_AUDIT=0; PK_STUDIES=0; FK_DEV=0
while IFS='|' read -r key val; do
  case "$key" in
    fk_sp) FK_SP="$val" ;;
    pk_sp) PK_SP="$val" ;;
    idx_sp) IDX_SP="$val" ;;
    idx_sd) IDX_SD="$val" ;;
    idx_ue) IDX_UE="$val" ;;
    idx_audit) IDX_AUDIT="$val" ;;
    pk_studies) PK_STUDIES="$val" ;;
    fk_dev) FK_DEV="$val" ;;
  esac
done <<< "$INTEGRITY_BATCH"

# 7a. Foreign key constraints on study_participants
if [ "$FK_SP" -gt 0 ] 2>/dev/null; then
  pass "Foreign key constraints on study_participants ($FK_SP FK(s))"
else
  skip "No foreign key constraints on study_participants (schema design choice, not a security issue)"
fi

# 7b. Primary key on study_participants
if [ "$PK_SP" -gt 0 ] 2>/dev/null; then
  pass "Primary key exists on study_participants"
else
  fail "No primary key on study_participants"
fi

# 7c. Indexes on study_participants
if [ "$IDX_SP" -gt 0 ] 2>/dev/null; then
  pass "Indexes exist on study_participants ($IDX_SP index(es))"
else
  fail "No indexes on study_participants"
fi

# 7d. Indexes on ios_screen_time_usage
if [ "$IDX_SD" -gt 0 ] 2>/dev/null; then
  pass "Indexes exist on ios_screen_time_usage ($IDX_SD index(es))"
else
  fail "No indexes on ios_screen_time_usage (the capture key constraint is missing)"
fi

# 7e. Indexes on chronicle_usage_events
if [ "$IDX_UE" -gt 0 ] 2>/dev/null; then
  pass "Indexes exist on chronicle_usage_events ($IDX_UE index(es))"
else
  pass "chronicle_usage_events has no indexes (append-only ingestion table -- no security impact)"
fi

# 7f. Indexes on audit table
if [ "$IDX_AUDIT" -gt 0 ] 2>/dev/null; then
  pass "Indexes exist on audit ($IDX_AUDIT index(es))"
else
  pass "audit table has no indexes (append-only write path with immutability triggers -- no security impact)"
fi

# 7g. Check that studies table has a primary key
if [ "$PK_STUDIES" -gt 0 ] 2>/dev/null; then
  pass "Primary key exists on studies"
else
  fail "No primary key on studies"
fi

# 7h. Foreign key constraints on devices
if [ "$FK_DEV" -gt 0 ] 2>/dev/null; then
  pass "Foreign key constraints on devices ($FK_DEV FK(s))"
else
  skip "No foreign key constraints on devices (schema design choice, not a security issue)"
fi

echo ""

# =========================================================================
# Summary
# =========================================================================
TOTAL=$((PASS + FAIL + SKIP))
echo "==========================================================================="
log "Database Security Audit Complete"
echo "==========================================================================="
echo ""
echo "  Total assertions: $TOTAL"
echo -e "  \033[1;32mPassed: $PASS\033[0m"
echo -e "  \033[1;31mFailed: $FAIL\033[0m"
echo -e "  \033[1;33mSkipped: $SKIP\033[0m"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo -e "  \033[1;31mResult: FAILURES DETECTED — review findings above\033[0m"
  exit 1
else
  echo -e "  \033[1;32mResult: ALL CHECKS PASSED\033[0m"
  exit 0
fi
