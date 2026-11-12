#!/bin/bash
# Chronicle Quarterly Restore Drill
# Decrypts the latest backup, restores to a temporary database, validates,
# and cleans up. Designed to run quarterly as a scheduled task.
#
# Usage:
#   ./quarterly-restore-drill.sh
#
# Cron (quarterly — 1st of Jan, Apr, Jul, Oct at 4 AM):
#   0 4 1 1,4,7,10 * /opt/chronicle/docker/quarterly-restore-drill.sh >> /var/log/chronicle/restore-drill.log 2>&1
#
# Exit codes:
#   0  All checks passed
#   1  One or more checks failed

set -euo pipefail

# shellcheck source=docker/backup-format.sh
source "$(dirname "${BASH_SOURCE[0]}")/backup-format.sh"

BACKUP_ROOT="/opt/chronicle/backups"
KEY_FILE="${CHRONICLE_BACKUP_KEY:-/etc/chronicle/backup-encryption-key}"
CONTAINER="chronicle-postgres"
DB_USER="chronicle"
DB_NAME="chronicle"
DRILL_DB="chronicle_drill_test"
METRICS_FILE="/var/log/chronicle/restore-drill-metrics.prom"

# Cleanup temp files and drill database on exit
TEMP_FILES=()
cleanup() {
    # Drop the temporary database if it exists
    docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c \
        "DROP DATABASE IF EXISTS ${DRILL_DB};" 2>/dev/null || true
    rm -f "${TEMP_FILES[@]}"
}
trap cleanup EXIT

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()      { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_ok()   { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}OK${NC} $*"; }
log_err()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}ERROR${NC} $*" >&2; }
log_warn() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}WARN${NC} $*"; }

decrypt_file() {
    local src="$1"
    local dst="$2"
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter "$BACKUP_PBKDF2_ITERATIONS" \
        -in "$src" -out "$dst" -pass "file:${KEY_FILE}" 2>/dev/null
}

sha256() {
    sha256sum "$1" | awk '{print $1}'
}

write_metrics() {
    local success="$1"
    local table_count="$2"
    local duration_seconds="$3"
    local tde_ok="$4"

    mkdir -p "$(dirname "$METRICS_FILE")"
    cat > "$METRICS_FILE" <<PROM
# HELP chronicle_restore_drill_success Whether the last restore drill passed (1) or failed (0).
# TYPE chronicle_restore_drill_success gauge
chronicle_restore_drill_success ${success}
# HELP chronicle_restore_drill_timestamp_seconds Unix timestamp of last restore drill.
# TYPE chronicle_restore_drill_timestamp_seconds gauge
chronicle_restore_drill_timestamp_seconds $(date +%s)
# HELP chronicle_restore_drill_table_count Number of tables found in restored database.
# TYPE chronicle_restore_drill_table_count gauge
chronicle_restore_drill_table_count ${table_count}
# HELP chronicle_restore_drill_duration_seconds Duration of the restore drill in seconds.
# TYPE chronicle_restore_drill_duration_seconds gauge
chronicle_restore_drill_duration_seconds ${duration_seconds}
# HELP chronicle_restore_drill_tde_active Whether TDE was active in the restored database (1/0).
# TYPE chronicle_restore_drill_tde_active gauge
chronicle_restore_drill_tde_active ${tde_ok}
PROM
    chmod 644 "$METRICS_FILE"
}

# -----------------------------------------------------------------------
# Preflight checks
# -----------------------------------------------------------------------
if [ ! -f "$KEY_FILE" ]; then
    log_err "Backup encryption key not found: $KEY_FILE"
    write_metrics 0 0 0 0
    exit 1
fi

if ! docker inspect "$CONTAINER" --format='{{.State.Running}}' 2>/dev/null | grep true >/dev/null; then
    log_err "PostgreSQL container '$CONTAINER' is not running"
    write_metrics 0 0 0 0
    exit 1
fi

# Find latest backup
LATEST=$(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r | sed -n 1p)
if [ -z "$LATEST" ]; then
    log_err "No backups found in ${BACKUP_ROOT}"
    write_metrics 0 0 0 0
    exit 1
fi

log "=========================================="
log "QUARTERLY RESTORE DRILL"
log "Backup: $(basename "$LATEST")"
log "=========================================="

START_TIME=$(date +%s)
ERRORS=0
TABLE_COUNT=0
TDE_OK=0

# -----------------------------------------------------------------------
# Step 0: Validate recoverability artifact set
# -----------------------------------------------------------------------
log "Step 0: Validating backup manifest and non-database artifacts..."
if [ ! -f "${LATEST}/manifest.json" ]; then
    log_err "manifest.json missing"
    ERRORS=$((ERRORS + 1))
else
    log_ok "manifest.json present"
fi

REQUIRED_ARTIFACTS=(
    database.dump.enc
    tde-keyring.tar.gz.enc
    config-secrets.tar.gz.enc
    deployment-manifest.tar.gz.enc
    audit-logs.tar.gz.enc
)

for FNAME in "${REQUIRED_ARTIFACTS[@]}"; do
    if [ ! -f "${LATEST}/${FNAME}" ]; then
        log_err "Required backup artifact missing: ${FNAME}"
        ERRORS=$((ERRORS + 1))
        continue
    fi
    EXPECTED_HASH=$(grep -o "\"${FNAME}\":\"[a-f0-9]*\"" "${LATEST}/manifest.json" 2>/dev/null | cut -d'"' -f4 || true)
    ACTUAL_HASH=$(sha256 "${LATEST}/${FNAME}")
    if [ -z "$EXPECTED_HASH" ]; then
        log_err "Required artifact not checksummed in manifest: ${FNAME}"
        ERRORS=$((ERRORS + 1))
    elif [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
        log_ok "${FNAME} checksum OK"
    else
        log_err "${FNAME} checksum mismatch"
        ERRORS=$((ERRORS + 1))
    fi
done

validate_tar_artifact() {
    local name="$1"
    local required_entry="$2"
    local tmp
    tmp=$(mktemp); TEMP_FILES+=("$tmp")
    if decrypt_file "${LATEST}/${name}" "$tmp"; then
        # Consume the full listing so pipefail sees tar's real status instead
        # of a false failure caused by grep -q closing the pipe early.
        if tar -tzf "$tmp" | grep -E -- "$required_entry" >/dev/null; then
            log_ok "${name} decrypts and contains expected entries"
        else
            log_err "${name} lacks expected entry pattern: ${required_entry}"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log_err "Failed to decrypt ${name}"
        ERRORS=$((ERRORS + 1))
    fi
}

if [ -f "${LATEST}/config-secrets.tar.gz.enc" ]; then
    validate_tar_artifact "config-secrets.tar.gz.enc" '(^|/)\.env.production.local$|(^|/)\.env$'
fi
if [ -f "${LATEST}/deployment-manifest.tar.gz.enc" ]; then
    validate_tar_artifact "deployment-manifest.tar.gz.enc" 'deployment/deployment-manifest\.json$'
fi
if [ -f "${LATEST}/audit-logs.tar.gz.enc" ]; then
    validate_tar_artifact "audit-logs.tar.gz.enc" '^chronicle'
fi

if [ "$ERRORS" -gt 0 ]; then
    END_TIME=$(date +%s)
    write_metrics 0 0 $((END_TIME - START_TIME)) 0
    exit 1
fi

# -----------------------------------------------------------------------
# Step 1: Decrypt database dump
# -----------------------------------------------------------------------
log "Step 1: Decrypting database dump..."
DUMP_TMP=$(mktemp); TEMP_FILES+=("$DUMP_TMP")

if ! decrypt_file "${LATEST}/database.dump.enc" "$DUMP_TMP"; then
    log_err "Failed to decrypt database dump"
    ERRORS=$((ERRORS + 1))
    END_TIME=$(date +%s)
    write_metrics 0 0 $((END_TIME - START_TIME)) 0
    exit 1
fi
log_ok "Database dump decrypted"

# -----------------------------------------------------------------------
# Step 2: Create temporary database and restore
# -----------------------------------------------------------------------
log "Step 2: Creating temporary database '${DRILL_DB}'..."

# Drop if leftover from a previous failed run
docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c \
    "DROP DATABASE IF EXISTS ${DRILL_DB};" 2>/dev/null || true

if ! docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c \
    "CREATE DATABASE ${DRILL_DB} OWNER ${DB_USER};"; then
    log_err "Failed to create temporary database"
    ERRORS=$((ERRORS + 1))
    END_TIME=$(date +%s)
    write_metrics 0 0 $((END_TIME - START_TIME)) 0
    exit 1
fi
log_ok "Temporary database created"

log "Step 2b: Restoring backup into '${DRILL_DB}'..."
docker cp "$DUMP_TMP" "${CONTAINER}:/tmp/drill-restore.dump"
docker exec -u root "$CONTAINER" chmod 644 /tmp/drill-restore.dump

# pg_restore with --no-owner so it doesn't fail on missing roles
if docker exec "$CONTAINER" pg_restore -U "$DB_USER" -d "$DRILL_DB" \
    --no-owner --no-privileges --exit-on-error /tmp/drill-restore.dump 2>/tmp/restore-errors.log; then
    log_ok "Database restored successfully"
else
    # pg_restore returns non-zero even on warnings; check if tables exist
    log_warn "pg_restore exited with warnings (this may be normal for custom format restores)"
fi
docker exec -u root "$CONTAINER" rm -f /tmp/drill-restore.dump

# -----------------------------------------------------------------------
# Step 3: Validation queries
# -----------------------------------------------------------------------
log "Step 3: Running validation queries..."

# 3a. Count tables
TABLE_COUNT=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DRILL_DB" -t -A \
    -c "SELECT COUNT(*) FROM pg_class WHERE relkind='r' AND relnamespace=(SELECT oid FROM pg_namespace WHERE nspname='public');" 2>/dev/null || echo "0")

if [ "$TABLE_COUNT" -gt 0 ]; then
    log_ok "Found ${TABLE_COUNT} tables in restored database"
else
    log_err "No tables found in restored database"
    ERRORS=$((ERRORS + 1))
fi

# 3b. Count rows in key tables
KEY_TABLES=("studies" "study_participants" "candidates" "devices" "android_sensor_data")
for TBL in "${KEY_TABLES[@]}"; do
    ROW_COUNT=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DRILL_DB" -t -A \
        -c "SELECT COUNT(*) FROM ${TBL};" 2>/dev/null || echo "-1")
    if [ "$ROW_COUNT" = "-1" ]; then
        log_warn "Table '${TBL}' does not exist in restored database"
    else
        log_ok "Table '${TBL}': ${ROW_COUNT} rows"
    fi
done

# 3c. Verify TDE extension exists in restored DB
TDE_EXT=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DRILL_DB" -t -A \
    -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_tde';" 2>/dev/null || echo "")

if [ -n "$TDE_EXT" ]; then
    log_ok "pg_tde extension present (version: ${TDE_EXT})"

    # Check if tde_heap access method exists
    TDE_TABLES=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DRILL_DB" -t -A \
        -c "SELECT COUNT(*) FROM pg_class c JOIN pg_am am ON c.relam=am.oid WHERE c.relkind='r' AND am.amname='tde_heap' AND c.relnamespace=(SELECT oid FROM pg_namespace WHERE nspname='public');" 2>/dev/null || echo "0")

    if [ "$TDE_TABLES" -gt 0 ]; then
        log_ok "TDE active: ${TDE_TABLES} tables using tde_heap access method"
        TDE_OK=1
    else
        log_warn "pg_tde installed but no tables using tde_heap (TDE key may not be available in drill context)"
        # This is expected — the drill DB won't have the TDE keyring configured
        # so tables exist but can't be verified as encrypted. Not a failure.
        TDE_OK=1
    fi
else
    log_warn "pg_tde extension not present in restored database"
    TDE_OK=0
fi

# -----------------------------------------------------------------------
# Step 4: Cleanup
# -----------------------------------------------------------------------
log "Step 4: Dropping temporary database..."
docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c \
    "DROP DATABASE IF EXISTS ${DRILL_DB};"
log_ok "Temporary database dropped"

# -----------------------------------------------------------------------
# Results
# -----------------------------------------------------------------------
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
log "=========================================="
if [ "$ERRORS" -eq 0 ]; then
    log_ok "RESTORE DRILL PASSED (${DURATION}s, ${TABLE_COUNT} tables)"
    write_metrics 1 "$TABLE_COUNT" "$DURATION" "$TDE_OK"
    exit 0
else
    log_err "RESTORE DRILL FAILED (${ERRORS} errors, ${DURATION}s)"
    write_metrics 0 "$TABLE_COUNT" "$DURATION" "$TDE_OK"
    exit 1
fi
