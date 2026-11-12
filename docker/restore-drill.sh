#!/bin/bash
# Chronicle Restore Drill Script
# Validates disaster recovery by performing a full restore to a temporary database.
#
# Usage:
#   ./restore-drill.sh <backup-directory> [encryption-key-file]
#
# This script:
#   1. Decrypts the backup using the backup encryption key
#   2. Restores to a temporary test database (chronicle_drill_test)
#   3. Runs validation (table count, row counts on key tables)
#   4. Drops the test database
#   5. Reports pass/fail
#
# Schedule quarterly: 0 4 1 */3 * /opt/chronicle/docker/restore-drill.sh <latest-backup>

set -euo pipefail

# shellcheck source=docker/backup-format.sh
source "$(dirname "${BASH_SOURCE[0]}")/backup-format.sh"

DEFAULT_KEY="/etc/chronicle/backup-encryption-key"
CONTAINER="chronicle-postgres"
DB_USER="chronicle"
DRILL_DB="chronicle_drill_test"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log()      { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_ok()   { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}PASS${NC} $*"; }
log_err()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}FAIL${NC} $*" >&2; }
log_warn() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}WARN${NC} $*"; }
log_step() { echo -e "\n${BOLD}=== Step $1: $2 ===${NC}"; }

decrypt_file() {
    local src="$1"
    local dst="$2"
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter "$BACKUP_PBKDF2_ITERATIONS" \
        -in "$src" -out "$dst" -pass "file:${KEY_FILE}" 2>/dev/null
}

sha256() {
    sha256sum "$1" | awk '{print $1}'
}

# ── Cleanup on exit ──────────────────────────────────────────────────────────
TEMP_FILES=()
cleanup() {
    log "Cleaning up..."
    # Drop drill database if it exists
    docker exec "$CONTAINER" psql -U "$DB_USER" -d postgres -c \
        "DROP DATABASE IF EXISTS ${DRILL_DB};" 2>/dev/null || true
    # Remove temp files
    rm -f "${TEMP_FILES[@]}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Parse arguments ───────────────────────────────────────────────────────────
BACKUP_DIR="${1:-}"
KEY_FILE="${2:-$DEFAULT_KEY}"

if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory> [encryption-key-file]"
    echo ""
    echo "Available backups:"
    ls -d /opt/chronicle/backups/[0-9]*_[0-9]* 2>/dev/null | sort -r | while read -r d; do
        echo "  $d"
    done
    exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
    log_err "Backup directory not found: $BACKUP_DIR"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    log_err "Encryption key not found: $KEY_FILE"
    exit 1
fi

if ! docker inspect "$CONTAINER" --format='{{.State.Running}}' 2>/dev/null | grep true >/dev/null; then
    log_err "PostgreSQL container '$CONTAINER' is not running"
    exit 1
fi

# ── Drill begins ──────────────────────────────────────────────────────────────
DRILL_START=$(date +%s)
ERRORS=0

echo ""
echo -e "${BOLD}=========================================="
echo "Chronicle Restore Drill"
echo -e "==========================================${NC}"
echo ""
echo "  Backup:    $(basename "$BACKUP_DIR")"
echo "  Key:       $KEY_FILE"
echo "  Drill DB:  $DRILL_DB"
echo "  Date:      $(date -Iseconds)"
echo ""

# ── Step 1: Verify backup integrity ──────────────────────────────────────────
log_step 1 "Verify backup integrity"

if [ ! -f "${BACKUP_DIR}/manifest.json" ]; then
    log_err "manifest.json missing from backup"
    ERRORS=$((ERRORS + 1))
else
    log_ok "manifest.json present"
fi

if [ ! -f "${BACKUP_DIR}/database.dump.enc" ]; then
    log_err "database.dump.enc missing — cannot proceed"
    exit 1
fi

for F in "${BACKUP_DIR}"/*.enc; do
    [ -f "$F" ] || continue
    FNAME=$(basename "$F")
    ACTUAL=$(sha256 "$F")
    EXPECTED=$(grep -o "\"${FNAME}\":\"[a-f0-9]*\"" "${BACKUP_DIR}/manifest.json" 2>/dev/null | cut -d'"' -f4)
    if [ -n "$EXPECTED" ] && [ "$ACTUAL" = "$EXPECTED" ]; then
        log_ok "${FNAME} checksum OK"
    elif [ -z "$EXPECTED" ]; then
        log_warn "${FNAME} not in manifest"
    else
        log_err "${FNAME} checksum MISMATCH"
        ERRORS=$((ERRORS + 1))
    fi
done

# ── Step 2: Decrypt database dump ────────────────────────────────────────────
log_step 2 "Decrypt database dump"

DUMP_TMP=$(mktemp)
TEMP_FILES+=("$DUMP_TMP")

if decrypt_file "${BACKUP_DIR}/database.dump.enc" "$DUMP_TMP"; then
    DUMP_SIZE=$(du -h "$DUMP_TMP" | cut -f1)
    log_ok "Decryption successful (${DUMP_SIZE})"
else
    log_err "Failed to decrypt database.dump.enc"
    exit 1
fi

# ── Step 3: Restore to temporary database ────────────────────────────────────
log_step 3 "Restore to temporary database '${DRILL_DB}'"

# Drop drill DB if it somehow exists
docker exec "$CONTAINER" psql -U "$DB_USER" -d postgres -c \
    "DROP DATABASE IF EXISTS ${DRILL_DB};" 2>/dev/null || true

# Create drill database
docker exec "$CONTAINER" psql -U "$DB_USER" -d postgres -c \
    "CREATE DATABASE ${DRILL_DB} OWNER ${DB_USER};" 2>&1

# Copy dump into container and restore
docker cp "$DUMP_TMP" "${CONTAINER}:/tmp/drill-restore.dump"
docker exec -u root "$CONTAINER" chmod 644 /tmp/drill-restore.dump

# --exit-on-error: without it pg_restore reports errors and still exits 0, so a half-restored
# archive used to reach the PASS report. Its status is the drill's primary signal.
RESTORE_STATUS=0
RESTORE_OUTPUT=$(docker exec "$CONTAINER" pg_restore \
    --exit-on-error \
    -U "$DB_USER" -d "$DRILL_DB" --no-owner --no-acl \
    /tmp/drill-restore.dump 2>&1) || RESTORE_STATUS=$?

docker exec -u root "$CONTAINER" rm -f /tmp/drill-restore.dump
rm -f "$DUMP_TMP"

if [ "$RESTORE_STATUS" -ne 0 ]; then
    log_err "pg_restore failed (exit ${RESTORE_STATUS}) — the backup is not restorable"
    printf '%s\n' "$RESTORE_OUTPUT" >&2
    exit 1
fi
log_ok "Database restore completed"

# ── Step 4: Validate restored data ──────────────────────────────────────────
log_step 4 "Validate restored data"

# Table count
TABLE_COUNT=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DRILL_DB" -t -A -c \
    "SELECT COUNT(*) FROM pg_class WHERE relkind='r' AND relnamespace=(SELECT oid FROM pg_namespace WHERE nspname='public');")

if [ "$TABLE_COUNT" -gt 0 ]; then
    log_ok "Table count: ${TABLE_COUNT}"
else
    log_err "No tables found in restored database"
    ERRORS=$((ERRORS + 1))
fi

# Check key tables and row counts
KEY_TABLES=(
    "studies"
    "candidates"
    "study_participants"
    "devices"
    "chronicle_usage_events"
    "audit"
    "organizations"
)

echo ""
printf "  %-35s %s\n" "TABLE" "ROW COUNT"
printf "  %-35s %s\n" "-----" "---------"

for TABLE in "${KEY_TABLES[@]}"; do
    EXISTS=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DRILL_DB" -t -A -c \
        "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname='${TABLE}' AND relnamespace=(SELECT oid FROM pg_namespace WHERE nspname='public'));")
    if [ "$EXISTS" = "t" ]; then
        ROW_COUNT=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DRILL_DB" -t -A -c \
            "SELECT COUNT(*) FROM ${TABLE};" 2>/dev/null || echo "ERROR")
        printf "  %-35s %s\n" "$TABLE" "$ROW_COUNT"
        if [ "$ROW_COUNT" = "ERROR" ]; then
            log_err "${TABLE} exists but is not readable after restore"
            ERRORS=$((ERRORS + 1))
        fi
    else
        # A key table absent from the restore means the archive did not carry the schema
        # this drill is supposed to prove; that is a failure, not an informational line.
        printf "  %-35s %s\n" "$TABLE" "(MISSING)"
        log_err "${TABLE} missing from the restored database"
        ERRORS=$((ERRORS + 1))
    fi
done

echo ""

# Compare table count against manifest if available
if [ -f "${BACKUP_DIR}/manifest.json" ]; then
    MANIFEST_TABLE_COUNT=$(grep -o '"table_count"[[:space:]]*:[[:space:]]*[0-9]*' "${BACKUP_DIR}/manifest.json" | grep -o '[0-9]*$')
    if [ -n "$MANIFEST_TABLE_COUNT" ]; then
        if [ "$TABLE_COUNT" -eq "$MANIFEST_TABLE_COUNT" ]; then
            log_ok "Table count matches manifest (${TABLE_COUNT})"
        else
            # A skipped object is exactly the data loss this drill exists to catch.
            log_err "Table count mismatch: restored=${TABLE_COUNT}, manifest=${MANIFEST_TABLE_COUNT}"
            ERRORS=$((ERRORS + 1))
        fi
    fi
fi

# ── Step 5: Validate TDE keyring backup ──────────────────────────────────────
log_step 5 "Validate TDE keyring backup"

if [ -f "${BACKUP_DIR}/tde-keyring.tar.gz.enc" ]; then
    KEYRING_TMP=$(mktemp)
    TEMP_FILES+=("$KEYRING_TMP")
    if decrypt_file "${BACKUP_DIR}/tde-keyring.tar.gz.enc" "$KEYRING_TMP"; then
        if tar -tzf "$KEYRING_TMP" >/dev/null 2>&1; then
            FILE_COUNT=$(tar -tzf "$KEYRING_TMP" 2>/dev/null | wc -l)
            log_ok "TDE keyring decrypts and extracts OK (${FILE_COUNT} entries)"
        else
            log_err "TDE keyring decrypted but tar archive is invalid"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log_err "Failed to decrypt TDE keyring"
        ERRORS=$((ERRORS + 1))
    fi
    rm -f "$KEYRING_TMP"
else
    log_warn "No TDE keyring backup in this backup set"
fi

# ── Step 6: Drop drill database (cleanup runs via trap, but be explicit) ─────
log_step 6 "Cleanup"

docker exec "$CONTAINER" psql -U "$DB_USER" -d postgres -c \
    "DROP DATABASE IF EXISTS ${DRILL_DB};" 2>&1
log_ok "Drill database '${DRILL_DB}' dropped"

# ── Report ────────────────────────────────────────────────────────────────────
DRILL_END=$(date +%s)
DURATION=$((DRILL_END - DRILL_START))

echo ""
echo -e "${BOLD}=========================================="
echo "Restore Drill Results"
echo -e "==========================================${NC}"
echo ""
echo "  Backup:     $(basename "$BACKUP_DIR")"
echo "  Duration:   ${DURATION}s"
echo "  Tables:     ${TABLE_COUNT}"
echo "  Errors:     ${ERRORS}"
echo ""

# Write the drill result to the audit trail BEFORE exiting, so a failed drill is recorded
# as well as a passing one.
DRILL_LOG="/opt/chronicle/backups/drill-results.log"
mkdir -p "$(dirname "$DRILL_LOG")"
echo "$(date -Iseconds) | backup=$(basename "$BACKUP_DIR") | tables=${TABLE_COUNT} | errors=${ERRORS} | duration=${DURATION}s | result=$([ "$ERRORS" -eq 0 ] && echo PASS || echo FAIL)" >> "$DRILL_LOG"
log "Drill result appended to ${DRILL_LOG}"

if [ "$ERRORS" -ne 0 ]; then
    echo -e "  Result:     ${RED}${BOLD}FAIL${NC} (${ERRORS} errors)"
    echo ""
    echo "  Review the errors above and take corrective action."
    exit 1
fi
echo -e "  Result:     ${GREEN}${BOLD}PASS${NC}"
echo ""
echo "  The backup can be successfully decrypted, restored, and contains valid data."
