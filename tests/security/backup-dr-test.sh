#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=docker/backup-format.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../docker/backup-format.sh"

# ---------------------------------------------------------------------------
# Backup & Disaster Recovery Tests for Chronicle
# ---------------------------------------------------------------------------
# Validates backup creation, integrity verification, tamper detection,
# encryption strength, TDE keyring backup, and optionally full restore.
#
# Usage:
#   ./backup-dr-test.sh [--full-dr]
#
# Options:
#   --full-dr   Run Test 4 (restore to temporary container). Requires extra
#               resources and a running PostgreSQL source container.
#
# Prerequisites:
#   - docker accessible
#   - /opt/chronicle/docker/backup-chronicle.sh present
#   - chronicle-postgres container running (for full tests)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKUP_SCRIPT="${PROJECT_ROOT}/docker/backup-chronicle.sh"
BACKUP_ROOT="/opt/chronicle/backups"
KEY_FILE="${CHRONICLE_BACKUP_KEY:-/etc/chronicle/backup-encryption-key}"
CONTAINER="chronicle-postgres"
DB_USER="chronicle"
DB_NAME="chronicle"
FULL_DR=false

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --full-dr) FULL_DR=true ;;
        -h|--help)
            echo "Usage: $0 [--full-dr]"
            echo "  --full-dr  Include restore-to-temporary-container test"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# -- Counters ---------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
WARN_COUNT=0

# -- Colors -----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# -- Helpers ----------------------------------------------------------------
log()  { printf "${CYAN}[INFO]${RESET}  %s\n" "$*"; }
pass() { ((PASS_COUNT++)) || true; printf "${GREEN}[PASS]${RESET}  %s\n" "$*"; }
fail() { ((FAIL_COUNT++)) || true; printf "${RED}[FAIL]${RESET}  %s\n" "$*"; }
skip() { ((SKIP_COUNT++)) || true; printf "${YELLOW}[SKIP]${RESET}  %s\n" "$*"; }
warn() { ((WARN_COUNT++)) || true; printf "${YELLOW}[WARN]${RESET}  %s\n" "$*"; }

section() {
    echo ""
    printf "${BOLD}=== %s ===${RESET}\n" "$*"
}

decrypt_backup_file() {
    local src="$1"
    local dst="$2"
    local key="$3"
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter "$BACKUP_PBKDF2_ITERATIONS" \
        -in "$src" -out "$dst" -pass "file:${key}" 2>/dev/null
}

# -- Temp cleanup -----------------------------------------------------------
TEMP_RESOURCES=()
cleanup() {
    for res in "${TEMP_RESOURCES[@]}"; do
        if [[ "$res" == container:* ]]; then
            local cname="${res#container:}"
            docker rm -f "$cname" >/dev/null 2>&1 || true
        else
            rm -rf "$res"
        fi
    done
}
trap cleanup EXIT

# -- Pre-flight checks -----------------------------------------------------
section "Pre-flight Checks"

if [ ! -f "$BACKUP_SCRIPT" ]; then
    fail "Backup script not found: $BACKUP_SCRIPT"
    echo "Cannot proceed without backup script."
    exit 1
fi
log "Backup script found: $BACKUP_SCRIPT"

if ! command -v docker &>/dev/null; then
    fail "docker command not available"
    echo "Cannot proceed without docker."
    exit 1
fi
log "docker is available"

POSTGRES_RUNNING=false
if docker inspect "$CONTAINER" --format='{{.State.Running}}' 2>/dev/null | grep -q true; then
    POSTGRES_RUNNING=true
    log "PostgreSQL container '$CONTAINER' is running"
else
    warn "PostgreSQL container '$CONTAINER' is not running -- some tests will be skipped"
fi

KEY_AVAILABLE=false
if [ -f "$KEY_FILE" ]; then
    KEY_AVAILABLE=true
    log "Encryption key found: $KEY_FILE"
else
    warn "Encryption key not found at $KEY_FILE -- some tests will be skipped"
fi

# ===========================================================================
# Test 1: Full Backup + Verify Cycle
# ===========================================================================
section "Test 1: Full Backup + Verify Cycle"

if [ "$POSTGRES_RUNNING" = false ] || [ "$KEY_AVAILABLE" = false ]; then
    skip "Test 1: prerequisites not met (container or key missing)"
else
    log "Running full backup..."
    if bash "$BACKUP_SCRIPT" --full >/dev/null 2>&1; then
        pass "Test 1a: Full backup completed successfully"
    else
        fail "Test 1a: Full backup failed (exit code $?)"
    fi

    log "Running verify on latest backup..."
    if bash "$BACKUP_SCRIPT" --verify >/dev/null 2>&1; then
        pass "Test 1b: Backup verification passed"
    else
        fail "Test 1b: Backup verification failed (exit code $?)"
    fi
fi

# ===========================================================================
# Test 2: Tampered Backup Detection
# ===========================================================================
section "Test 2: Tampered Backup Detection"

if [ "$POSTGRES_RUNNING" = false ] || [ "$KEY_AVAILABLE" = false ]; then
    skip "Test 2: prerequisites not met (container or key missing)"
else
    LATEST_BACKUP=$(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r | head -1)
    if [ -z "$LATEST_BACKUP" ]; then
        skip "Test 2: no backup found to tamper with"
    else
        TAMPER_DIR=$(mktemp -d)
        TEMP_RESOURCES+=("$TAMPER_DIR")

        # Copy the entire backup directory
        cp -r "$LATEST_BACKUP" "$TAMPER_DIR/tampered_backup"
        TAMPERED_BACKUP="$TAMPER_DIR/tampered_backup"

        # Tamper with the database dump: flip a byte near the middle
        TAMPER_TARGET="$TAMPERED_BACKUP/database.dump.enc"
        if [ -f "$TAMPER_TARGET" ]; then
            FILE_SIZE=$(stat -c%s "$TAMPER_TARGET")
            MIDPOINT=$((FILE_SIZE / 2))

            # Read the byte at midpoint, XOR with 0xFF to flip it
            python3 -c "
import sys
with open('$TAMPER_TARGET', 'r+b') as f:
    f.seek($MIDPOINT)
    b = f.read(1)
    f.seek($MIDPOINT)
    f.write(bytes([b[0] ^ 0xFF]))
" 2>/dev/null

            # Now try to verify the tampered backup.
            # The verify function checks the latest backup by directory sort,
            # so we need to test manually: checksum should mismatch.
            ACTUAL_HASH=$(sha256sum "$TAMPER_TARGET" | awk '{print $1}')
            EXPECTED_HASH=$(grep -o '"database.dump.enc":"[a-f0-9]*"' "$TAMPERED_BACKUP/manifest.json" 2>/dev/null | cut -d'"' -f4 || echo "")

            if [ -n "$EXPECTED_HASH" ] && [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
                pass "Test 2: Tampered file checksum differs from manifest (tamper detected)"
            elif [ -z "$EXPECTED_HASH" ]; then
                # Try decryption -- tampered data should fail to decrypt properly
                DECRYPT_TMP=$(mktemp)
                TEMP_RESOURCES+=("$DECRYPT_TMP")
                if decrypt_backup_file "$TAMPER_TARGET" "$DECRYPT_TMP" "$KEY_FILE"; then
                    # Decryption might succeed but produce garbage -- check with pg_restore
                    if docker cp "$DECRYPT_TMP" "${CONTAINER}:/tmp/tamper_verify.dump" 2>/dev/null && \
                       docker exec "$CONTAINER" pg_restore --list /tmp/tamper_verify.dump >/dev/null 2>&1; then
                        fail "Test 2: Tampered backup still passes validation (unlikely but possible)"
                    else
                        pass "Test 2: Tampered backup fails content validation"
                    fi
                    docker exec -u root "$CONTAINER" rm -f /tmp/tamper_verify.dump 2>/dev/null || true
                else
                    pass "Test 2: Tampered backup fails decryption"
                fi
            else
                fail "Test 2: Tampered file checksum still matches manifest"
            fi
        else
            skip "Test 2: database.dump.enc not found in backup"
        fi
    fi
fi

# ===========================================================================
# Test 3: Wrong Encryption Key
# ===========================================================================
section "Test 3: Wrong Encryption Key"

LATEST_BACKUP=$(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r | head -1)
if [ -z "$LATEST_BACKUP" ]; then
    skip "Test 3: no backup found"
elif [ ! -f "$LATEST_BACKUP/database.dump.enc" ]; then
    skip "Test 3: no database.dump.enc in latest backup"
else
    WRONG_KEY_FILE=$(mktemp)
    TEMP_RESOURCES+=("$WRONG_KEY_FILE")
    echo "this-is-a-completely-wrong-encryption-key-for-testing-purposes" > "$WRONG_KEY_FILE"

    DECRYPT_TMP=$(mktemp)
    TEMP_RESOURCES+=("$DECRYPT_TMP")

    if decrypt_backup_file "$LATEST_BACKUP/database.dump.enc" "$DECRYPT_TMP" "$WRONG_KEY_FILE"; then
        # OpenSSL may exit 0 but produce garbage -- validate content
        if [ -s "$DECRYPT_TMP" ] && file "$DECRYPT_TMP" 2>/dev/null | grep -qi "postgresql\|data\|archive"; then
            fail "Test 3: Decryption with wrong key produced valid-looking output"
        else
            pass "Test 3: Wrong key produces unreadable output (garbage data)"
        fi
    else
        pass "Test 3: Decryption with wrong key failed as expected"
    fi
fi

# ===========================================================================
# Test 4: Restore to Temporary Container (optional, --full-dr)
# ===========================================================================
section "Test 4: Restore to Temporary Container"

if [ "$FULL_DR" = false ]; then
    skip "Test 4: skipped (run with --full-dr to enable)"
elif [ "$POSTGRES_RUNNING" = false ]; then
    skip "Test 4: source PostgreSQL container not running"
elif [ "$KEY_AVAILABLE" = false ]; then
    skip "Test 4: encryption key not available"
else
    LATEST_BACKUP=$(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r | head -1)
    if [ -z "$LATEST_BACKUP" ] || [ ! -f "$LATEST_BACKUP/database.dump.enc" ]; then
        skip "Test 4: no valid backup found"
    else
        DR_CONTAINER="chronicle-dr-test-$$"
        TEMP_RESOURCES+=("container:$DR_CONTAINER")
        DR_PORT=45432

        log "Starting temporary PostgreSQL container: $DR_CONTAINER"

        # Detect the postgres image used by the source container
        PG_IMAGE=$(docker inspect "$CONTAINER" --format='{{.Config.Image}}' 2>/dev/null || echo "postgres:18")

        docker run -d \
            --name "$DR_CONTAINER" \
            -e POSTGRES_USER="$DB_USER" \
            -e POSTGRES_PASSWORD="dr-test-password" \
            -e POSTGRES_DB="$DB_NAME" \
            -p "${DR_PORT}:5432" \
            "$PG_IMAGE" >/dev/null 2>&1

        # Wait for the temporary container to be ready
        log "Waiting for temporary container to accept connections..."
        READY=false
        for _ in {1..30}; do
            if docker exec "$DR_CONTAINER" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
                READY=true
                break
            fi
            sleep 1
        done

        if [ "$READY" = false ]; then
            fail "Test 4a: Temporary PostgreSQL container did not become ready"
        else
            log "Temporary container ready. Decrypting and restoring backup..."

            # Decrypt the backup
            RESTORE_TMP=$(mktemp)
            TEMP_RESOURCES+=("$RESTORE_TMP")

            if decrypt_backup_file "$LATEST_BACKUP/database.dump.enc" "$RESTORE_TMP" "$KEY_FILE"; then

                # Copy dump into the DR container and restore
                docker cp "$RESTORE_TMP" "${DR_CONTAINER}:/tmp/restore.dump" 2>/dev/null
                docker exec -u root "$DR_CONTAINER" chmod 644 /tmp/restore.dump 2>/dev/null

                if docker exec "$DR_CONTAINER" pg_restore -U "$DB_USER" -d "$DB_NAME" \
                    --no-owner --no-privileges --clean --if-exists \
                    /tmp/restore.dump >/dev/null 2>&1; then
                    pass "Test 4a: Backup restored successfully to temporary container"
                else
                    # pg_restore may return non-zero for warnings; check if tables exist
                    TABLE_COUNT=$(docker exec "$DR_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -A \
                        -c "SELECT COUNT(*) FROM pg_class WHERE relkind='r' AND relnamespace=(SELECT oid FROM pg_namespace WHERE nspname='public');" 2>/dev/null || echo "0")
                    if [ "$TABLE_COUNT" -gt 0 ]; then
                        pass "Test 4a: Backup restored with warnings ($TABLE_COUNT tables created)"
                    else
                        fail "Test 4a: Backup restore failed -- no tables created"
                    fi
                fi

                # Compare row counts between source and restored databases
                log "Comparing row counts between source and restored databases..."

                # Get table names from the restored database
                TABLES=$(docker exec "$DR_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -A \
                    -c "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;" 2>/dev/null || echo "")

                if [ -z "$TABLES" ]; then
                    fail "Test 4b: No tables found in restored database"
                else
                    MISMATCH=0
                    COMPARED=0
                    while IFS= read -r table; do
                        [ -z "$table" ] && continue

                        SOURCE_COUNT=$(docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -A \
                            -c "SELECT COUNT(*) FROM \"$table\";" 2>/dev/null || echo "error")
                        RESTORED_COUNT=$(docker exec "$DR_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -t -A \
                            -c "SELECT COUNT(*) FROM \"$table\";" 2>/dev/null || echo "error")

                        if [ "$SOURCE_COUNT" = "error" ] || [ "$RESTORED_COUNT" = "error" ]; then
                            continue
                        fi

                        ((COMPARED++)) || true
                        if [ "$SOURCE_COUNT" != "$RESTORED_COUNT" ]; then
                            log "  Row count mismatch: $table (source=$SOURCE_COUNT, restored=$RESTORED_COUNT)"
                            ((MISMATCH++)) || true
                        fi
                    done <<< "$TABLES"

                    if [ "$COMPARED" -eq 0 ]; then
                        fail "Test 4b: Could not compare any tables"
                    elif [ "$MISMATCH" -eq 0 ]; then
                        pass "Test 4b: Row counts match across $COMPARED tables"
                    else
                        fail "Test 4b: Row count mismatches in $MISMATCH of $COMPARED tables"
                    fi
                fi

                docker exec -u root "$DR_CONTAINER" rm -f /tmp/restore.dump 2>/dev/null || true
            else
                fail "Test 4a: Could not decrypt backup for restore"
            fi
        fi

        # Cleanup happens via trap, but remove container early to free port
        docker rm -f "$DR_CONTAINER" >/dev/null 2>&1 || true
    fi
fi

# ===========================================================================
# Test 5: TDE Keyring Backup Check
# ===========================================================================
section "Test 5: TDE Keyring Backup Check"

LATEST_BACKUP=$(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r | head -1)
if [ -z "$LATEST_BACKUP" ]; then
    skip "Test 5: no backup found"
else
    if [ -f "$LATEST_BACKUP/tde-keyring.tar.gz.enc" ]; then
        # Verify the keyring archive is non-trivial (not empty)
        KEYRING_SIZE=$(stat -c%s "$LATEST_BACKUP/tde-keyring.tar.gz.enc" 2>/dev/null || echo "0")
        if [ "$KEYRING_SIZE" -gt 100 ]; then
            pass "Test 5a: TDE keyring backup present (${KEYRING_SIZE} bytes)"
        else
            warn "Test 5a: TDE keyring backup file is suspiciously small (${KEYRING_SIZE} bytes)"
        fi

        # If we have the key, validate the archive contents
        if [ "$KEY_AVAILABLE" = true ]; then
            KEYRING_TMP=$(mktemp)
            TEMP_RESOURCES+=("$KEYRING_TMP")
            if decrypt_backup_file "$LATEST_BACKUP/tde-keyring.tar.gz.enc" "$KEYRING_TMP" "$KEY_FILE"; then
                ENTRY_COUNT=$(tar -tzf "$KEYRING_TMP" 2>/dev/null | wc -l)
                if [ "$ENTRY_COUNT" -gt 0 ]; then
                    pass "Test 5b: TDE keyring archive valid ($ENTRY_COUNT entries)"
                else
                    fail "Test 5b: TDE keyring archive is empty"
                fi
            else
                fail "Test 5b: TDE keyring archive failed to decrypt"
            fi
        else
            skip "Test 5b: cannot validate keyring contents without encryption key"
        fi
    else
        fail "Test 5a: TDE keyring backup NOT found in latest backup"
        warn "Test 5: Without TDE keyring, encrypted database data is UNRECOVERABLE"
    fi
fi

# ===========================================================================
# Test 6: Backup Recency
# ===========================================================================
section "Test 6: Backup Recency"

LATEST_BACKUP=$(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r | head -1)
if [ -z "$LATEST_BACKUP" ]; then
    skip "Test 6: no backups found"
else
    BACKUP_NAME=$(basename "$LATEST_BACKUP")

    # Extract timestamp from directory name (format: YYYYMMDD_HHMMSS)
    if [[ "$BACKUP_NAME" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})_([0-9]{2})([0-9]{2})([0-9]{2})$ ]]; then
        BACKUP_TS=$(date -d "${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}" +%s 2>/dev/null || echo "0")
    else
        # Fallback: use directory modification time
        BACKUP_TS=$(stat -c%Y "$LATEST_BACKUP" 2>/dev/null || echo "0")
    fi

    NOW_TS=$(date +%s)
    AGE_HOURS=$(( (NOW_TS - BACKUP_TS) / 3600 ))

    if [ "$AGE_HOURS" -le 48 ]; then
        pass "Test 6: Most recent backup is ${AGE_HOURS} hours old (within 48h threshold)"
    else
        AGE_DAYS=$(( AGE_HOURS / 24 ))
        warn "Test 6: Most recent backup is ${AGE_DAYS} days old (${AGE_HOURS}h) -- exceeds 48h threshold"
    fi
fi

# ===========================================================================
# Test 7: Backup Encryption Strength
# ===========================================================================
section "Test 7: Backup Encryption Strength"

if [ "$KEY_AVAILABLE" = false ]; then
    skip "Test 7: encryption key file not found"
else
    # Check file permissions
    KEY_PERMS=$(stat -c%a "$KEY_FILE" 2>/dev/null || echo "unknown")
    if [ "$KEY_PERMS" = "600" ] || [ "$KEY_PERMS" = "400" ]; then
        pass "Test 7a: Encryption key file permissions are restrictive ($KEY_PERMS)"
    else
        fail "Test 7a: Encryption key file permissions too open ($KEY_PERMS) -- should be 600 or 400"
    fi

    # Check key length
    KEY_LENGTH=$(wc -c < "$KEY_FILE" 2>/dev/null | tr -d ' ')
    if [ "$KEY_LENGTH" -ge 32 ]; then
        pass "Test 7b: Encryption key length is sufficient (${KEY_LENGTH} chars)"
    else
        fail "Test 7b: Encryption key too short (${KEY_LENGTH} chars) -- minimum 32 recommended"
    fi

    # Check key is not stored inside the backup directory
    KEY_REALPATH=$(realpath "$KEY_FILE" 2>/dev/null || echo "$KEY_FILE")
    BACKUP_REALPATH=$(realpath "$BACKUP_ROOT" 2>/dev/null || echo "$BACKUP_ROOT")
    if [[ "$KEY_REALPATH" == "$BACKUP_REALPATH"* ]]; then
        warn "Test 7c: Encryption key is stored inside backup directory -- should be stored separately"
    else
        pass "Test 7c: Encryption key stored outside backup directory"
    fi
fi

# ===========================================================================
# Test 8: Production Recoverability Artifact Set
# ===========================================================================
section "Test 8: Production Recoverability Artifact Set"

LATEST_BACKUP=$(ls -d "${BACKUP_ROOT}"/[0-9]*_[0-9]* 2>/dev/null | sort -r | head -1)
if [ -z "$LATEST_BACKUP" ]; then
    skip "Test 8: no backups found"
elif [ ! -f "$LATEST_BACKUP/manifest.json" ]; then
    fail "Test 8a: manifest.json missing"
else
    REQUIRED_ARTIFACTS=(
        "database.dump.enc"
        "tde-keyring.tar.gz.enc"
        "config-secrets.tar.gz.enc"
        "deployment-manifest.tar.gz.enc"
        "audit-logs.tar.gz.enc"
    )

    MISSING=0
    for artifact in "${REQUIRED_ARTIFACTS[@]}"; do
        if [ ! -f "$LATEST_BACKUP/$artifact" ]; then
            fail "Test 8a: required artifact missing: $artifact"
            MISSING=$((MISSING + 1))
            continue
        fi
        if ! grep -q "\"$artifact\"" "$LATEST_BACKUP/manifest.json"; then
            fail "Test 8a: required artifact not declared in manifest: $artifact"
            MISSING=$((MISSING + 1))
        fi
    done
    if [ "$MISSING" -eq 0 ]; then
        pass "Test 8a: required production recovery artifacts are present and declared"
    fi

    if [ "$KEY_AVAILABLE" = false ]; then
        skip "Test 8b: cannot decrypt artifact bundles without encryption key"
    else
        CONFIG_TMP=$(mktemp); TEMP_RESOURCES+=("$CONFIG_TMP")
        if [ -f "$LATEST_BACKUP/config-secrets.tar.gz.enc" ] && \
           decrypt_backup_file "$LATEST_BACKUP/config-secrets.tar.gz.enc" "$CONFIG_TMP" "$KEY_FILE" && \
           tar -tzf "$CONFIG_TMP" 2>/dev/null | grep -E '(^|/)\.env.production.local$|(^|/)\.env$' >/dev/null; then
            pass "Test 8b: config/secrets bundle decrypts and includes env config"
        else
            fail "Test 8b: config/secrets bundle missing, invalid, or lacks env config"
        fi

        DEPLOY_TMP=$(mktemp); TEMP_RESOURCES+=("$DEPLOY_TMP")
        if [ -f "$LATEST_BACKUP/deployment-manifest.tar.gz.enc" ] && \
           decrypt_backup_file "$LATEST_BACKUP/deployment-manifest.tar.gz.enc" "$DEPLOY_TMP" "$KEY_FILE" && \
           tar -tzf "$DEPLOY_TMP" 2>/dev/null | grep 'deployment/deployment-manifest.json' >/dev/null; then
            pass "Test 8c: deployment manifest bundle decrypts and includes deployment manifest"
        else
            fail "Test 8c: deployment manifest bundle missing or invalid"
        fi

        AUDIT_TMP=$(mktemp); TEMP_RESOURCES+=("$AUDIT_TMP")
        if [ -f "$LATEST_BACKUP/audit-logs.tar.gz.enc" ] && \
           decrypt_backup_file "$LATEST_BACKUP/audit-logs.tar.gz.enc" "$AUDIT_TMP" "$KEY_FILE" && \
           tar -tzf "$AUDIT_TMP" 2>/dev/null | grep '^chronicle' >/dev/null; then
            pass "Test 8d: audit log bundle decrypts and includes chronicle log tree"
        else
            fail "Test 8d: audit log bundle missing or invalid"
        fi
    fi
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
printf "${BOLD}=============================${RESET}\n"
printf "${BOLD}  Backup DR Test Summary${RESET}\n"
printf "${BOLD}=============================${RESET}\n"
printf "${GREEN}  PASS: %d${RESET}\n" "$PASS_COUNT"
printf "${RED}  FAIL: %d${RESET}\n" "$FAIL_COUNT"
printf "${YELLOW}  WARN: %d${RESET}\n" "$WARN_COUNT"
printf "${YELLOW}  SKIP: %d${RESET}\n" "$SKIP_COUNT"
TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))
printf "  TOTAL: %d\n" "$TOTAL"
printf "${BOLD}=============================${RESET}\n"

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf "${RED}RESULT: FAILED${RESET}\n"
    exit 1
elif [ "$WARN_COUNT" -gt 0 ]; then
    printf "${YELLOW}RESULT: PASSED WITH WARNINGS${RESET}\n"
    exit 0
else
    printf "${GREEN}RESULT: PASSED${RESET}\n"
    exit 0
fi
