#!/bin/bash
# Chronicle PostgreSQL Encryption Verification Script
#
# Verifies that Transparent Data Encryption (TDE) is properly
# configured and all sensitive tables are encrypted.
#
# Usage: ./verify-encryption.sh [docker-compose-file]
#        Default: docker-compose.traefik.yml
#
# pg_tde version: 2.2 (Percona PostgreSQL 18.4)

set -euo pipefail

COMPOSE_FILE="${1:-docker-compose.traefik.yml}"
CONTAINER_NAME="chronicle-postgres"
DB_USER="${POSTGRES_USER:-chronicle}"
DB_NAME="${POSTGRES_DB:-chronicle}"

# Public application tables that MUST be encrypted. Populated dynamically so
# verification fails when schema migrations add unencrypted tables.
SENSITIVE_TABLES=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

echo "=========================================="
echo "Chronicle TDE Verification"
echo "=========================================="
echo ""

run_psql() {
    docker exec "$CONTAINER_NAME" bash -lc \
        "PGPASSWORD=\"\$POSTGRES_PASSWORD\" psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U \"\${POSTGRES_USER:-$DB_USER}\" -d \"\${POSTGRES_DB:-$DB_NAME}\" -t -A -c \"$1\""
}

discover_sensitive_tables() {
    SENSITIVE_TABLES=()
    local table_output
    table_output=$(run_psql "
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind = 'r'
        AND n.nspname = 'public'
        ORDER BY c.relname;
    ")
    while IFS= read -r TABLE; do
        if [ -n "$TABLE" ]; then
            SENSITIVE_TABLES+=("$TABLE")
        fi
    done <<< "$table_output"
}

print_status() {
    local check_name="$1"
    local status="$2"
    local details="$3"

    if [ "$status" = "PASS" ]; then
        echo -e "[${GREEN}PASS${NC}] $check_name"
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [ "$status" = "WARN" ]; then
        echo -e "[${YELLOW}WARN${NC}] $check_name"
        WARN_COUNT=$((WARN_COUNT + 1))
    else
        echo -e "[${RED}FAIL${NC}] $check_name"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    if [ -n "$details" ]; then
        echo "       $details"
    fi
}

# Check 1: Container is running
echo "1. Checking PostgreSQL container..."
if docker inspect "$CONTAINER_NAME" --format='{{.State.Running}}' 2>/dev/null | grep true >/dev/null; then
    print_status "PostgreSQL container is running" "PASS" ""
else
    print_status "PostgreSQL container is NOT running" "FAIL" ""
    echo ""
    echo "Start with: docker compose -p chronicle -f ${COMPOSE_FILE} up -d postgres"
    exit 1
fi
echo ""

# Check 2: shared_preload_libraries includes pg_tde
echo "2. Checking shared_preload_libraries..."
SPL=$(run_psql "SHOW shared_preload_libraries;")
if echo "$SPL" | grep "pg_tde" >/dev/null; then
    print_status "pg_tde in shared_preload_libraries" "PASS" "$SPL"
else
    print_status "pg_tde NOT in shared_preload_libraries" "FAIL" "Current: $SPL"
    echo ""
    echo "Add to docker-compose.traefik.yml postgres command:"
    echo "  -c shared_preload_libraries=pg_tde"
    exit 1
fi
echo ""

# Check 3: pg_tde extension is installed
echo "3. Checking pg_tde extension..."
EXT_EXISTS=$(run_psql "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_tde');")
if [ "$EXT_EXISTS" = "t" ]; then
    VERSION=$(run_psql "SELECT pg_tde_version();")
    print_status "pg_tde extension installed" "PASS" "Version: $VERSION"
else
    print_status "pg_tde extension NOT installed" "FAIL" ""
    echo "   Run: ./migrate-tde.sh"
    exit 1
fi
echo ""

# Check 4: Key provider is configured
echo "4. Checking key provider..."
PROVIDER_COUNT=$(run_psql "SELECT COUNT(*) FROM pg_tde_list_all_database_key_providers();")
if [ "$PROVIDER_COUNT" -gt 0 ]; then
    PROVIDER_NAME=$(run_psql "SELECT name FROM pg_tde_list_all_database_key_providers() LIMIT 1;")
    print_status "Key provider configured" "PASS" "Provider: $PROVIDER_NAME"
else
    print_status "No key provider configured" "FAIL" ""
    echo "   Run: ./migrate-tde.sh"
    exit 1
fi
echo ""

# Check 5: Test encrypted table creation
echo "5. Testing encrypted table creation..."
CREATE_OUTPUT=$(docker compose -p chronicle -f "${COMPOSE_FILE}" exec -T postgres \
    bash -lc "PGPASSWORD=\"\$POSTGRES_PASSWORD\" psql -h 127.0.0.1 -U \"\${POSTGRES_USER:-$DB_USER}\" -d \"\${POSTGRES_DB:-$DB_NAME}\" -c \"
        DROP TABLE IF EXISTS _encryption_test_table;
        CREATE TABLE _encryption_test_table (id SERIAL PRIMARY KEY, test_data TEXT) USING tde_heap;
        INSERT INTO _encryption_test_table (test_data) VALUES ('TDE test');
    \"" 2>&1)

if echo "$CREATE_OUTPUT" | grep "CREATE TABLE" >/dev/null; then
    print_status "Encrypted table creation works" "PASS" ""
else
    print_status "Failed to create encrypted table" "FAIL" "$CREATE_OUTPUT"
fi

# Verify and clean up test table
IS_ENCRYPTED=$(run_psql "SELECT pg_tde_is_encrypted('_encryption_test_table'::regclass);")
if [ "$IS_ENCRYPTED" = "t" ]; then
    print_status "Test table encryption verified" "PASS" ""
else
    print_status "Test table NOT encrypted" "FAIL" ""
fi
run_psql "DROP TABLE IF EXISTS _encryption_test_table;" >/dev/null 2>&1
echo ""

# Check 6: Keyring directory security
echo "6. Checking keyring directory security..."
KEYRING_PERMS=$(docker exec "$CONTAINER_NAME" stat -c "%a %U" /var/lib/postgresql/tde-keyring 2>/dev/null || echo "error")
if echo "$KEYRING_PERMS" | grep "^700 postgres" >/dev/null; then
    print_status "Keyring directory permissions (700, postgres)" "PASS" ""
elif echo "$KEYRING_PERMS" | grep "error" >/dev/null; then
    print_status "Cannot check keyring directory" "WARN" ""
else
    print_status "Keyring directory permissions" "WARN" "Got: $KEYRING_PERMS (expected: 700 postgres)"
fi
echo ""

# Check 7: Public application tables encryption status
echo "7. Checking public application tables encryption..."
echo ""
discover_sensitive_tables

if [ "${#SENSITIVE_TABLES[@]}" -eq 0 ]; then
    print_status "  public application tables" "FAIL" "no public tables found; table discovery failed or migrations have not run"
fi

for TABLE in "${SENSITIVE_TABLES[@]}"; do
    TABLE_EXISTS=$(run_psql "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = '$TABLE' AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public'));")
    if [ "$TABLE_EXISTS" != "t" ]; then
        print_status "  $TABLE" "WARN" "table does not exist"
        continue
    fi

    CURRENT_AM=$(run_psql "SELECT am.amname FROM pg_class c JOIN pg_am am ON c.relam = am.oid WHERE c.relname = '$TABLE' AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');")
    if [ "$CURRENT_AM" = "tde_heap" ]; then
        print_status "  $TABLE" "PASS" "tde_heap"
    else
        print_status "  $TABLE" "FAIL" "access method: $CURRENT_AM (expected: tde_heap)"
    fi
done

echo ""

# Summary
echo "=========================================="
echo "Verification Summary"
echo "=========================================="
echo ""
echo -e "  Passed: ${GREEN}${PASS_COUNT}${NC}"
echo -e "  Warnings: ${YELLOW}${WARN_COUNT}${NC}"
echo -e "  Failed: ${RED}${FAIL_COUNT}${NC}"
echo ""

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}All encryption checks passed!${NC}"
    echo ""
    echo "All tables:"
    docker exec "$CONTAINER_NAME" bash -lc \
        "PGPASSWORD=\"\$POSTGRES_PASSWORD\" psql -h 127.0.0.1 -U \"\${POSTGRES_USER:-$DB_USER}\" -d \"\${POSTGRES_DB:-$DB_NAME}\" -c \"
            SELECT c.relname AS table_name,
                   am.amname AS access_method,
                   CASE WHEN am.amname = 'tde_heap' THEN 'ENCRYPTED' ELSE 'standard' END AS status
            FROM pg_class c
            JOIN pg_am am ON c.relam = am.oid
            WHERE c.relkind = 'r'
            AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
            ORDER BY am.amname DESC, c.relname;
        \"" 2>/dev/null || echo "Could not list tables."
    echo ""
    exit 0
else
    echo -e "${RED}Some checks failed. Run ./migrate-tde.sh to fix.${NC}"
    exit 1
fi
