#!/bin/bash
# Chronicle TDE Migration Script
# Idempotent script to enable Transparent Data Encryption on sensitive tables.
#
# Usage: ./migrate-tde.sh
# Runs via docker exec against the running chronicle-postgres container.
#
# Prerequisites:
#   - chronicle-postgres container running
#   - shared_preload_libraries includes pg_tde (set in docker-compose.traefik.yml)
#
# pg_tde version: 2.2 (Percona PostgreSQL 18.4)

set -euo pipefail

CONTAINER="chronicle-postgres"
DB_USER="chronicle"
DB_NAME="chronicle"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

KEYRING_DIR="/var/lib/postgresql/tde-keyring"
KEYRING_FILE="${KEYRING_DIR}/chronicle-keyring.per"
CONFIGURED_PROVIDER=""
EXPECTED_PROVIDER="${CHRONICLE_TDE_EXPECTED_PROVIDER:-}"
PROVIDER_NAME="${CHRONICLE_TDE_EXPECTED_PROVIDER_NAME:-}"
KEY_NAME="${CHRONICLE_TDE_EXPECTED_KEY_NAME:-chronicle-principal-key}"

# Public application tables to encrypt. Populated dynamically after pg_tde is ready
# so the inventory cannot drift when schema migrations add tables.
SENSITIVE_TABLES=()

run_psql() {
    docker exec "$CONTAINER" bash -lc \
        "PGPASSWORD=\"\$POSTGRES_PASSWORD\" psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U \"\${POSTGRES_USER:-$DB_USER}\" -d \"\${POSTGRES_DB:-$DB_NAME}\" -t -A -c \"$1\""
}

run_psql_verbose() {
    docker exec "$CONTAINER" bash -lc \
        "PGPASSWORD=\"\$POSTGRES_PASSWORD\" psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U \"\${POSTGRES_USER:-$DB_USER}\" -d \"\${POSTGRES_DB:-$DB_NAME}\" -c \"$1\"" \
        2>&1
}

configure_vault_provider() {
    docker exec "$CONTAINER" bash -euc '
        export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is unavailable}"
        : "${PG_TDE_VAULT_URL:?PG_TDE_VAULT_URL is required}"
        : "${PG_TDE_VAULT_MOUNT_PATH:?PG_TDE_VAULT_MOUNT_PATH is required}"
        token_path="${PG_TDE_VAULT_TOKEN_PATH:-/var/lib/postgresql/ssl-run/pg-tde-vault-token}"
        test -s "$token_path"
        case "$PG_TDE_VAULT_URL" in
            https://*) ;;
            *) test "${PG_TDE_ALLOW_INSECURE_VAULT:-false}" = true ;;
        esac
        psql -X -v ON_ERROR_STOP=1 -q \
          -h 127.0.0.1 \
          -U "${POSTGRES_USER:-chronicle}" \
          -d "${POSTGRES_DB:-chronicle}" \
          -v provider_name="$1" \
          -v vault_url="$PG_TDE_VAULT_URL" \
          -v vault_mount="$PG_TDE_VAULT_MOUNT_PATH" \
          -v token_path="$token_path" \
          -v ca_path="${PG_TDE_VAULT_CA_PATH:-}" <<'\''EOSQL'\''
SELECT EXISTS (
    SELECT 1 FROM pg_tde_list_all_database_key_providers()
    WHERE name = :'\''provider_name'\''
) AS provider_exists \gset
\if :provider_exists
SELECT format(
    '\''SELECT pg_tde_change_database_key_provider_vault_v2(%L, %L, %L, %L, %s)'\'',
    :'\''provider_name'\'', :'\''vault_url'\'', :'\''vault_mount'\'', :'\''token_path'\'',
    CASE WHEN :'\''ca_path'\'' = '\'''\'' THEN '\''NULL'\'' ELSE quote_literal(:'\''ca_path'\'') END
) \gexec
\else
SELECT format(
    '\''SELECT pg_tde_add_database_key_provider_vault_v2(%L, %L, %L, %L, %s)'\'',
    :'\''provider_name'\'', :'\''vault_url'\'', :'\''vault_mount'\'', :'\''token_path'\'',
    CASE WHEN :'\''ca_path'\'' = '\'''\'' THEN '\''NULL'\'' ELSE quote_literal(:'\''ca_path'\'') END
) \gexec
\endif
EOSQL
    ' chronicle-vault-provider "$PROVIDER_NAME"
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

echo "=========================================="
echo "Chronicle TDE Migration"
echo "=========================================="
echo ""

# Step 1: Verify container is running
echo "1. Checking container..."
if ! docker inspect "$CONTAINER" --format='{{.State.Running}}' 2>/dev/null | grep true >/dev/null; then
    echo -e "${RED}ABORT: Container $CONTAINER is not running${NC}"
    exit 1
fi
echo -e "   ${GREEN}Container is running${NC}"
echo ""

CONFIGURED_PROVIDER=$(docker exec "$CONTAINER" sh -euc \
    'printf "%s\n" "${PG_TDE_KEY_PROVIDER:?PG_TDE_KEY_PROVIDER is unavailable}"')
[ -n "$EXPECTED_PROVIDER" ] || EXPECTED_PROVIDER="$CONFIGURED_PROVIDER"
case "$EXPECTED_PROVIDER" in
    file) DEFAULT_PROVIDER_NAME=chronicle-file-vault ;;
    vault) DEFAULT_PROVIDER_NAME=chronicle-vault ;;
    *)
        echo "Unsupported TDE key provider: ${EXPECTED_PROVIDER:-unset}" >&2
        exit 1
        ;;
esac
if [ "$CONFIGURED_PROVIDER" != "$EXPECTED_PROVIDER" ]; then
    echo "Configured TDE provider '${CONFIGURED_PROVIDER}' does not match expected '${EXPECTED_PROVIDER}'" >&2
    exit 1
fi
[ -n "$PROVIDER_NAME" ] || PROVIDER_NAME="$DEFAULT_PROVIDER_NAME"
if [[ ! "$PROVIDER_NAME" =~ ^[A-Za-z0-9._-]+$ ]] \
    || [[ ! "$KEY_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "TDE provider/key names must contain only letters, digits, dot, underscore, or dash" >&2
    exit 1
fi

# Step 2: Verify pg_tde is in shared_preload_libraries
echo "2. Checking shared_preload_libraries..."
SPL=$(run_psql "SHOW shared_preload_libraries;")
if ! echo "$SPL" | grep "pg_tde" >/dev/null; then
    echo -e "${RED}ABORT: pg_tde is NOT in shared_preload_libraries${NC}"
    echo "   Current value: $SPL"
    echo "   Add to docker-compose.traefik.yml postgres command:"
    echo "     -c shared_preload_libraries=pg_tde"
    exit 1
fi
echo -e "   ${GREEN}pg_tde is loaded: $SPL${NC}"
echo ""

# Step 3: Create extension if needed
echo "3. Creating pg_tde extension..."
EXT_EXISTS=$(run_psql "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_tde');")
if [ "$EXT_EXISTS" = "t" ]; then
    echo -e "   ${GREEN}pg_tde extension already exists${NC}"
else
    run_psql_verbose "CREATE EXTENSION pg_tde;"
    echo -e "   ${GREEN}pg_tde extension created${NC}"
fi
# A cluster restored from a 17-era dump carries pg_tde 1.0 and the branch above sees it as
# "already exists", so it would stay on 1.0. Percona 18.4-5 defaults to 2.2. Idempotent.
run_psql_verbose "ALTER EXTENSION pg_tde UPDATE;"
EXT_VER=$(run_psql "SELECT extversion FROM pg_extension WHERE extname = 'pg_tde';")
echo -e "   ${GREEN}pg_tde extension version: ${EXT_VER}${NC}"
echo ""

# Step 4: Prepare provider-specific local state
echo "4. Preparing ${EXPECTED_PROVIDER} provider state..."
if [ "$EXPECTED_PROVIDER" = file ]; then
    docker exec -u root "$CONTAINER" sh -euc \
        'mkdir -p "$1"; chown postgres:postgres "$1"; chmod 700 "$1"' \
        chronicle-keyring-dir "$KEYRING_DIR" 2>&1
    echo -e "   ${GREEN}File keyring directory ready${NC}"
else
    echo -e "   ${GREEN}Vault provider uses external key custody${NC}"
fi
echo ""

# Step 5: Configure the exact provider declared by the recovery contract
echo "5. Configuring key provider..."
PROVIDER_EXISTS=$(run_psql "SELECT COUNT(*) FROM pg_tde_list_all_database_key_providers() WHERE name = '${PROVIDER_NAME}';")
if [ "$EXPECTED_PROVIDER" = file ]; then
    if [ "$PROVIDER_EXISTS" -gt 0 ]; then
        run_psql_verbose "SELECT pg_tde_change_database_key_provider_file('${PROVIDER_NAME}', '${KEYRING_FILE}');" >/dev/null
    else
        run_psql_verbose "SELECT pg_tde_add_database_key_provider_file('${PROVIDER_NAME}', '${KEYRING_FILE}');" >/dev/null
    fi
else
    configure_vault_provider
fi
EXPECTED_PROVIDER_TYPE="file"
[ "$EXPECTED_PROVIDER" = vault ] && EXPECTED_PROVIDER_TYPE="vault-v2"
ACTUAL_PROVIDER_TYPE=$(run_psql "SELECT type FROM pg_tde_list_all_database_key_providers() WHERE name = '${PROVIDER_NAME}';")
if [ "$ACTUAL_PROVIDER_TYPE" != "$EXPECTED_PROVIDER_TYPE" ]; then
    echo -e "   ${RED}Configured provider type '${ACTUAL_PROVIDER_TYPE:-missing}' does not match '${EXPECTED_PROVIDER_TYPE}'${NC}"
    exit 1
fi
echo -e "   ${GREEN}Key provider '${PROVIDER_NAME}' configured as ${ACTUAL_PROVIDER_TYPE}${NC}"
echo ""

# Step 6: Create and set principal key if not exists
# pg_tde 2.x: try to create key; if it already exists, just ensure it's set
echo "6. Setting principal key..."
# Idempotent by construction: a key can exist in the keyring without
# pg_tde_key_info() listing it as the active principal, so the old
# COUNT(*)-based existence check produced a false negative, fell through to
# create, and `set -e` aborted on "already exists" BEFORE any table was
# encrypted. Instead: attempt the create, treat "already exists" as success,
# fail only on a genuine error, then always (re)assert the principal key —
# pg_tde_set_key is idempotent.
if CREATE_OUT=$(run_psql_verbose "SELECT pg_tde_create_key_using_database_key_provider('${KEY_NAME}', '${PROVIDER_NAME}');"); then
    echo -e "   ${GREEN}Principal key created${NC}"
elif echo "$CREATE_OUT" | grep -i "already exists" >/dev/null; then
    echo -e "   ${GREEN}Principal key '${KEY_NAME}' already exists${NC}"
else
    echo -e "   ${RED}Failed to create principal key:${NC}"
    echo "$CREATE_OUT"
    exit 1
fi
run_psql_verbose "SELECT pg_tde_set_key_using_database_key_provider('${KEY_NAME}', '${PROVIDER_NAME}');" >/dev/null
KEY_STATE=$(run_psql "SELECT key_name || '|' || provider_name FROM pg_tde_key_info();")
if [ "$KEY_STATE" != "${KEY_NAME}|${PROVIDER_NAME}" ]; then
    echo -e "   ${RED}Active principal key/provider does not match the recovery contract${NC}"
    exit 1
fi
run_psql_verbose "SELECT pg_tde_verify_key();" >/dev/null
echo -e "   ${GREEN}Principal key set${NC}"
echo ""

# Step 7: Convert public application tables to tde_heap
echo "7. Discovering and converting public application tables to tde_heap..."
echo ""
discover_sensitive_tables
if [ "${#SENSITIVE_TABLES[@]}" -eq 0 ]; then
    echo -e "   ${RED}ABORT${NC} No public application tables found; table discovery failed or migrations have not run"
    exit 1
fi

CONVERTED=0
SKIPPED=0
FAILED=0

for TABLE in "${SENSITIVE_TABLES[@]}"; do
    # Check if table exists
    TABLE_EXISTS=$(run_psql "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = '$TABLE' AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public'));")
    if [ "$TABLE_EXISTS" != "t" ]; then
        echo -e "   ${YELLOW}SKIP${NC} $TABLE (table does not exist)"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # Check current access method
    CURRENT_AM=$(run_psql "SELECT am.amname FROM pg_class c JOIN pg_am am ON c.relam = am.oid WHERE c.relname = '$TABLE' AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');")
    if [ "$CURRENT_AM" = "tde_heap" ]; then
        echo -e "   ${GREEN}OK${NC}   $TABLE (already tde_heap)"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # Convert table
    OUTPUT=$(run_psql_verbose "ALTER TABLE public.\"$TABLE\" SET ACCESS METHOD tde_heap;" 2>&1)
    if echo "$OUTPUT" | grep "ALTER TABLE" >/dev/null; then
        echo -e "   ${GREEN}DONE${NC} $TABLE (heap -> tde_heap)"
        CONVERTED=$((CONVERTED + 1))
    else
        echo -e "   ${RED}FAIL${NC} $TABLE: $OUTPUT"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "   Converted: $CONVERTED | Skipped: $SKIPPED | Failed: $FAILED"
echo ""

# Step 8: Verification summary
echo "8. Verification summary:"
echo ""
echo "   Public application table encryption status:"
run_psql_verbose "
SELECT c.relname AS table_name,
       am.amname AS access_method,
       CASE WHEN am.amname = 'tde_heap' THEN 'ENCRYPTED' ELSE 'NOT ENCRYPTED' END AS status
FROM pg_class c
JOIN pg_am am ON c.relam = am.oid
WHERE c.relkind = 'r'
AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
ORDER BY c.relname;
"

echo ""
echo "=========================================="
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}TDE Migration Complete${NC}"
else
    echo -e "${RED}TDE Migration completed with $FAILED failures${NC}"
    exit 1
fi
echo "=========================================="
