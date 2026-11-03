#!/bin/bash
# Chronicle PostgreSQL Encryption Initialization Script
# This script sets up Transparent Data Encryption (TDE) using Percona's pg_tde extension
#
# Usage: This script runs automatically as a Docker entrypoint script
#        Place it in /docker-entrypoint-initdb.d/ to run on first container start
#
# Participant data at rest is encrypted.

set -euo pipefail

echo "=========================================="
echo "Chronicle PostgreSQL TDE Initialization"
echo "=========================================="

# Configuration from environment variables
PG_TDE_KEY_PROVIDER="${PG_TDE_KEY_PROVIDER:-file}"
PG_TDE_VAULT_URL="${PG_TDE_VAULT_URL:-}"
PG_TDE_VAULT_TOKEN="${PG_TDE_VAULT_TOKEN:-}"
# pg_tde reads the Vault token from a FILE (vault_token_path), never as a literal.
# The keyring volume is the only writable, non-world-readable path in this pod.
PG_TDE_VAULT_TOKEN_PATH="${PG_TDE_VAULT_TOKEN_PATH:-/var/lib/postgresql/tde-keyring/.vault-token}"
PG_TDE_VAULT_MOUNT_PATH="${PG_TDE_VAULT_MOUNT_PATH:-secret}"
PG_TDE_VAULT_CA_PATH="${PG_TDE_VAULT_CA_PATH:-}"
POSTGRES_DB="${POSTGRES_DB:-chronicle}"

# Key file location (for file-based provider only, used in development/testing)
# In production, use HashiCorp Vault or another KMS
PG_TDE_KEYRING_DIR="/var/lib/postgresql/tde-keyring"
PG_TDE_KEYRING_FILE="${PG_TDE_KEYRING_DIR}/chronicle-keyring.per"

echo "[INFO] TDE Key Provider: ${PG_TDE_KEY_PROVIDER}"

# Function to wait for PostgreSQL to be ready
wait_for_postgres() {
    echo "[INFO] Waiting for PostgreSQL to be ready..."
    until pg_isready -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB}"; do
        echo "[INFO] PostgreSQL is not ready yet. Waiting..."
        sleep 2
    done
    echo "[INFO] PostgreSQL is ready."
}

# Function to create pg_tde extension
create_extension() {
    echo "[INFO] Creating pg_tde extension in database: ${POSTGRES_DB}"
    psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB}" <<-EOSQL
        -- Check if extension already exists
        DO \$\$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_tde') THEN
                CREATE EXTENSION pg_tde;
                RAISE NOTICE 'pg_tde extension created successfully';
            ELSE
                RAISE NOTICE 'pg_tde extension already exists';
            END IF;
        END
        \$\$;
EOSQL
}

# Function to setup file-based key provider (for development/testing)
setup_file_key_provider() {
    echo "[INFO] Setting up file-based key provider (development mode)"
    echo "[WARNING] File-based key provider is for DEVELOPMENT/TESTING only!"
    echo "[WARNING] For production, configure HashiCorp Vault using PG_TDE_KEY_PROVIDER=vault"

    # Create keyring directory with secure permissions
    mkdir -p "${PG_TDE_KEYRING_DIR}"
    chmod 700 "${PG_TDE_KEYRING_DIR}"
    chown postgres:postgres "${PG_TDE_KEYRING_DIR}"

    psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB}" <<-EOSQL
        -- Add file-based key provider
        DO \$\$
        BEGIN
            -- Check if key provider already exists
            IF NOT EXISTS (
                SELECT 1 FROM pg_tde_list_all_database_key_providers()
                WHERE name = 'chronicle-file-vault'
            ) THEN
                PERFORM pg_tde_add_database_key_provider_file(
                    'chronicle-file-vault',
                    '${PG_TDE_KEYRING_FILE}'
                );
                RAISE NOTICE 'File key provider created';
            ELSE
                RAISE NOTICE 'Key provider already exists';
            END IF;
        END
        \$\$;

        -- Create and set the principal key if not exists
        DO \$\$
        DECLARE
            principal_exists boolean := false;
        BEGIN
            BEGIN
                PERFORM 1 FROM pg_tde_key_info()
                WHERE key_name = 'chronicle-principal-key';
                principal_exists := FOUND;
            EXCEPTION
                WHEN object_not_in_prerequisite_state THEN
                    -- pg_tde raises this before any principal key is set.
                    principal_exists := false;
            END;

            IF NOT principal_exists THEN
                PERFORM pg_tde_create_key_using_database_key_provider(
                    'chronicle-principal-key',
                    'chronicle-file-vault'
                );
                RAISE NOTICE 'Principal encryption key created';
            ELSE
                RAISE NOTICE 'Principal key already exists';
            END IF;

            PERFORM pg_tde_set_key_using_database_key_provider(
                'chronicle-principal-key',
                'chronicle-file-vault'
            );
            RAISE NOTICE 'Principal encryption key set';
        END
        \$\$;
EOSQL

    echo "[INFO] File-based key provider configured"
    echo "[INFO] Keyring file location: ${PG_TDE_KEYRING_FILE}"
}

# Function to setup HashiCorp Vault key provider (for production)
setup_vault_key_provider() {
    echo "[INFO] Setting up HashiCorp Vault key provider (production mode)"

    # Validate required environment variables
    if [ -z "${PG_TDE_VAULT_URL}" ]; then
        echo "[ERROR] PG_TDE_VAULT_URL is required for Vault key provider"
        exit 1
    fi

    # pg_tde's vault_v2 provider takes a token FILE PATH, not the token itself.
    # Materialise the token from the pod secret if a file was not mounted directly.
    if [ ! -s "${PG_TDE_VAULT_TOKEN_PATH}" ]; then
        if [ -z "${PG_TDE_VAULT_TOKEN}" ]; then
            echo "[ERROR] PG_TDE_VAULT_TOKEN or a nonempty PG_TDE_VAULT_TOKEN_PATH is required for Vault key provider"
            exit 1
        fi
        mkdir -p "$(dirname "${PG_TDE_VAULT_TOKEN_PATH}")"
        ( umask 077; printf '%s' "${PG_TDE_VAULT_TOKEN}" > "${PG_TDE_VAULT_TOKEN_PATH}" )
        chmod 600 "${PG_TDE_VAULT_TOKEN_PATH}"
    fi

    # Argument order is (provider_name, url, mount_path, token_path, ca_path) at every
    # pg_tde version (1.0 through 2.2). Passing the token third makes pg_tde open the
    # mount path as the token file: 'could not open file "secret" for "vault_token"'.
    psql -v ON_ERROR_STOP=1 \
        --username "${POSTGRES_USER:-postgres}" \
        --dbname "${POSTGRES_DB}" \
        -v vault_url="${PG_TDE_VAULT_URL}" \
        -v vault_token_path="${PG_TDE_VAULT_TOKEN_PATH}" \
        -v vault_mount_path="${PG_TDE_VAULT_MOUNT_PATH}" \
        -v vault_ca_path="${PG_TDE_VAULT_CA_PATH}" <<-EOSQL
        -- Add Vault key provider (psql variables are not expanded inside dollar-quoting,
        -- so generate the call as SQL to keep every argument safely quoted).
        SELECT format(
            'SELECT pg_tde_add_database_key_provider_vault_v2(%L, %L, %L, %L, %s)',
            'chronicle-vault', :'vault_url', :'vault_mount_path', :'vault_token_path',
            CASE WHEN :'vault_ca_path' = '' THEN 'NULL' ELSE quote_literal(:'vault_ca_path') END
        )
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_tde_list_all_database_key_providers()
            WHERE name = 'chronicle-vault'
        ) \gexec

        -- Create and set the principal key if not exists
        DO \$\$
        DECLARE
            principal_exists boolean := false;
        BEGIN
            BEGIN
                PERFORM 1 FROM pg_tde_key_info()
                WHERE key_name = 'chronicle-principal-key';
                principal_exists := FOUND;
            EXCEPTION
                WHEN object_not_in_prerequisite_state THEN
                    -- pg_tde raises this before any principal key is set.
                    principal_exists := false;
            END;

            IF NOT principal_exists THEN
                PERFORM pg_tde_create_key_using_database_key_provider(
                    'chronicle-principal-key',
                    'chronicle-vault'
                );
                RAISE NOTICE 'Principal encryption key created in Vault';
            ELSE
                RAISE NOTICE 'Principal key already exists in Vault';
            END IF;

            PERFORM pg_tde_set_key_using_database_key_provider(
                'chronicle-principal-key',
                'chronicle-vault'
            );
            RAISE NOTICE 'Principal encryption key set in Vault';
        END
        \$\$;
EOSQL

    echo "[INFO] HashiCorp Vault key provider configured"
    echo "[INFO] Vault URL: ${PG_TDE_VAULT_URL}"
}

# Function to verify encryption is working
verify_encryption() {
    echo "[INFO] Verifying TDE configuration..."

    psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB}" <<-EOSQL
        -- List key providers
        SELECT * FROM pg_tde_list_all_database_key_providers();

        -- List encryption keys
        SELECT * FROM pg_tde_key_info();

        -- Create a test encrypted table to verify TDE works
        CREATE TABLE IF NOT EXISTS _tde_verification_test (
            id SERIAL PRIMARY KEY,
            test_data TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        ) USING tde_heap;

        -- Insert test data
        INSERT INTO _tde_verification_test (test_data)
        VALUES ('TDE verification test - ' || NOW()::TEXT)
        ON CONFLICT DO NOTHING;

        -- Verify table is encrypted
        DO \$\$
        BEGIN
            IF NOT pg_tde_is_encrypted('_tde_verification_test'::regclass) THEN
                RAISE EXCEPTION 'TDE verification table is not encrypted';
            END IF;
        END
        \$\$;

        -- Clean up test table
        DROP TABLE IF EXISTS _tde_verification_test;
EOSQL

    echo "[INFO] TDE verification completed successfully"
}

# Function to enable encryption on existing tables (for migrations)
enable_encryption_on_table() {
    local table_name=$1
    echo "[INFO] Enabling encryption on table: ${table_name}"

    psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB}" <<-EOSQL
        ALTER TABLE public."${table_name}" SET ACCESS METHOD tde_heap;
EOSQL
}

# Main execution
echo "[INFO] Starting PostgreSQL TDE initialization..."

# Setup key provider based on configuration
case "${PG_TDE_KEY_PROVIDER}" in
    "file")
        create_extension
        setup_file_key_provider
        ;;
    "vault")
        create_extension
        setup_vault_key_provider
        ;;
    "none")
        echo "[WARNING] TDE is disabled. Set PG_TDE_KEY_PROVIDER=file or vault to enable."
        exit 0
        ;;
    *)
        echo "[ERROR] Unknown key provider: ${PG_TDE_KEY_PROVIDER}"
        echo "[ERROR] Valid options: file, vault, none"
        exit 1
        ;;
esac

# Verify encryption is working
verify_encryption

# Convert public application tables to tde_heap (idempotent).
# The table list is discovered at runtime to avoid stale hard-coded inventories.
echo "[INFO] Discovering and converting public application tables to tde_heap..."

mapfile -t SENSITIVE_TABLES < <(
    psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB}" -t -A -c \
        "SELECT c.relname
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relkind = 'r'
         AND n.nspname = 'public'
         ORDER BY c.relname;" | sed '/^$/d'
)

if [ "${#SENSITIVE_TABLES[@]}" -eq 0 ]; then
    echo "[INFO] No public application tables exist yet (run migrate-tde.sh after backend creates schema)"
fi

for TABLE in "${SENSITIVE_TABLES[@]}"; do
    # Only convert if table exists (it may not on first init before backend creates schema)
    TABLE_EXISTS=$(psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB}" -t -A -c \
        "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = '${TABLE}' AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public'));")
    if [ "$TABLE_EXISTS" = "t" ]; then
        CURRENT_AM=$(psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB}" -t -A -c \
            "SELECT am.amname FROM pg_class c JOIN pg_am am ON c.relam = am.oid WHERE c.relname = '${TABLE}';")
        if [ "$CURRENT_AM" != "tde_heap" ]; then
            enable_encryption_on_table "$TABLE"
            echo "[INFO] Converted $TABLE to tde_heap"
        else
            echo "[INFO] $TABLE already uses tde_heap"
        fi
    else
        echo "[INFO] $TABLE does not exist yet (will be encrypted by migrate-tde.sh after backend creates schema)"
    fi
done

echo "=========================================="
echo "PostgreSQL TDE Initialization Complete"
echo "=========================================="
echo ""
echo "To create encrypted tables, use:"
echo "  CREATE TABLE my_table (...) USING tde_heap;"
echo ""
echo "To encrypt existing tables, use:"
echo "  ALTER TABLE my_table SET ACCESS METHOD tde_heap;"
echo ""
echo "To verify a table is encrypted, use:"
echo "  SELECT pg_tde_is_encrypted('my_table'::regclass);"
echo ""
