#!/bin/bash
# init-audit-immutability.sh
# PostgreSQL entrypoint init script: enables pgaudit, enforces audit log immutability,
# and prepares WAL archiving.
#
# This script runs automatically during container first-start via
# /docker-entrypoint-initdb.d/ as the postgres superuser.

set -euo pipefail

echo "=== Initializing audit immutability controls ==="

# Enable pgaudit extension and create trigger function
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-'EOSQL'
    CREATE EXTENSION IF NOT EXISTS pgaudit;

    CREATE OR REPLACE FUNCTION prevent_audit_modification()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'Audit records are immutable. DELETE and UPDATE operations are not permitted on audit tables (HIPAA §164.312(b))';
        RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;
EOSQL

# Validate POSTGRES_USER contains only safe identifier characters (alphanumeric + underscore)
if ! echo "$POSTGRES_USER" | grep -qE '^[a-zA-Z_][a-zA-Z0-9_]*$'; then
    echo "ERROR: POSTGRES_USER contains unsafe characters: $POSTGRES_USER" >&2
    exit 1
fi

# Apply triggers and revoke permissions from every runtime role. The bootstrap owner remains
# able to perform governed retention work, while neither request nor maintenance traffic may
# rewrite, delete, or truncate immutable audit history.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOSQL
    DO \$\$
    BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit') THEN
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger WHERE tgname = 'prevent_audit_modification_trigger'
                AND tgrelid = 'audit'::regclass
            ) THEN
                CREATE TRIGGER prevent_audit_modification_trigger
                    BEFORE DELETE OR UPDATE ON audit
                    FOR EACH ROW
                    EXECUTE FUNCTION prevent_audit_modification();
            END IF;
            REVOKE DELETE, UPDATE, TRUNCATE ON audit FROM chronicle_app, chronicle_admin;
        END IF;
    END \$\$;

    DO \$\$
    BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_buffer') THEN
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger WHERE tgname = 'prevent_audit_buffer_modification_trigger'
                AND tgrelid = 'audit_buffer'::regclass
            ) THEN
                CREATE TRIGGER prevent_audit_buffer_modification_trigger
                    BEFORE DELETE OR UPDATE ON audit_buffer
                    FOR EACH ROW
                    EXECUTE FUNCTION prevent_audit_modification();
            END IF;
            REVOKE DELETE, UPDATE, TRUNCATE ON audit_buffer FROM chronicle_app, chronicle_admin;
        END IF;
    END \$\$;
EOSQL

echo "=== Audit immutability controls initialized ==="
