-- Generated from docker/init-db-roles.sql; do not edit.
-- =============================================================================
-- Chronicle Database Role Initialization Script
-- =============================================================================
-- This script creates the database roles required for Row-Level Security (RLS).
--
-- Roles:
--   chronicle_app   - Application user with RLS enforced
--   chronicle_admin - Admin user that bypasses RLS for maintenance
--
-- Usage:
--   1. Run this script as the PostgreSQL superuser (postgres)
--   2. Configure your application to use chronicle_app for normal operations
--   3. Run Flyway as the offline schema owner (POSTGRES_USER in selfhost)
--   4. Use chronicle_admin only for bounded maintenance and diagnostics
--
-- Security:
--   - chronicle_app has RLS enforced (FORCE ROW LEVEL SECURITY)
--   - chronicle_admin bypasses RLS (BYPASSRLS attribute)
--   - Passwords should be set via environment variables or secrets management
-- =============================================================================

SET search_path TO public;

-- Create application role (RLS enforced)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'chronicle_app') THEN
        CREATE ROLE chronicle_app WITH
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION
            CONNECTION LIMIT -1;

        RAISE NOTICE 'Created role: chronicle_app';
    ELSE
        RAISE NOTICE 'Role chronicle_app already exists';
    END IF;
END $$;

-- Create admin role (bypasses RLS)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'chronicle_admin') THEN
        CREATE ROLE chronicle_admin WITH
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION
            BYPASSRLS
            CONNECTION LIMIT 5;

        RAISE NOTICE 'Created role: chronicle_admin';
    ELSE
        RAISE NOTICE 'Role chronicle_admin already exists';
    END IF;
END $$;

-- Flyway owns every permanent table. Runtime roles can use the schema but may
-- not create attacker-controlled tables, functions, or triggers in it.
GRANT USAGE ON SCHEMA public TO chronicle_app;
GRANT USAGE ON SCHEMA public TO chronicle_admin;
REVOKE CREATE ON SCHEMA public FROM PUBLIC, chronicle_app, chronicle_admin;

-- Framework tables are created after role bootstrap. Set their creation defaults;
-- preserve existing object/column ACLs, which the migration or restored dump owns.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO chronicle_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO chronicle_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON TABLES TO chronicle_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON SEQUENCES TO chronicle_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO chronicle_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO chronicle_admin;

-- =============================================================================
-- Append-only audit-trail immutability (defense-in-depth)
-- =============================================================================
-- The append-only audit trails must stay immutable to the application roles. RLS is the
-- PRIMARY enforcement (V2 policies on audit_logs; V44 policies on study_settings_audit and
-- participant_collection_acknowledgment; V90/V93 policies on withdrawal receipts and settings
-- revisions) and is GRANT-proof. These REVOKEs are belt-and-suspenders:
-- the creation defaults above otherwise hand
-- chronicle_app (and chronicle_admin, which BYPASSes RLS) UPDATE/DELETE on every table — which
-- is exactly what silently defeated the V15/V25/V26 REVOKEs once before (the grant re-ran after
-- the one-time migration). Stripping it here, as the LAST word and on every re-run, means the
-- grant never reaches these tables in the first place. Only the postgres superuser may purge
-- (for retention). Guarded on table existence so it is a no-op at fresh-DB init (the audit
-- tables are created later by the application's table bootstrap).
DO $$
DECLARE
    audit_table TEXT;
BEGIN
    -- The function owner reads the token key; request roles never read or replace it.
    IF to_regclass('public.chronicle_participant_token_key') IS NOT NULL THEN
        REVOKE ALL ON public.chronicle_participant_token_key FROM PUBLIC, chronicle_app, chronicle_admin;
    END IF;
    FOREACH audit_table IN ARRAY ARRAY[
        'audit_logs',
        'audit',
        'audit_buffer',
        'study_settings_audit',
        'participant_collection_acknowledgment',
        'mobile_withdrawal_requests'
    ] LOOP
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = audit_table
        ) THEN
            EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM chronicle_app, chronicle_admin', audit_table);
            RAISE NOTICE 'Revoked UPDATE/DELETE/TRUNCATE on % from chronicle_app, chronicle_admin', audit_table;
        END IF;
    END LOOP;

    -- The application inserts withdrawal receipts inside the atomic withdrawal
    -- transaction. The BYPASSRLS maintenance role must never forge or pre-bind one.
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'mobile_withdrawal_requests'
    ) THEN
        REVOKE INSERT ON mobile_withdrawal_requests FROM chronicle_admin;
        RAISE NOTICE 'Revoked INSERT on mobile_withdrawal_requests from chronicle_admin';
    END IF;

    -- The request path only appends to the legacy audit store and only UPDATEs the
    -- deletion-audit outbox (V112).
    IF to_regclass('public.audit') IS NOT NULL THEN
        REVOKE SELECT ON audit FROM chronicle_app;
    END IF;
    IF to_regclass('public.audit_buffer') IS NOT NULL THEN
        REVOKE SELECT ON audit_buffer FROM chronicle_app;
    END IF;
    IF to_regclass('public.data_deletion_audit_outbox') IS NOT NULL THEN
        REVOKE DELETE, TRUNCATE ON data_deletion_audit_outbox FROM chronicle_app;
    END IF;

    -- DataCollection revisions are written only by the SECURITY DEFINER trigger in V93.
    -- Runtime roles may read the ledger but may never forge or destroy its evidence.
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'data_collection_settings_revisions'
    ) THEN
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE
            ON data_collection_settings_revisions FROM chronicle_app, chronicle_admin;
        RAISE NOTICE 'Revoked mutation privileges on data_collection_settings_revisions from chronicle_app, chronicle_admin';
    END IF;

    -- Restore reconciliation receipts are written only by the trusted schema owner during
    -- blocking startup. The app cannot read them and neither runtime role may forge or erase one.
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'restore_continuity_reconciliations'
    ) THEN
        REVOKE ALL ON restore_continuity_reconciliations FROM chronicle_app;
        REVOKE INSERT, UPDATE, DELETE, TRUNCATE
            ON restore_continuity_reconciliations FROM chronicle_admin;
        GRANT SELECT ON restore_continuity_reconciliations TO chronicle_admin;
        RAISE NOTICE 'Restricted restore continuity receipts to the trusted schema owner';
    END IF;

    -- The V93 trigger is already attached by the trusted schema owner. Runtime
    -- roles must not invoke its SECURITY DEFINER function from attacker-owned
    -- triggers to forge revision evidence.
    IF to_regprocedure('public.record_data_collection_settings_revision()') IS NOT NULL THEN
        REVOKE EXECUTE ON FUNCTION public.record_data_collection_settings_revision()
            FROM chronicle_app, chronicle_admin;
        RAISE NOTICE 'Revoked direct revision-recorder execution from chronicle_app, chronicle_admin';
    END IF;
END $$;

-- =============================================================================
-- Password Configuration
-- =============================================================================
-- Set passwords for the roles. In production, use environment variables or
-- secrets management instead of hardcoded passwords.
--
-- Example (run separately with actual passwords):
--   ALTER ROLE chronicle_app PASSWORD 'your-secure-app-password';
--   ALTER ROLE chronicle_admin PASSWORD 'your-secure-admin-password';
-- =============================================================================

-- Placeholder for password setting (uncomment and modify in deployment)
-- ALTER ROLE chronicle_app PASSWORD :'CHRONICLE_APP_PASSWORD';
-- ALTER ROLE chronicle_admin PASSWORD :'CHRONICLE_ADMIN_PASSWORD';

-- =============================================================================
-- Verification Queries (optional - uncomment to verify setup)
-- =============================================================================
-- SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname LIKE 'chronicle_%';
-- SELECT * FROM information_schema.role_table_grants WHERE grantee LIKE 'chronicle_%';
