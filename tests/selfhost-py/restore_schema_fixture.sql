-- Minimal application contract used by the real restore-service regression.
CREATE ROLE chronicle_app;
CREATE ROLE chronicle_admin;
CREATE TABLE chronicle_participant_token_key (singleton boolean PRIMARY KEY, key_bytes bytea NOT NULL);
INSERT INTO chronicle_participant_token_key VALUES (true, decode(repeat('ab', 32), 'hex'));
CREATE TABLE studies (study_id uuid, settings jsonb, modules jsonb, lifecycle_status text,
    collection_closed_at timestamptz, updated_at timestamptz,
    closed_capture_windows tstzmultirange NOT NULL DEFAULT '{}'::tstzmultirange);
CREATE TABLE study_participants (study_id uuid, participant_id text, participation_status text,
    capture_cutoff timestamptz, updated_at timestamptz,
    closed_capture_windows tstzmultirange NOT NULL DEFAULT '{}'::tstzmultirange,
    hard_stop_generation bigint NOT NULL DEFAULT 0, hard_stopped_at timestamptz);
CREATE TABLE api_keys (key_id uuid, study_id uuid, participant_id text, random_device_id uuid, revoked boolean);
CREATE TABLE mobile_withdrawal_requests (request_id uuid, api_key_id uuid, study_id uuid,
    participant_id text, random_device_id uuid, already_withdrawn boolean, created_at timestamptz);
CREATE TABLE data_deletion_operations (operation_id uuid, study_id uuid, participant_ref text,
    participant_id text, participant_block_token text, mode text, status text, requested_by text,
    idempotency_key uuid, registry_version integer, started_at timestamptz,
    completed_at timestamptz, proof_hash text, cancelled_by text, cancelled_at timestamptz);
CREATE TABLE data_deletion_tombstones (operation_id uuid, study_ref text, participant_ref text,
    mode text, registry_version integer, completed_at timestamptz, proof_hash text);
CREATE TABLE data_collection_settings_revisions (study_id uuid, settings_version integer,
    setting jsonb, study_modules jsonb, issued_at timestamptz);
CREATE TABLE participant_form_access_codes (access_code_id uuid, token_hash bytea, study_id uuid,
    participant_id text, form_kind text, resource_id uuid, logical_date date, issuer_type text,
    issued_by text, expires_at timestamptz, exchanged_at timestamptz, revoked_at timestamptz,
    created_at timestamptz, enrollment_attempt_id uuid, enrollment_source_device_hash text,
    enrollment_random_device_id uuid, enrollment_manifest_digest text, enrollment_request_hash text,
    enrollment_proposed_key_hash text, enrollment_replay_expires_at timestamptz,
    enrollment_settings_version integer, enrollment_disclosure_version text,
    enrollment_enabled_modules text[], enrollment_required_modules text[]);
CREATE TABLE erased_device_key_tombstones (key_hash text, kind text, expires_at timestamptz);
CREATE TABLE participant_purge_cutoffs (study_id uuid, participant_block_token text, cutoff timestamptz);
CREATE TABLE participant_collection_acknowledgment (study_id uuid, acknowledged_at timestamptz,
    recorded_at timestamptz);
CREATE TABLE flyway_schema_history (version text, success boolean, installed_rank integer);
CREATE TABLE audit (event text);
CREATE TABLE audit_buffer (event text);
CREATE TABLE data_deletion_audit_outbox (event text);
CREATE TABLE restore_continuity_reconciliations (receipt text);
GRANT SELECT ON studies TO chronicle_app;
GRANT INSERT ON audit TO chronicle_app;
INSERT INTO audit VALUES ('backup-row');

CREATE TABLE jwt_session_state (
    state_group text NOT NULL,
    state_key text NOT NULL,
    state_value bigint NOT NULL,
    expires_at timestamp with time zone,
    PRIMARY KEY (state_group, state_key)
);
