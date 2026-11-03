-- Generated from selfhost/restore-checkpoint-capture.sql.template by scripts/generate-chronicle-contracts.py.
CREATE SCHEMA chronicle_restore_continuity;
REVOKE ALL ON SCHEMA chronicle_restore_continuity
    FROM PUBLIC, chronicle_app, chronicle_admin;

CREATE TABLE chronicle_restore_continuity.checkpoint (
    contract_version INTEGER NOT NULL,
    checkpoint_id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    source_schema_version TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL,
    withdrawal_receipt_count BIGINT NOT NULL,
    revoked_api_key_count BIGINT NOT NULL,
    withdrawn_participant_count BIGINT NOT NULL,
    deletion_operation_count BIGINT NOT NULL,
    source_tombstone_count BIGINT NOT NULL,
    collection_revision_count BIGINT NOT NULL,
    published_collection_settings_count BIGINT NOT NULL,
    enrollment_invitation_count BIGINT NOT NULL,
    erased_device_key_tombstone_count BIGINT NOT NULL,
    restricted_participant_count BIGINT NOT NULL,
    archived_study_count BIGINT NOT NULL
);

CREATE TABLE chronicle_restore_continuity.withdrawal_requests AS
SELECT request_id, api_key_id, study_id, participant_id, random_device_id,
       already_withdrawn, created_at
FROM public.mobile_withdrawal_requests;

CREATE TABLE chronicle_restore_continuity.revoked_api_keys AS
SELECT key_id, study_id, participant_id, random_device_id
FROM public.api_keys
WHERE revoked;

CREATE TABLE chronicle_restore_continuity.withdrawn_participants AS
SELECT study_id, participant_id
FROM public.study_participants
WHERE participation_status = 'NOT_ENROLLED'
UNION
SELECT study_id, participant_id
FROM public.mobile_withdrawal_requests;

CREATE TABLE chronicle_restore_continuity.restricted_participants (
    study_id UUID NOT NULL,
    participant_id TEXT NOT NULL,
    participation_status TEXT NOT NULL,
    capture_cutoff TIMESTAMPTZ,
    closed_capture_windows tstzmultirange NOT NULL DEFAULT '{}'::tstzmultirange,
    hard_stop_generation BIGINT NOT NULL DEFAULT 0,
    hard_stopped_at TIMESTAMPTZ,
    PRIMARY KEY (study_id, participant_id)
);
CREATE TABLE chronicle_restore_continuity.archived_studies (
    study_id UUID PRIMARY KEY,
    collection_closed_at TIMESTAMPTZ,
    closed_capture_windows tstzmultirange NOT NULL DEFAULT '{}'::tstzmultirange,
    lifecycle_status TEXT NOT NULL DEFAULT 'ARCHIVED'
);
INSERT INTO chronicle_restore_continuity.restricted_participants
SELECT study_id, participant_id, participation_status, capture_cutoff, closed_capture_windows,
       hard_stop_generation, hard_stopped_at
FROM public.study_participants WHERE participation_status IN ('PAUSED', 'COLLECTION_COMPLETED')
   OR closed_capture_windows <> '{}'::tstzmultirange OR hard_stop_generation > 0;
INSERT INTO chronicle_restore_continuity.archived_studies
SELECT study_id, collection_closed_at, closed_capture_windows, lifecycle_status
FROM public.studies WHERE lifecycle_status = 'ARCHIVED' OR closed_capture_windows <> '{}'::tstzmultirange;

CREATE TABLE chronicle_restore_continuity.deletion_operations AS
SELECT operation_id, study_id, participant_ref, participant_id, participant_block_token,
       mode, status, requested_by, idempotency_key, registry_version,
       started_at, completed_at, proof_hash, cancelled_by, cancelled_at
FROM public.data_deletion_operations;

CREATE TABLE chronicle_restore_continuity.deletion_tombstones AS
SELECT operation_id, study_ref, participant_ref, mode, registry_version,
       completed_at, proof_hash
FROM public.data_deletion_tombstones;

CREATE TABLE chronicle_restore_continuity.data_collection_settings_revisions AS
SELECT study_id, settings_version, setting, study_modules, issued_at
FROM public.data_collection_settings_revisions;

CREATE TABLE chronicle_restore_continuity.published_data_collection_settings AS
SELECT study_id,
       (settings -> 'DataCollection' ->> 'settingsVersion')::INTEGER AS settings_version,
       settings -> 'DataCollection' AS setting, modules AS study_modules
FROM public.studies
WHERE jsonb_typeof(settings -> 'DataCollection') = 'object'
  AND settings -> 'DataCollection' ->> 'settingsVersion' ~ '^[1-9][0-9]*$';

CREATE TABLE chronicle_restore_continuity.enrollment_invitations AS
SELECT access_code_id, token_hash, study_id, participant_id, form_kind, resource_id,
       logical_date, issuer_type, issued_by, expires_at, exchanged_at, revoked_at, created_at,
       enrollment_attempt_id, enrollment_source_device_hash, enrollment_random_device_id,
       enrollment_manifest_digest, enrollment_request_hash, enrollment_proposed_key_hash,
       enrollment_replay_expires_at, enrollment_settings_version,
       enrollment_disclosure_version, enrollment_enabled_modules, enrollment_required_modules
FROM public.participant_form_access_codes
WHERE form_kind = 'ENROLLMENT';

-- Erasure deleted these device keys; their hashes keep answering an offline phone with its terminal
-- status. A key enrolled after the backup exists nowhere else, so its tombstone is carried as is.
CREATE TABLE chronicle_restore_continuity.erased_device_key_tombstones (
    key_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
DO $$
BEGIN
    IF to_regclass('public.erased_device_key_tombstones') IS NOT NULL THEN
        INSERT INTO chronicle_restore_continuity.erased_device_key_tombstones (key_hash, kind, expires_at)
        SELECT key_hash, kind, expires_at
        FROM public.erased_device_key_tombstones
        WHERE expires_at > now();
    END IF;
END $$;

CREATE TABLE chronicle_restore_continuity.participant_purge_cutoffs
    (LIKE public.participant_purge_cutoffs);
CREATE TABLE chronicle_restore_continuity.participant_token_key AS
    SELECT singleton, key_bytes FROM public.chronicle_participant_token_key;
CREATE TABLE chronicle_restore_continuity.participant_collection_acknowledgment
    (LIKE public.participant_collection_acknowledgment);
ALTER TABLE chronicle_restore_continuity.checkpoint
    ADD COLUMN purge_cutoff_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN collection_acknowledgment_count BIGINT NOT NULL DEFAULT 0;
INSERT INTO chronicle_restore_continuity.participant_purge_cutoffs
SELECT * FROM public.participant_purge_cutoffs;
INSERT INTO chronicle_restore_continuity.participant_collection_acknowledgment
SELECT * FROM public.participant_collection_acknowledgment;

WITH capture_windows(kind, study_id, participant_id, closed_window) AS (
    SELECT 'participant-window', study_id, participant_id, unnest(closed_capture_windows)
    FROM chronicle_restore_continuity.restricted_participants
    UNION ALL
    SELECT 'study-window', study_id, NULL, unnest(closed_capture_windows)
    FROM chronicle_restore_continuity.archived_studies
), canonical(line) AS (
    SELECT concat_ws('|', kind, study_id::text, COALESCE(participant_id, '<null>'),
                     COALESCE(extract(epoch FROM lower(closed_window))::text, '<null>'),
                     COALESCE(extract(epoch FROM upper(closed_window))::text, '<null>'),
                     lower_inc(closed_window), upper_inc(closed_window))
    FROM capture_windows
    UNION ALL
    SELECT concat_ws('|', 'participant-token-key', singleton::text, encode(key_bytes, 'hex'))
    FROM chronicle_restore_continuity.participant_token_key
    UNION ALL
    SELECT concat_ws('|',
        'withdrawal', request_id::text, api_key_id::text, study_id::text,
        participant_id, random_device_id::text, already_withdrawn::text,
        to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    FROM chronicle_restore_continuity.withdrawal_requests
    UNION ALL
    SELECT concat_ws('|',
        'revoked-key', key_id::text, study_id::text,
        COALESCE(participant_id, '<null>'), COALESCE(random_device_id::text, '<null>'))
    FROM chronicle_restore_continuity.revoked_api_keys
    UNION ALL
    SELECT concat_ws('|', 'withdrawn', study_id::text, participant_id)
    FROM chronicle_restore_continuity.withdrawn_participants
    UNION ALL
    SELECT concat_ws('|',
        'operation', operation_id::text, study_id::text,
        COALESCE(participant_ref, '<null>'), COALESCE(participant_id, '<null>'),
        COALESCE(participant_block_token, '<null>'),
        mode, status, requested_by, idempotency_key::text, registry_version::text,
        COALESCE(to_char(started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '<null>'),
        COALESCE(to_char(completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '<null>'),
        COALESCE(proof_hash, '<null>'), COALESCE(cancelled_by, '<null>'),
        COALESCE(to_char(cancelled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '<null>'))
    FROM chronicle_restore_continuity.deletion_operations
    UNION ALL
    SELECT concat_ws('|',
        'tombstone', operation_id::text, study_ref,
        COALESCE(participant_ref, '<null>'), mode, registry_version::text,
        to_char(completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        proof_hash)
    FROM chronicle_restore_continuity.deletion_tombstones
    UNION ALL
    SELECT concat_ws('|', 'collection-revision', study_id::text, settings_version::text,
                     setting::text, study_modules::text,
                     to_char(issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    FROM chronicle_restore_continuity.data_collection_settings_revisions
    UNION ALL
    SELECT concat_ws('|', 'published-collection-settings', study_id::text,
                     settings_version::text, setting::text, study_modules::text)
    FROM chronicle_restore_continuity.published_data_collection_settings
    UNION ALL
    SELECT concat_ws('|', 'enrollment-invitation', access_code_id::text,
                     encode(token_hash, 'hex'), study_id::text, participant_id, form_kind,
                     COALESCE(resource_id::text, '<null>'), COALESCE(logical_date::text, '<null>'),
                     issuer_type, issued_by,
                     to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                     COALESCE(to_char(exchanged_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '<null>'),
                     COALESCE(to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '<null>'),
                     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                     COALESCE(enrollment_attempt_id::text, '<null>'),
                     COALESCE(enrollment_source_device_hash, '<null>'),
                     COALESCE(enrollment_random_device_id::text, '<null>'),
                     COALESCE(enrollment_manifest_digest, '<null>'),
                     COALESCE(enrollment_request_hash, '<null>'),
                     COALESCE(enrollment_proposed_key_hash, '<null>'),
                     COALESCE(to_char(enrollment_replay_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '<null>'),
                     COALESCE(enrollment_settings_version::text, '<null>'),
                     COALESCE(enrollment_disclosure_version, '<null>'),
                     COALESCE(enrollment_enabled_modules::text, '<null>'),
                     COALESCE(enrollment_required_modules::text, '<null>'))
    FROM chronicle_restore_continuity.enrollment_invitations
    UNION ALL
    SELECT concat_ws('|', 'erased-device-key', key_hash, kind,
                     to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    FROM chronicle_restore_continuity.erased_device_key_tombstones
    UNION ALL
    SELECT concat_ws('|', 'restricted-participant', study_id::text, participant_id, participation_status,
                     COALESCE(to_char(capture_cutoff AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '<null>'),
                     hard_stop_generation::text,
                     COALESCE(to_char(hard_stopped_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '<null>'))
    FROM chronicle_restore_continuity.restricted_participants
    UNION ALL
    SELECT concat_ws('|', 'archived-study', study_id::text, lifecycle_status,
                     to_char(collection_closed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    FROM chronicle_restore_continuity.archived_studies
    UNION ALL
    SELECT concat_ws('|', 'purge-cutoff', study_id::text, participant_block_token,
                     to_char(cutoff AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    FROM chronicle_restore_continuity.participant_purge_cutoffs
    UNION ALL
    SELECT concat_ws('|', 'collection-acknowledgment', (to_jsonb(acknowledgment) - 'acknowledged_at' - 'recorded_at')::text,
                     to_char(acknowledged_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                     to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    FROM chronicle_restore_continuity.participant_collection_acknowledgment acknowledgment
), digest AS (
    SELECT encode(
        sha256(convert_to(COALESCE(string_agg(line, E'\n' ORDER BY line), ''), 'UTF8')),
        'hex'
    ) AS value
    FROM canonical
)
INSERT INTO chronicle_restore_continuity.checkpoint (
    contract_version, checkpoint_id, created_at, source_schema_version,
    checkpoint_sha256, withdrawal_receipt_count, revoked_api_key_count,
    withdrawn_participant_count, deletion_operation_count, source_tombstone_count,
    collection_revision_count, published_collection_settings_count,
    enrollment_invitation_count, erased_device_key_tombstone_count,
    restricted_participant_count, archived_study_count, purge_cutoff_count, collection_acknowledgment_count
)
SELECT 8,
       gen_random_uuid(),
       now(),
       COALESCE(
           (SELECT version FROM public.flyway_schema_history
            WHERE success ORDER BY installed_rank DESC LIMIT 1),
           'unversioned'
       ),
       digest.value,
       (SELECT count(*) FROM chronicle_restore_continuity.withdrawal_requests),
       (SELECT count(*) FROM chronicle_restore_continuity.revoked_api_keys),
       (SELECT count(*) FROM chronicle_restore_continuity.withdrawn_participants),
       (SELECT count(*) FROM chronicle_restore_continuity.deletion_operations),
       (SELECT count(*) FROM chronicle_restore_continuity.deletion_tombstones),
       (SELECT count(*) FROM chronicle_restore_continuity.data_collection_settings_revisions),
       (SELECT count(*) FROM chronicle_restore_continuity.published_data_collection_settings),
       (SELECT count(*) FROM chronicle_restore_continuity.enrollment_invitations),
       (SELECT count(*) FROM chronicle_restore_continuity.erased_device_key_tombstones),
       (SELECT count(*) FROM chronicle_restore_continuity.restricted_participants),
       (SELECT count(*) FROM chronicle_restore_continuity.archived_studies),
       (SELECT count(*) FROM chronicle_restore_continuity.participant_purge_cutoffs),
       (SELECT count(*) FROM chronicle_restore_continuity.participant_collection_acknowledgment)
FROM digest;

REVOKE ALL ON ALL TABLES IN SCHEMA chronicle_restore_continuity
    FROM PUBLIC, chronicle_app, chronicle_admin;
