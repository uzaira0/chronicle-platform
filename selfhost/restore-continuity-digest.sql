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
