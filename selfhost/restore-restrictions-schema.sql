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
