DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM chronicle_restore_continuity.restricted_participants source
        JOIN public.study_participants target USING (study_id, participant_id)
        WHERE NOT target.closed_capture_windows @> source.closed_capture_windows
           OR target.hard_stop_generation < source.hard_stop_generation
           OR (source.hard_stopped_at IS NOT NULL
               AND (target.hard_stopped_at IS NULL OR target.hard_stopped_at < source.hard_stopped_at))
           OR (source.participation_status IN ('PAUSED', 'COLLECTION_COMPLETED')
               AND target.participation_status IN ('ENROLLED', 'UNKNOWN'))
           OR (source.participation_status = 'COLLECTION_COMPLETED' AND target.participation_status = 'PAUSED')
           OR (source.capture_cutoff IS NOT NULL
               AND target.participation_status IN ('PAUSED', 'COLLECTION_COMPLETED', 'NOT_ENROLLED')
               AND (target.capture_cutoff IS NULL OR target.capture_cutoff > source.capture_cutoff))
    ) OR EXISTS (
        SELECT 1 FROM chronicle_restore_continuity.archived_studies source
        JOIN public.studies target USING (study_id)
        WHERE NOT target.closed_capture_windows @> source.closed_capture_windows
           OR (source.lifecycle_status <> 'ACTIVE' AND (target.lifecycle_status = 'ACTIVE'
               OR target.collection_closed_at IS NULL OR target.collection_closed_at > source.collection_closed_at))
    ) THEN
        RAISE EXCEPTION 'Post-restore collection restrictions could not be proven';
    END IF;
END $$;
