-- Preserve stronger terminal restrictions already present in the selected backup.
UPDATE public.study_participants target
SET participation_status = source.participation_status, updated_at = now()
FROM chronicle_restore_continuity.restricted_participants source
WHERE target.study_id = source.study_id AND target.participant_id = source.participant_id
  AND source.participation_status IN ('PAUSED', 'COLLECTION_COMPLETED')
  AND (target.participation_status IN ('ENROLLED', 'UNKNOWN')
       OR (target.participation_status = 'PAUSED' AND source.participation_status = 'COLLECTION_COMPLETED'));

UPDATE public.studies target
SET lifecycle_status = CASE WHEN target.lifecycle_status = 'ACTIVE' THEN 'ARCHIVED' ELSE target.lifecycle_status END,
    collection_closed_at = LEAST(target.collection_closed_at, source.collection_closed_at), updated_at = now()
FROM chronicle_restore_continuity.archived_studies source
WHERE target.study_id = source.study_id AND source.lifecycle_status <> 'ACTIVE'
  AND (target.lifecycle_status = 'ACTIVE' OR target.collection_closed_at IS NULL
       OR target.collection_closed_at > source.collection_closed_at);

UPDATE public.study_participants target
-- record_capture_cutoff imports the protected checkpoint's hard-stop facts with these windows.
SET closed_capture_windows = target.closed_capture_windows + source.closed_capture_windows
FROM chronicle_restore_continuity.restricted_participants source
WHERE target.study_id = source.study_id AND target.participant_id = source.participant_id;

UPDATE public.study_participants target
SET capture_cutoff = LEAST(target.capture_cutoff, source.capture_cutoff)
FROM chronicle_restore_continuity.restricted_participants source
WHERE target.study_id = source.study_id AND target.participant_id = source.participant_id
  AND source.participation_status IN ('PAUSED', 'COLLECTION_COMPLETED', 'NOT_ENROLLED')
  AND target.participation_status IN ('PAUSED', 'COLLECTION_COMPLETED', 'NOT_ENROLLED');

UPDATE public.studies target
SET closed_capture_windows = target.closed_capture_windows + source.closed_capture_windows
FROM chronicle_restore_continuity.archived_studies source
WHERE target.study_id = source.study_id;
