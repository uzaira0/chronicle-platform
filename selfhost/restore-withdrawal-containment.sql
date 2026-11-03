UPDATE public.api_keys AS target
SET revoked = true
FROM chronicle_restore_continuity.revoked_api_keys AS source
WHERE target.key_id = source.key_id;

UPDATE public.api_keys AS target
SET revoked = true
FROM chronicle_restore_continuity.withdrawn_participants AS source
WHERE target.study_id = source.study_id
  AND target.participant_id = source.participant_id
  AND target.participant_id IS NOT NULL;

UPDATE public.study_participants AS target
SET participation_status = 'NOT_ENROLLED', updated_at = now()
FROM chronicle_restore_continuity.withdrawn_participants AS source
WHERE target.study_id = source.study_id
  AND target.participant_id = source.participant_id;

DO $$
DECLARE violations BIGINT;
BEGIN
    SELECT
        (SELECT count(*)
         FROM chronicle_restore_continuity.revoked_api_keys source
         JOIN public.api_keys target ON target.key_id = source.key_id
         WHERE NOT target.revoked) +
        (SELECT count(*)
         FROM chronicle_restore_continuity.withdrawn_participants source
         JOIN public.api_keys target
           ON target.study_id = source.study_id
          AND target.participant_id = source.participant_id
         WHERE NOT target.revoked) +
        (SELECT count(*)
         FROM chronicle_restore_continuity.withdrawn_participants source
         JOIN public.study_participants target
           ON target.study_id = source.study_id
          AND target.participant_id = source.participant_id
         WHERE target.participation_status <> 'NOT_ENROLLED')
    INTO violations;
    IF violations <> 0 THEN
        RAISE EXCEPTION 'Post-restore withdrawal containment verification failed';
    END IF;
END $$;
