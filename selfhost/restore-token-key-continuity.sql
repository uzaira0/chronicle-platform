DO $$
BEGIN
    IF (SELECT count(*) FROM chronicle_restore_continuity.participant_token_key) <> 1
       OR (SELECT count(*) FROM public.chronicle_participant_token_key) <> 1
       OR NOT EXISTS (
           SELECT 1 FROM chronicle_restore_continuity.participant_token_key captured
           JOIN public.chronicle_participant_token_key restored
             ON captured.singleton = restored.singleton AND captured.key_bytes = restored.key_bytes
           WHERE captured.singleton
       ) THEN
        RAISE EXCEPTION 'Participant token key differs from protected restore checkpoint';
    END IF;
END $$;
