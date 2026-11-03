CREATE TABLE chronicle_restore_continuity.participant_purge_cutoffs
    (LIKE public.participant_purge_cutoffs);
CREATE TABLE chronicle_restore_continuity.participant_token_key AS
    SELECT singleton, key_bytes FROM public.chronicle_participant_token_key;
CREATE TABLE chronicle_restore_continuity.participant_collection_acknowledgment
    (LIKE public.participant_collection_acknowledgment);
ALTER TABLE chronicle_restore_continuity.checkpoint
    ADD COLUMN purge_cutoff_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN collection_acknowledgment_count BIGINT NOT NULL DEFAULT 0;
