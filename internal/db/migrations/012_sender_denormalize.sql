-- +goose Up
-- The per-account deliverability aggregate used to self-join mail_events on
-- queue_id to recover the envelope sender, which made /deliverability time out
-- on busy servers. The sender is now denormalized onto delivery events at
-- ingest time (internal/logs), and this index makes that lookup — and the
-- one-time backfill of historical rows — a single probe on (queue_id, action).
CREATE INDEX idx_mail_events_qid_action ON mail_events(queue_id, action);

-- +goose Down
DROP INDEX idx_mail_events_qid_action;
