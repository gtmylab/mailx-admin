-- +goose Up
CREATE INDEX idx_mail_events_qid_action ON mail_events(queue_id, action);

-- +goose Down
DROP INDEX idx_mail_events_qid_action;
