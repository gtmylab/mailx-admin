-- +goose Up
-- +goose StatementBegin

ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_mail_events_to ON mail_events(to_addr, ts DESC);
CREATE INDEX idx_mail_events_svc_act ON mail_events(service, action, ts DESC);

-- +goose StatementEnd

-- +goose Down
DROP INDEX idx_mail_events_svc_act;
DROP INDEX idx_mail_events_to;
ALTER TABLE users DROP COLUMN display_name;
