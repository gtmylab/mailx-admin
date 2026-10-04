-- +goose Up
-- +goose StatementBegin

-- Display name (identity) for a mailbox: the "From" name shown in webmail and
-- in the default Roundcube identity. Empty means "derive from the local part".
ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- Per-recipient lookups: the per-user message audit ("what did this mailbox
-- send/receive") filters on to_addr/from_addr, which had no to_addr index.
CREATE INDEX idx_mail_events_to ON mail_events(to_addr, ts DESC);
CREATE INDEX idx_mail_events_svc_act ON mail_events(service, action, ts DESC);

-- +goose StatementEnd

-- +goose Down
DROP INDEX idx_mail_events_svc_act;
DROP INDEX idx_mail_events_to;
-- display_name is left in place: SQLite < 3.35 cannot drop a column, and a
-- rollback that erases user data is worse than one that keeps a harmless column.
