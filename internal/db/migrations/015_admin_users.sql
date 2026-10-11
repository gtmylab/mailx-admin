-- +goose Up
-- Panel admin accounts: identity, account type, per-user session TTL, group
-- membership, and notification handles (Slack/Telegram/email/etc).
ALTER TABLE admin_users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_users ADD COLUMN email TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'panel'; -- system | panel | both
ALTER TABLE admin_users ADD COLUMN session_ttl_minutes INTEGER;                -- NULL = global default
ALTER TABLE admin_users ADD COLUMN group_id INTEGER;

CREATE TABLE admin_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL DEFAULT 'readonly', -- superadmin | admin | operator | readonly
    permissions TEXT NOT NULL DEFAULT '[]'        -- JSON array of permission strings
);

CREATE TABLE admin_user_notifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    provider      TEXT NOT NULL,   -- slack | telegram | discord | email | webhook
    target        TEXT NOT NULL,   -- webhook URL / chat id / email address
    events        TEXT NOT NULL DEFAULT '[]', -- JSON array of event names
    active        INTEGER NOT NULL DEFAULT 1
);

-- +goose Down
-- SQLite < 3.35 cannot drop columns; the new columns are harmless and are left
-- in place on rollback (matching the codebase's 008_analytics precedent).
DROP TABLE admin_user_notifications;
DROP TABLE admin_groups;
