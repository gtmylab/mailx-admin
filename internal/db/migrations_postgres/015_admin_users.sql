-- +goose Up
ALTER TABLE admin_users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_users ADD COLUMN email TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'panel';
ALTER TABLE admin_users ADD COLUMN session_ttl_minutes INTEGER;
ALTER TABLE admin_users ADD COLUMN group_id INTEGER;

CREATE TABLE admin_groups (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL DEFAULT 'readonly',
    permissions TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE admin_user_notifications (
    id            BIGSERIAL PRIMARY KEY,
    admin_user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    provider      TEXT NOT NULL,
    target        TEXT NOT NULL,
    events        TEXT NOT NULL DEFAULT '[]',
    active        INTEGER NOT NULL DEFAULT 1
);

-- +goose Down
DROP TABLE admin_user_notifications;
DROP TABLE admin_groups;
ALTER TABLE admin_users DROP COLUMN display_name;
ALTER TABLE admin_users DROP COLUMN email;
ALTER TABLE admin_users DROP COLUMN account_type;
ALTER TABLE admin_users DROP COLUMN session_ttl_minutes;
ALTER TABLE admin_users DROP COLUMN group_id;
