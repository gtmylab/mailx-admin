-- +goose Up
-- +goose StatementBegin

ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'virtual';
ALTER TABLE users ADD COLUMN sys_uid INTEGER;
ALTER TABLE users ADD COLUMN sys_gid INTEGER;
ALTER TABLE users ADD COLUMN home TEXT;

CREATE INDEX idx_users_kind ON users(kind);

-- +goose StatementEnd

-- +goose Down
DROP INDEX idx_users_kind;
ALTER TABLE users DROP COLUMN home;
ALTER TABLE users DROP COLUMN sys_gid;
ALTER TABLE users DROP COLUMN sys_uid;
ALTER TABLE users DROP COLUMN kind;
