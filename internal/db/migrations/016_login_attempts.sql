-- +goose Up
-- Brute-force login tracking: one row per attempt, so the login handler can
-- lock an account (or a username) after repeated failures within a window.
CREATE TABLE login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL,
    remote_ip    TEXT,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_login_attempts_username ON login_attempts (username, attempted_at);

-- +goose Down
DROP TABLE login_attempts;
