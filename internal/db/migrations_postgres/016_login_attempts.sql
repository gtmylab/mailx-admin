-- +goose Up
CREATE TABLE login_attempts (
    id           BIGSERIAL PRIMARY KEY,
    username     TEXT NOT NULL,
    remote_ip    TEXT,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_login_attempts_username ON login_attempts (username, attempted_at);

-- +goose Down
DROP TABLE login_attempts;
