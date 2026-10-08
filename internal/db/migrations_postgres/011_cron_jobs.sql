-- +goose Up
CREATE TABLE cron_jobs (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    schedule    TEXT NOT NULL,
    command     TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run_at TIMESTAMP,
    last_status TEXT NOT NULL DEFAULT '',
    last_output TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down
DROP TABLE cron_jobs;
