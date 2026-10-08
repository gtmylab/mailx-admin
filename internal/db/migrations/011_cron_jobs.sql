-- +goose Up
-- User-defined scheduled jobs. Enabled rows are rendered to /etc/cron.d/mailx-admin
-- and run by the system cron daemon through `mailx-admin cron run <id>`, which
-- records last_run_at / last_status / last_output so the panel can show history.
CREATE TABLE cron_jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    schedule    TEXT NOT NULL,                     -- standard 5-field cron expression
    command     TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run_at TIMESTAMP,
    last_status TEXT NOT NULL DEFAULT '',          -- '' | 'ok' | 'error' | 'running'
    last_output TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down
DROP TABLE cron_jobs;
