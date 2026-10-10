-- +goose Up
-- Rich cron scheduler UI: run-as user, stdin, description, a simple schedule
-- preset, and an advanced picker (minute/hour/day/month/weekday selections)
-- plus an optional annual date range. The final `schedule` column remains the
-- authoritative 5-field cron expression.
ALTER TABLE cron_jobs ADD COLUMN run_as TEXT NOT NULL DEFAULT 'root';
ALTER TABLE cron_jobs ADD COLUMN input TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN simple_schedule TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN schedule_mode TEXT NOT NULL DEFAULT 'simple';
ALTER TABLE cron_jobs ADD COLUMN minutes TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN hours TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN days TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN months TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN weekdays TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN date_range_mode TEXT NOT NULL DEFAULT 'any';
ALTER TABLE cron_jobs ADD COLUMN start_month TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN start_date TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN end_month TEXT NOT NULL DEFAULT '';
ALTER TABLE cron_jobs ADD COLUMN end_date TEXT NOT NULL DEFAULT '';

-- +goose Down
-- SQLite < 3.35 cannot drop columns; the new columns are harmless and are left
-- in place on rollback (matching the codebase's 008_analytics precedent).
