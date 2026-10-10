-- +goose Up
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
ALTER TABLE cron_jobs DROP COLUMN run_as;
ALTER TABLE cron_jobs DROP COLUMN input;
ALTER TABLE cron_jobs DROP COLUMN description;
ALTER TABLE cron_jobs DROP COLUMN simple_schedule;
ALTER TABLE cron_jobs DROP COLUMN schedule_mode;
ALTER TABLE cron_jobs DROP COLUMN minutes;
ALTER TABLE cron_jobs DROP COLUMN hours;
ALTER TABLE cron_jobs DROP COLUMN days;
ALTER TABLE cron_jobs DROP COLUMN months;
ALTER TABLE cron_jobs DROP COLUMN weekdays;
ALTER TABLE cron_jobs DROP COLUMN date_range_mode;
ALTER TABLE cron_jobs DROP COLUMN start_month;
ALTER TABLE cron_jobs DROP COLUMN start_date;
ALTER TABLE cron_jobs DROP COLUMN end_month;
ALTER TABLE cron_jobs DROP COLUMN end_date;
