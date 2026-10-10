package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// ---- Cron jobs -------------------------------------------------------------

// cronJobColumns is the shared column list for scanning a cron job row.
const cronJobColumns = `id, name, schedule, command, enabled, run_as, input, description,
	simple_schedule, schedule_mode, minutes, hours, days, months, weekdays,
	date_range_mode, start_month, start_date, end_month, end_date,
	last_run_at, last_status, last_output, created_at, updated_at`

// cronSetCSV serializes a CronValueSet as a sorted, comma-separated string.
func cronSetCSV(s models.CronValueSet) string {
	if len(s) == 0 {
		return ""
	}
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// cronSetFromCSV parses a comma-separated string back into a CronValueSet.
func cronSetFromCSV(csv string) models.CronValueSet {
	s := models.CronValueSet{}
	for _, part := range strings.Split(csv, ",") {
		if part = strings.TrimSpace(part); part != "" {
			s[part] = true
		}
	}
	return s
}

// scanCronJob scans one cron_jobs row (in cronJobColumns order) into j.
func scanCronJob(scan func(dest ...any) error, j *models.CronJob) error {
	var enabled int
	var lastRun sql.NullTime
	var minutes, hours, days, months, weekdays string
	if err := scan(&j.ID, &j.Name, &j.Schedule, &j.Command, &enabled, &j.RunAs, &j.Input, &j.Description,
		&j.SimpleSchedule, &j.ScheduleMode, &minutes, &hours, &days, &months, &weekdays,
		&j.DateRangeMode, &j.StartMonth, &j.StartDate, &j.EndMonth, &j.EndDate,
		&lastRun, &j.LastStatus, &j.LastOutput, &j.CreatedAt, &j.UpdatedAt); err != nil {
		return err
	}
	j.Enabled = enabled == 1
	if lastRun.Valid {
		t := lastRun.Time
		j.LastRunAt = &t
	}
	j.Minutes = cronSetFromCSV(minutes)
	j.Hours = cronSetFromCSV(hours)
	j.Days = cronSetFromCSV(days)
	j.Months = cronSetFromCSV(months)
	j.Weekdays = cronSetFromCSV(weekdays)
	return nil
}

func (s *Store) ListCronJobs(ctx context.Context) ([]models.CronJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cronJobColumns+` FROM cron_jobs ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list cron jobs: %w", err)
	}
	defer rows.Close()

	var out []models.CronJob
	for rows.Next() {
		var j models.CronJob
		if err := scanCronJob(rows.Scan, &j); err != nil {
			return nil, fmt.Errorf("scan cron job: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) GetCronJob(ctx context.Context, id int64) (*models.CronJob, error) {
	var j models.CronJob
	err := scanCronJob(s.db.QueryRowContext(ctx, `SELECT `+cronJobColumns+` FROM cron_jobs WHERE id = ?`, id).Scan, &j)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cron job: %w", err)
	}
	return &j, nil
}

func (s *Store) InsertCronJob(ctx context.Context, j models.CronJob) (int64, error) {
	enabled := 0
	if j.Enabled {
		enabled = 1
	}
	now := time.Now()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO cron_jobs (name, schedule, command, enabled, run_as, input, description,
		  simple_schedule, schedule_mode, minutes, hours, days, months, weekdays,
		  date_range_mode, start_month, start_date, end_month, end_date, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.Name, j.Schedule, j.Command, enabled, j.RunAs, j.Input, j.Description,
		j.SimpleSchedule, j.ScheduleMode,
		cronSetCSV(j.Minutes), cronSetCSV(j.Hours), cronSetCSV(j.Days), cronSetCSV(j.Months), cronSetCSV(j.Weekdays),
		j.DateRangeMode, j.StartMonth, j.StartDate, j.EndMonth, j.EndDate, now, now)
	if err != nil {
		return 0, fmt.Errorf("insert cron job: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) UpdateCronJob(ctx context.Context, j models.CronJob) error {
	enabled := 0
	if j.Enabled {
		enabled = 1
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE cron_jobs SET name = ?, schedule = ?, command = ?, enabled = ?, run_as = ?,
		  input = ?, description = ?, simple_schedule = ?, schedule_mode = ?, minutes = ?,
		  hours = ?, days = ?, months = ?, weekdays = ?, date_range_mode = ?, start_month = ?,
		  start_date = ?, end_month = ?, end_date = ?, updated_at = ?
		WHERE id = ?`,
		j.Name, j.Schedule, j.Command, enabled, j.RunAs, j.Input, j.Description,
		j.SimpleSchedule, j.ScheduleMode,
		cronSetCSV(j.Minutes), cronSetCSV(j.Hours), cronSetCSV(j.Days), cronSetCSV(j.Months), cronSetCSV(j.Weekdays),
		j.DateRangeMode, j.StartMonth, j.StartDate, j.EndMonth, j.EndDate, time.Now(), j.ID); err != nil {
		return fmt.Errorf("update cron job: %w", err)
	}
	return nil
}

func (s *Store) SetCronJobEnabled(ctx context.Context, id int64, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE cron_jobs SET enabled = ?, updated_at = ? WHERE id = ?`, e, time.Now(), id); err != nil {
		return fmt.Errorf("set cron job enabled: %w", err)
	}
	return nil
}

func (s *Store) DeleteCronJob(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM cron_jobs WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete cron job: %w", err)
	}
	return nil
}

// MarkCronRun records the outcome of a job execution for the panel.
func (s *Store) MarkCronRun(ctx context.Context, id int64, status, output string) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE cron_jobs SET last_run_at = ?, last_status = ?, last_output = ? WHERE id = ?`,
		time.Now(), status, output, id); err != nil {
		return fmt.Errorf("mark cron run: %w", err)
	}
	return nil
}
