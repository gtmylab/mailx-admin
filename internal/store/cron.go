package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// ---- Cron jobs -------------------------------------------------------------

func (s *Store) ListCronJobs(ctx context.Context) ([]models.CronJob, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, schedule, command, enabled, last_run_at, last_status, last_output, created_at, updated_at
		FROM cron_jobs ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list cron jobs: %w", err)
	}
	defer rows.Close()

	var out []models.CronJob
	for rows.Next() {
		var j models.CronJob
		var enabled int
		var lastRun sql.NullTime
		if err := rows.Scan(&j.ID, &j.Name, &j.Schedule, &j.Command, &enabled, &lastRun,
			&j.LastStatus, &j.LastOutput, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan cron job: %w", err)
		}
		j.Enabled = enabled == 1
		if lastRun.Valid {
			t := lastRun.Time
			j.LastRunAt = &t
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) GetCronJob(ctx context.Context, id int64) (*models.CronJob, error) {
	var j models.CronJob
	var enabled int
	var lastRun sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, schedule, command, enabled, last_run_at, last_status, last_output, created_at, updated_at
		FROM cron_jobs WHERE id = ?`, id).
		Scan(&j.ID, &j.Name, &j.Schedule, &j.Command, &enabled, &lastRun,
			&j.LastStatus, &j.LastOutput, &j.CreatedAt, &j.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cron job: %w", err)
	}
	j.Enabled = enabled == 1
	if lastRun.Valid {
		t := lastRun.Time
		j.LastRunAt = &t
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
		INSERT INTO cron_jobs (name, schedule, command, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		j.Name, j.Schedule, j.Command, enabled, now, now)
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
		UPDATE cron_jobs SET name = ?, schedule = ?, command = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		j.Name, j.Schedule, j.Command, enabled, time.Now(), j.ID); err != nil {
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
