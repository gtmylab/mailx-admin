package syncer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gtmylab/mailx-admin/internal/reconciler"
)

// ---------------------------------------------------------------------------
// SQL recorder
// ---------------------------------------------------------------------------

// sqlRecorder writes run history to reconcile_runs (created in 001, extended
// with the drift column in 005).
type sqlRecorder struct{ db *sql.DB }

func (r sqlRecorder) begin(ctx context.Context, run Run) (int64, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, `
        INSERT INTO reconcile_runs (trigger, dry_run, status)
        VALUES (?, ?, 'running')
        RETURNING id
    `, run.Trigger, boolInt(run.DryRun)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("record sync start: %w", err)
	}
	return id, nil
}

func (r sqlRecorder) finish(ctx context.Context, id int64, res *reconciler.Result, runErr error) error {
	status := "ok"
	var errText any
	if runErr != nil {
		status = "error"
		errText = runErr.Error()
	}

	var changes []reconciler.FileChange
	var drift []reconciler.Drift
	if res != nil {
		changes = res.Changes
		drift = res.Drift
	}
	files, _ := json.Marshal(changes)
	driftJSON, _ := json.Marshal(drift)

	_, err := r.db.ExecContext(ctx, `
        UPDATE reconcile_runs
        SET finished_at = ?, status = ?, files_changed = ?, drift = ?, error = ?
        WHERE id = ?
    `, time.Now().UTC(), status, string(files), string(driftJSON), errText, id)
	if err != nil {
		return fmt.Errorf("record sync result: %w", err)
	}
	return nil
}

const runColumns = `id, started_at, finished_at, trigger, dry_run, status, files_changed, drift, error`

func (r sqlRecorder) latest(ctx context.Context) (*Run, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+runColumns+` FROM reconcile_runs ORDER BY id DESC LIMIT 1`)
	return scanRun(row)
}

func (r sqlRecorder) history(ctx context.Context, limit int) ([]Run, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+runColumns+` FROM reconcile_runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("read sync history: %w", err)
	}
	defer rows.Close()

	var out []Run
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		if run != nil {
			out = append(out, *run)
		}
	}
	return out, rows.Err()
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRun(row rowScanner) (*Run, error) {
	var (
		run        Run
		finished   sql.NullTime
		dryRun     int
		files      sql.NullString
		drift      sql.NullString
		errText    sql.NullString
		startedRaw any
	)
	if err := row.Scan(&run.ID, &startedRaw, &finished, &run.Trigger,
		&dryRun, &run.Status, &files, &drift, &errText); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan sync run: %w", err)
	}

	// SQLite hands TIMESTAMP columns back as text unless the driver registered a
	// converter for the declared type, so accept both shapes.
	switch t := startedRaw.(type) {
	case time.Time:
		run.StartedAt = t
	case string:
		run.StartedAt = parseTime(t)
	case []byte:
		run.StartedAt = parseTime(string(t))
	}
	if finished.Valid {
		run.FinishedAt = &finished.Time
	}
	run.DryRun = dryRun == 1
	if files.Valid && files.String != "" {
		_ = json.Unmarshal([]byte(files.String), &run.Files)
	}
	if drift.Valid && drift.String != "" {
		_ = json.Unmarshal([]byte(drift.String), &run.Drift)
	}
	if errText.Valid {
		run.Error = errText.String
	}
	return &run, nil
}

func parseTime(s string) time.Time {
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
