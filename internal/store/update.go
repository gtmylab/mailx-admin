package store

import (
	"context"
	"fmt"
	"time"
)

// UpdateCheck is one recorded release-check result.
type UpdateCheck struct {
	CheckedAt time.Time
	Current   string
	Latest    string
	Available bool
	UpToDate  bool
	Error     string
	Notes     string
}

// RecordUpdateCheck stores the result of a release check so the Updates page can
// show a history of what was checked and when.
func (s *Store) RecordUpdateCheck(ctx context.Context, c UpdateCheck) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO update_checks (checked_at, current, latest, available, up_to_date, error, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, c.CheckedAt, c.Current, c.Latest, btoi(c.Available), btoi(c.UpToDate), c.Error, c.Notes)
	if err != nil {
		return fmt.Errorf("record update check: %w", err)
	}
	return nil
}

// ListUpdateChecks returns the most recent release checks, newest first.
func (s *Store) ListUpdateChecks(ctx context.Context, limit int) ([]UpdateCheck, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT checked_at, current, latest, available, up_to_date, error, notes
		FROM update_checks ORDER BY checked_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list update checks: %w", err)
	}
	defer rows.Close()

	var out []UpdateCheck
	for rows.Next() {
		var c UpdateCheck
		var available, upToDate int
		if err := rows.Scan(&c.CheckedAt, &c.Current, &c.Latest, &available, &upToDate, &c.Error, &c.Notes); err != nil {
			return nil, fmt.Errorf("scan update check: %w", err)
		}
		c.Available = available == 1
		c.UpToDate = upToDate == 1
		out = append(out, c)
	}
	return out, rows.Err()
}
