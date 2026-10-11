package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// isBusyErr reports whether err is SQLite's SQLITE_BUSY ("database is locked").
func isBusyErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "database is locked")
}

// retryBusy retries a short-lived write when SQLite reports "database is locked".
// SQLITE_BUSY is transient — the writer holding the lock commits within
// milliseconds — so a short backoff beats surfacing a 500 under contention.
// Callers must only use it for idempotent, short statements.
func retryBusy(fn func() error) error {
	const attempts = 3
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); !isBusyErr(err) {
			return err
		}
		time.Sleep(time.Duration(i+1) * 50 * time.Millisecond)
	}
	return err
}

// exec runs a single write statement, retrying transient "database is locked".
// It is the retrying twin of s.db.ExecContext and returns the same shape, so a
// short request-scoped write can swap one for the other without any other change.
func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var res sql.Result
	err := retryBusy(func() error {
		var err error
		res, err = s.db.ExecContext(ctx, query, args...)
		return err
	})
	return res, err
}
