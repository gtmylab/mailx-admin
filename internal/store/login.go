package store

import (
	"context"
	"time"
)

// RecordLoginAttempt records a successful or failed panel login for the
// brute-force lockout check in the login handler.
func (s *Store) RecordLoginAttempt(ctx context.Context, username, ip string, success bool) error {
	v := 0
	if success {
		v = 1
	}
	_, err := s.exec(ctx, `
		INSERT INTO login_attempts (username, remote_ip, success, attempted_at)
		VALUES (?, ?, ?, ?)`, username, ip, v, time.Now())
	return err
}

// CountRecentFailedLogins returns how many failed attempts there have been for
// username since the given time.
func (s *Store) CountRecentFailedLogins(ctx context.Context, username string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM login_attempts
		WHERE username = ? AND success = 0 AND attempted_at > ?`, username, since).Scan(&n)
	return n, err
}
