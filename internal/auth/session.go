package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

type Session struct {
	ID          string
	AdminUserID int64
	Username    string
	Role        string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	UserAgent   string
	RemoteIP    string
}

type SessionStore struct {
	db     *sql.DB
	maxAge time.Duration
}

func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{
		db:     db,
		maxAge: 24 * time.Hour,
	}
}

// SetMaxAge changes the default session lifetime used by Create.
func (s *SessionStore) SetMaxAge(d time.Duration) {
	if d > 0 {
		s.maxAge = d
	}
}

// Create mints a session with the store's default lifetime.
func (s *SessionStore) Create(ctx context.Context, adminUserID int64, ua, ip string) (*Session, error) {
	return s.CreateWithTTL(ctx, adminUserID, s.maxAge, ua, ip)
}

// CreateWithTTL mints a session that expires after ttl.
func (s *SessionStore) CreateWithTTL(ctx context.Context, adminUserID int64, ttl time.Duration, ua, ip string) (*Session, error) {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	expiresAt := time.Now().Add(ttl)

	_, err := s.db.ExecContext(ctx, `
        INSERT INTO sessions (id, admin_user_id, expires_at, created_at, user_agent, remote_ip)
        VALUES (?, ?, ?, ?, ?, ?)
    `, id, adminUserID, expiresAt, time.Now(), ua, ip)
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}

	return &Session{
		ID:          id,
		AdminUserID: adminUserID,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
		UserAgent:   ua,
		RemoteIP:    ip,
	}, nil
}

func (s *SessionStore) Get(ctx context.Context, id string) (*Session, error) {
	var sess Session
	var ua, ip sql.NullString

	err := s.db.QueryRowContext(ctx, `
        SELECT s.id, s.admin_user_id, a.username, a.role, s.expires_at, s.created_at,
               s.user_agent, s.remote_ip
        FROM sessions s
        JOIN admin_users a ON a.id = s.admin_user_id
        WHERE s.id = ? AND a.active = 1
    `, id).Scan(
		&sess.ID, &sess.AdminUserID, &sess.Username, &sess.Role,
		&sess.ExpiresAt, &sess.CreatedAt, &ua, &ip,
	)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	sess.UserAgent = ua.String
	sess.RemoteIP = ip.String
	return &sess, nil
}

func (s *SessionStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// CleanupExpired removes sessions that have passed their expiry.
// Run this periodically (systemd timer).
func (s *SessionStore) CleanupExpired(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// List returns active (unexpired) sessions, optionally restricted to one admin.
// Pass adminUserID == 0 for every admin.
func (s *SessionStore) List(ctx context.Context, adminUserID int64) ([]Session, error) {
	query := `
		SELECT s.id, s.admin_user_id, a.username, a.role, s.expires_at, s.created_at, s.user_agent, s.remote_ip
		FROM sessions s
		JOIN admin_users a ON a.id = s.admin_user_id
		WHERE s.expires_at > ?`
	args := []any{time.Now()}
	if adminUserID > 0 {
		query += ` AND s.admin_user_id = ?`
		args = append(args, adminUserID)
	}
	query += ` ORDER BY s.created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var sess Session
		var ua, ip sql.NullString
		if err := rows.Scan(&sess.ID, &sess.AdminUserID, &sess.Username, &sess.Role,
			&sess.ExpiresAt, &sess.CreatedAt, &ua, &ip); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sess.UserAgent = ua.String
		sess.RemoteIP = ip.String
		out = append(out, sess)
	}
	return out, rows.Err()
}

// DeleteForUser revokes every session for an admin except the one given (so a
// user can "sign out everywhere else" without dropping their current session).
func (s *SessionStore) DeleteForUser(ctx context.Context, adminUserID int64, exceptID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE admin_user_id = ? AND id <> ?`, adminUserID, exceptID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
