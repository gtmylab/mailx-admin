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

func (s *SessionStore) Create(ctx context.Context, adminUserID int64, ua, ip string) (*Session, error) {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	expiresAt := time.Now().Add(s.maxAge)

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
