package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// ---- Admin users -----------------------------------------------------------

const adminUserColumns = `id, username, password_hash, totp_secret, totp_enabled, role, active,
	display_name, email, account_type, session_ttl_minutes, group_id, last_login, created_at`

func scanAdminUser(scan func(...any) error, a *models.AdminUser) error {
	var totpEnabled, active int
	var totpSecret sql.NullString
	var lastLogin sql.NullTime
	var ttl, groupID sql.NullInt64
	if err := scan(&a.ID, &a.Username, &a.PasswordHash, &totpSecret, &totpEnabled, &a.Role, &active,
		&a.DisplayName, &a.Email, &a.AccountType, &ttl, &groupID, &lastLogin, &a.CreatedAt); err != nil {
		return err
	}
	a.TotpSecret = totpSecret.String
	a.TotpEnabled = totpEnabled == 1
	a.Active = active == 1
	if ttl.Valid {
		a.SessionTTLMinutes = int(ttl.Int64)
	}
	if groupID.Valid {
		a.GroupID = groupID.Int64
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		a.LastLogin = &t
	}
	return nil
}

func (s *Store) ListAdminUsers(ctx context.Context) ([]models.AdminUser, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+adminUserColumns+` FROM admin_users ORDER BY username ASC`)
	if err != nil {
		return nil, fmt.Errorf("list admin users: %w", err)
	}
	defer rows.Close()
	var out []models.AdminUser
	for rows.Next() {
		var a models.AdminUser
		if err := scanAdminUser(rows.Scan, &a); err != nil {
			return nil, fmt.Errorf("scan admin user: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAdminUser(ctx context.Context, id int64) (*models.AdminUser, error) {
	var a models.AdminUser
	err := scanAdminUser(s.db.QueryRowContext(ctx, `SELECT `+adminUserColumns+` FROM admin_users WHERE id = ?`, id).Scan, &a)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get admin user: %w", err)
	}
	return &a, nil
}

func (s *Store) InsertAdminUser(ctx context.Context, a models.AdminUser) (int64, error) {
	totpEnabled, active := 0, 0
	if a.TotpEnabled {
		totpEnabled = 1
	}
	if a.Active {
		active = 1
	}
	var totpSecret, ttl, groupID any
	if a.TotpSecret != "" {
		totpSecret = a.TotpSecret
	}
	if a.SessionTTLMinutes > 0 {
		ttl = a.SessionTTLMinutes
	}
	if a.GroupID > 0 {
		groupID = a.GroupID
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_users (username, password_hash, totp_secret, totp_enabled, role, active,
		  display_name, email, account_type, session_ttl_minutes, group_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.Username, a.PasswordHash, totpSecret, totpEnabled, a.Role, active,
		a.DisplayName, a.Email, a.AccountType, ttl, groupID, time.Now())
	if err != nil {
		return 0, fmt.Errorf("insert admin user: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) UpdateAdminUser(ctx context.Context, a models.AdminUser) error {
	active := 0
	if a.Active {
		active = 1
	}
	var ttl, groupID any
	if a.SessionTTLMinutes > 0 {
		ttl = a.SessionTTLMinutes
	}
	if a.GroupID > 0 {
		groupID = a.GroupID
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE admin_users SET role = ?, active = ?, display_name = ?, email = ?,
		  account_type = ?, session_ttl_minutes = ?, group_id = ? WHERE id = ?`,
		a.Role, active, a.DisplayName, a.Email, a.AccountType, ttl, groupID, a.ID)
	if err != nil {
		return fmt.Errorf("update admin user: %w", err)
	}
	return nil
}

func (s *Store) SetAdminUserPassword(ctx context.Context, id int64, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE admin_users SET password_hash = ? WHERE id = ?`, hash, id)
	return err
}

func (s *Store) SetAdminUserTOTP(ctx context.Context, id int64, secret string, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	var sec any
	if secret != "" {
		sec = secret
	}
	_, err := s.db.ExecContext(ctx, `UPDATE admin_users SET totp_secret = ?, totp_enabled = ? WHERE id = ?`, sec, e, id)
	return err
}

func (s *Store) SetAdminUserActive(ctx context.Context, id int64, active bool) error {
	a := 0
	if active {
		a = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE admin_users SET active = ? WHERE id = ?`, a, id)
	return err
}

func (s *Store) DeleteAdminUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_users WHERE id = ?`, id)
	return err
}

// ---- Admin groups -----------------------------------------------------------

func (s *Store) ListAdminGroups(ctx context.Context) ([]models.AdminGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, role, permissions FROM admin_groups ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list admin groups: %w", err)
	}
	defer rows.Close()
	var out []models.AdminGroup
	for rows.Next() {
		var g models.AdminGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Role, &g.Permissions); err != nil {
			return nil, fmt.Errorf("scan admin group: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) InsertAdminGroup(ctx context.Context, g models.AdminGroup) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO admin_groups (name, role, permissions) VALUES (?, ?, ?)`,
		g.Name, g.Role, g.Permissions)
	if err != nil {
		return 0, fmt.Errorf("insert admin group: %w", err)
	}
	return res.LastInsertId()
}

// ---- Admin notifications ----------------------------------------------------

func (s *Store) ListAdminNotifications(ctx context.Context, adminUserID int64) ([]models.AdminNotification, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, admin_user_id, provider, target, events, active
		FROM admin_user_notifications WHERE admin_user_id = ? ORDER BY id ASC`, adminUserID)
	if err != nil {
		return nil, fmt.Errorf("list admin notifications: %w", err)
	}
	defer rows.Close()
	var out []models.AdminNotification
	for rows.Next() {
		var n models.AdminNotification
		var active int
		if err := rows.Scan(&n.ID, &n.AdminUserID, &n.Provider, &n.Target, &n.Events, &active); err != nil {
			return nil, fmt.Errorf("scan admin notification: %w", err)
		}
		n.Active = active == 1
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) InsertAdminNotification(ctx context.Context, n models.AdminNotification) (int64, error) {
	active := 0
	if n.Active {
		active = 1
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_user_notifications (admin_user_id, provider, target, events, active)
		VALUES (?, ?, ?, ?, ?)`, n.AdminUserID, n.Provider, n.Target, n.Events, active)
	if err != nil {
		return 0, fmt.Errorf("insert admin notification: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) DeleteAdminNotification(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_user_notifications WHERE id = ?`, id)
	return err
}

func (s *Store) SetAdminNotificationActive(ctx context.Context, id int64, active bool) error {
	a := 0
	if active {
		a = 1
	}
	_, err := s.db.ExecContext(ctx, `UPDATE admin_user_notifications SET active = ? WHERE id = ?`, a, id)
	return err
}

func (s *Store) GetAdminGroup(ctx context.Context, id int64) (*models.AdminGroup, error) {
	var g models.AdminGroup
	err := s.db.QueryRowContext(ctx, `SELECT id, name, role, permissions FROM admin_groups WHERE id = ?`, id).
		Scan(&g.ID, &g.Name, &g.Role, &g.Permissions)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get admin group: %w", err)
	}
	return &g, nil
}

func (s *Store) UpdateAdminGroup(ctx context.Context, g models.AdminGroup) error {
	_, err := s.db.ExecContext(ctx, `UPDATE admin_groups SET name = ?, role = ?, permissions = ? WHERE id = ?`,
		g.Name, g.Role, g.Permissions, g.ID)
	if err != nil {
		return fmt.Errorf("update admin group: %w", err)
	}
	return nil
}

func (s *Store) DeleteAdminGroup(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE admin_users SET group_id = NULL WHERE group_id = ?`, id); err != nil {
		return fmt.Errorf("clear group members: %w", err)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete admin group: %w", err)
	}
	return nil
}
