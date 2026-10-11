package models

import "time"

// AdminUser is a panel operator account, separate from the mail users table.
type AdminUser struct {
	ID                int64
	Username          string
	PasswordHash      string
	TotpSecret        string
	TotpEnabled       bool
	Role              string // superadmin | admin | operator | readonly
	Active            bool
	DisplayName       string
	Email             string
	AccountType       string // system | panel | both
	SessionTTLMinutes int    // 0 = global default
	GroupID           int64  // 0 = no group
	LastLogin         *time.Time
	CreatedAt         time.Time
}

// AdminGroup is a named role/permission set an admin can belong to.
type AdminGroup struct {
	ID          int64
	Name        string
	Role        string
	Permissions string // JSON array of permission strings
}

// AdminNotification is one notification handle (Slack/Telegram/…) for an admin.
type AdminNotification struct {
	ID          int64
	AdminUserID int64
	Provider    string
	Target      string
	Events      string // JSON array of event names
	Active      bool
}
