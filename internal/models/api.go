package models

import (
	"database/sql"
	"time"
)

// APIMessage is one transactional message sent through the public API. The
// structured fields (To, CC, BCC, Headers, Attachments) are stored as JSON
// strings so the schema stays identical on SQLite and Postgres.
type APIMessage struct {
	ID             int64
	APIKeyID       sql.NullInt64
	MessageID      string
	FromAddr       string
	ToAddr         string // JSON array
	CC             string // JSON array
	BCC            string // JSON array
	ReplyTo        string
	Subject        string
	Tag            string
	Template       string
	Headers        string // JSON object
	Attachments    string // JSON array
	Status         string // "queued" | "failed"
	Error          string
	IdempotencyKey sql.NullString
	CreatedAt      time.Time
}

// APITemplate is a named transactional email template rendered with variables
// at send time.
type APITemplate struct {
	ID        int64
	Name      string
	Subject   string
	Text      string
	HTML      string
	CreatedAt time.Time
	UpdatedAt time.Time
}
