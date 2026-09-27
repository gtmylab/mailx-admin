package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type Entry struct {
	ID         int64
	Ts         time.Time
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	Result     string
	Detail     any
	RemoteIP   string
}

type Logger struct {
	db *sql.DB
}

func New(db *sql.DB) *Logger { return &Logger{db: db} }

func (l *Logger) Log(ctx context.Context, e Entry) error {
	var detailJSON []byte
	if e.Detail != nil {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("marshal audit detail: %w", err)
		}
		detailJSON = b
	}

	_, err := l.db.ExecContext(ctx, `
        INSERT INTO audit_log (ts, actor, action, target_type, target_id, result, detail, remote_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
		time.Now().UTC(),
		e.Actor,
		e.Action,
		nullIfEmpty(e.TargetType),
		nullIfEmpty(e.TargetID),
		e.Result,
		nullIfEmpty(string(detailJSON)),
		nullIfEmpty(e.RemoteIP),
	)
	if err != nil {
		return fmt.Errorf("audit insert: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
