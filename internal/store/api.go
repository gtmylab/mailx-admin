package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// ---- Transactional messages -------------------------------------------------

func (s *Store) InsertAPIMessage(ctx context.Context, m models.APIMessage) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO api_messages
		  (api_key_id, message_id, from_addr, to_addr, cc, bcc, reply_to, subject,
		   tag, template, headers, attachments, status, error, idempotency_key, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullInt(m.APIKeyID), m.MessageID, m.FromAddr, m.ToAddr, m.CC, m.BCC,
		m.ReplyTo, m.Subject, m.Tag, m.Template, m.Headers, m.Attachments,
		m.Status, m.Error, m.IdempotencyKey, time.Now())
	if err != nil {
		return 0, fmt.Errorf("insert api message: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) APIMessageByMessageID(ctx context.Context, messageID string) (*models.APIMessage, error) {
	var m models.APIMessage
	var keyID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, api_key_id, message_id, from_addr, to_addr, cc, bcc, reply_to,
		       subject, tag, template, headers, attachments, status, error,
		       idempotency_key, created_at
		FROM api_messages WHERE message_id = ?`, messageID).Scan(
		&m.ID, &keyID, &m.MessageID, &m.FromAddr, &m.ToAddr, &m.CC, &m.BCC,
		&m.ReplyTo, &m.Subject, &m.Tag, &m.Template, &m.Headers, &m.Attachments,
		&m.Status, &m.Error, &m.IdempotencyKey, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	m.APIKeyID = keyID
	return &m, nil
}

// APIMessageByIdempotency returns a message previously sent under the same key
// and idempotency key, so a retried request is not sent twice.
func (s *Store) APIMessageByIdempotency(ctx context.Context, keyID int64, idem string) (*models.APIMessage, error) {
	var m models.APIMessage
	var k sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, api_key_id, message_id, from_addr, to_addr, cc, bcc, reply_to,
		       subject, tag, template, headers, attachments, status, error,
		       idempotency_key, created_at
		FROM api_messages WHERE api_key_id = ? AND idempotency_key = ?`, keyID, idem).Scan(
		&m.ID, &k, &m.MessageID, &m.FromAddr, &m.ToAddr, &m.CC, &m.BCC,
		&m.ReplyTo, &m.Subject, &m.Tag, &m.Template, &m.Headers, &m.Attachments,
		&m.Status, &m.Error, &m.IdempotencyKey, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	m.APIKeyID = k
	return &m, nil
}

func (s *Store) ListAPIMessages(ctx context.Context, since time.Time, tag string, limit int) ([]models.APIMessage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, api_key_id, message_id, from_addr, to_addr, cc, bcc, reply_to,
	                 subject, tag, template, headers, attachments, status, error,
	                 idempotency_key, created_at
	          FROM api_messages WHERE created_at >= ?`
	args := []any{since}
	if tag != "" {
		query += ` AND tag = ?`
		args = append(args, tag)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list api messages: %w", err)
	}
	defer rows.Close()

	var out []models.APIMessage
	for rows.Next() {
		var m models.APIMessage
		var k sql.NullInt64
		if err := rows.Scan(&m.ID, &k, &m.MessageID, &m.FromAddr, &m.ToAddr, &m.CC,
			&m.BCC, &m.ReplyTo, &m.Subject, &m.Tag, &m.Template, &m.Headers,
			&m.Attachments, &m.Status, &m.Error, &m.IdempotencyKey, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api message: %w", err)
		}
		m.APIKeyID = k
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---- Templates ---------------------------------------------------------------

func (s *Store) InsertAPITemplate(ctx context.Context, t models.APITemplate) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO api_templates (name, subject, text, html, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		t.Name, t.Subject, t.Text, t.HTML, time.Now(), time.Now())
	if err != nil {
		return 0, fmt.Errorf("insert api template: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) UpdateAPITemplate(ctx context.Context, t models.APITemplate) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE api_templates SET subject = ?, text = ?, html = ?, updated_at = ?
		WHERE name = ?`, t.Subject, t.Text, t.HTML, time.Now(), t.Name)
	if err != nil {
		return fmt.Errorf("update api template: %w", err)
	}
	return nil
}

func (s *Store) APITemplateByName(ctx context.Context, name string) (*models.APITemplate, error) {
	var t models.APITemplate
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, subject, text, html, created_at, updated_at
		FROM api_templates WHERE name = ?`, name).Scan(
		&t.ID, &t.Name, &t.Subject, &t.Text, &t.HTML, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) APITemplates(ctx context.Context) ([]models.APITemplate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, subject, text, html, created_at, updated_at
		FROM api_templates ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list api templates: %w", err)
	}
	defer rows.Close()

	var out []models.APITemplate
	for rows.Next() {
		var t models.APITemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Subject, &t.Text, &t.HTML, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan api template: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAPITemplate(ctx context.Context, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_templates WHERE name = ?`, name)
	if err != nil {
		return false, fmt.Errorf("delete api template: %w", err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func nullInt(n sql.NullInt64) any {
	if n.Valid {
		return n.Int64
	}
	return nil
}

// MarkAPIMessageFailed flips a message to "failed" and records the error, for
// when sendmail rejects the message after it was recorded.
func (s *Store) MarkAPIMessageFailed(ctx context.Context, id int64, msg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_messages SET status = 'failed', error = ? WHERE id = ?`, msg, id)
	return err
}
