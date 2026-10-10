package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// btoi encodes a bool the way SQLite stores it.
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- Outbound IPs ----------------------------------------------------------

func (s *Store) ListOutboundIPs(ctx context.Context) ([]models.OutboundIP, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, ip, mode, priority, active, ptr_ok, ptr_record, notes, created_at, updated_at
        FROM outbound_ips ORDER BY priority DESC, ip ASC`)
	if err != nil {
		return nil, fmt.Errorf("list outbound ips: %w", err)
	}
	defer rows.Close()

	var out []models.OutboundIP
	for rows.Next() {
		var ip models.OutboundIP
		var active int
		var ptrOK sql.NullInt64
		if err := rows.Scan(&ip.ID, &ip.IP, &ip.Mode, &ip.Priority, &active,
			&ptrOK, &ip.PTRRecord, &ip.Notes, &ip.CreatedAt, &ip.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan outbound ip: %w", err)
		}
		ip.Active = active == 1
		if ptrOK.Valid {
			b := ptrOK.Int64 == 1
			ip.PTROK = &b
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

func (s *Store) ListOutboundRules(ctx context.Context, ipID int64) ([]models.OutboundRule, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, ip_id, match_type, match_value, priority
        FROM outbound_rules WHERE ip_id = ? ORDER BY priority DESC, id ASC`, ipID)
	if err != nil {
		return nil, fmt.Errorf("list outbound rules: %w", err)
	}
	defer rows.Close()

	var out []models.OutboundRule
	for rows.Next() {
		var r models.OutboundRule
		if err := rows.Scan(&r.ID, &r.IPID, &r.MatchType, &r.MatchValue, &r.Priority); err != nil {
			return nil, fmt.Errorf("scan outbound rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) InsertOutboundIP(ctx context.Context, ip models.OutboundIP) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
        INSERT INTO outbound_ips (ip, mode, priority, active, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ip.IP, ip.Mode, ip.Priority, btoi(ip.Active), ip.Notes, time.Now(), time.Now())
	if err != nil {
		return 0, fmt.Errorf("insert outbound ip: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) UpdateOutboundIP(ctx context.Context, ip models.OutboundIP) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE outbound_ips SET mode = ?, priority = ?, active = ?, notes = ?, updated_at = ?
        WHERE id = ?`,
		ip.Mode, ip.Priority, btoi(ip.Active), ip.Notes, time.Now(), ip.ID)
	if err != nil {
		return fmt.Errorf("update outbound ip: %w", err)
	}
	return nil
}

func (s *Store) SetOutboundIPPTR(ctx context.Context, id int64, ok bool, record string) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE outbound_ips SET ptr_ok = ?, ptr_record = ?, updated_at = ? WHERE id = ?`,
		btoi(ok), record, time.Now(), id)
	if err != nil {
		return fmt.Errorf("set outbound ip ptr: %w", err)
	}
	return nil
}

func (s *Store) DeleteOutboundIP(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM outbound_ips WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete outbound ip: %w", err)
	}
	return nil
}

func (s *Store) InsertOutboundRule(ctx context.Context, r models.OutboundRule) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
        INSERT INTO outbound_rules (ip_id, match_type, match_value, priority) VALUES (?, ?, ?, ?)`,
		r.IPID, r.MatchType, r.MatchValue, r.Priority)
	if err != nil {
		return 0, fmt.Errorf("insert outbound rule: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) DeleteOutboundRule(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM outbound_rules WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete outbound rule: %w", err)
	}
	return nil
}

// ---- Suppressions ----------------------------------------------------------

func (s *Store) ListSuppressions(ctx context.Context) ([]models.Suppression, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, email, reason, source, notes, created_at, expires_at, direction, match_type
        FROM suppressions ORDER BY direction ASC, email ASC`)
	if err != nil {
		return nil, fmt.Errorf("list suppressions: %w", err)
	}
	defer rows.Close()

	var out []models.Suppression
	for rows.Next() {
		var sup models.Suppression
		var expires sql.NullTime
		if err := rows.Scan(&sup.ID, &sup.Email, &sup.Reason, &sup.Source, &sup.Notes, &sup.CreatedAt, &expires, &sup.Direction, &sup.MatchType); err != nil {
			return nil, fmt.Errorf("scan suppression: %w", err)
		}
		if expires.Valid {
			sup.ExpiresAt = &expires.Time
		}
		out = append(out, sup)
	}
	return out, rows.Err()
}

func (s *Store) InsertSuppression(ctx context.Context, sup models.Suppression) (int64, error) {
	if sup.Direction == "" {
		sup.Direction = "out"
	}
	if sup.MatchType == "" {
		sup.MatchType = "email"
	}
	var expires any
	if sup.ExpiresAt != nil {
		expires = *sup.ExpiresAt
	}
	res, err := s.db.ExecContext(ctx, `
        INSERT INTO suppressions (email, reason, source, notes, created_at, expires_at, direction, match_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET reason = excluded.reason, source = excluded.source,
            notes = excluded.notes, expires_at = excluded.expires_at,
            direction = excluded.direction, match_type = excluded.match_type`,
		sup.Email, sup.Reason, sup.Source, sup.Notes, time.Now(), expires, sup.Direction, sup.MatchType)
	if err != nil {
		return 0, fmt.Errorf("insert suppression: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) DeleteSuppression(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM suppressions WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete suppression: %w", err)
	}
	return nil
}

// DeleteSuppressionByEmail removes a suppression by its (case-insensitive) email
// address and reports whether a row was actually deleted, so an API caller can
// tell "removed" from "was not there".
func (s *Store) DeleteSuppressionByEmail(ctx context.Context, email string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM suppressions WHERE LOWER(email) = LOWER(?)`, email)
	if err != nil {
		return false, fmt.Errorf("delete suppression by email: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("delete suppression by email: %w", err)
	}
	return n > 0, nil
}

// ---- Quota samples ---------------------------------------------------------

func (s *Store) InsertQuotaSample(ctx context.Context, userID int64, bytesUsed int64, messages int) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO quota_samples (user_id, bytes_used, messages, sampled_at) VALUES (?, ?, ?, ?)`,
		userID, bytesUsed, messages, time.Now())
	if err != nil {
		return fmt.Errorf("insert quota sample: %w", err)
	}
	return nil
}

func (s *Store) QuotaSamples(ctx context.Context, userID int64, since time.Time) ([]models.QuotaSample, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, bytes_used, messages, sampled_at
        FROM quota_samples WHERE user_id = ? AND sampled_at >= ? ORDER BY sampled_at ASC`, userID, since)
	if err != nil {
		return nil, fmt.Errorf("list quota samples: %w", err)
	}
	defer rows.Close()

	var out []models.QuotaSample
	for rows.Next() {
		var q models.QuotaSample
		if err := rows.Scan(&q.ID, &q.UserID, &q.BytesUsed, &q.Messages, &q.SampledAt); err != nil {
			return nil, fmt.Errorf("scan quota sample: %w", err)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// ---- Blocklist checks ------------------------------------------------------

func (s *Store) InsertBlocklistCheck(ctx context.Context, list, zone, ip, status, detail string) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO blocklist_checks (list, zone, ip, status, detail, checked_at) VALUES (?, ?, ?, ?, ?, ?)`,
		list, zone, ip, status, detail, time.Now())
	if err != nil {
		return fmt.Errorf("insert blocklist check: %w", err)
	}
	return nil
}

// LatestBlocklistStatus returns the most recent check per (list, ip).
func (s *Store) LatestBlocklistStatus(ctx context.Context) ([]models.BlocklistCheck, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT b.id, b.list, b.zone, b.ip, b.status, b.detail, b.checked_at
        FROM blocklist_checks b
        JOIN (
            SELECT list, ip, MAX(id) AS max_id FROM blocklist_checks GROUP BY list, ip
        ) latest ON latest.max_id = b.id
        ORDER BY b.ip ASC, b.list ASC`)
	if err != nil {
		return nil, fmt.Errorf("latest blocklist status: %w", err)
	}
	defer rows.Close()

	var out []models.BlocklistCheck
	for rows.Next() {
		var b models.BlocklistCheck
		if err := rows.Scan(&b.ID, &b.List, &b.Zone, &b.IP, &b.Status, &b.Detail, &b.CheckedAt); err != nil {
			return nil, fmt.Errorf("scan blocklist check: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ---- API keys --------------------------------------------------------------

func (s *Store) ListAPIKeys(ctx context.Context) ([]models.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, name, prefix, key_hash, scopes, active, created_at, last_used_at, expires_at
        FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var out []models.APIKey
	for rows.Next() {
		var k models.APIKey
		var active int
		var lastUsed, expires sql.NullTime
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.KeyHash, &k.Scopes, &active,
			&k.CreatedAt, &lastUsed, &expires); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		k.Active = active == 1
		if lastUsed.Valid {
			k.LastUsedAt = &lastUsed.Time
		}
		if expires.Valid {
			k.ExpiresAt = &expires.Time
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) InsertAPIKey(ctx context.Context, k models.APIKey) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
        INSERT INTO api_keys (name, prefix, key_hash, scopes, active, created_at)
        VALUES (?, ?, ?, ?, ?, ?)`,
		k.Name, k.Prefix, k.KeyHash, k.Scopes, btoi(k.Active), time.Now())
	if err != nil {
		return 0, fmt.Errorf("insert api key: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) DeleteAPIKey(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}
	return nil
}

func (s *Store) APIKeyByHash(ctx context.Context, hash string) (*models.APIKey, error) {
	var k models.APIKey
	var active int
	var lastUsed, expires sql.NullTime
	err := s.db.QueryRowContext(ctx, `
        SELECT id, name, prefix, key_hash, scopes, active, created_at, last_used_at, expires_at
        FROM api_keys WHERE key_hash = ?`, hash).Scan(
		&k.ID, &k.Name, &k.Prefix, &k.KeyHash, &k.Scopes, &active,
		&k.CreatedAt, &lastUsed, &expires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("api key by hash: %w", err)
	}
	k.Active = active == 1
	if lastUsed.Valid {
		k.LastUsedAt = &lastUsed.Time
	}
	if expires.Valid {
		k.ExpiresAt = &expires.Time
	}
	return &k, nil
}

func (s *Store) TouchAPIKey(ctx context.Context, id int64) {
	_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now(), id)
}

// ---- Webhooks --------------------------------------------------------------

func (s *Store) ListWebhooks(ctx context.Context) ([]models.Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, url, events, secret, active, created_at FROM webhooks ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	var out []models.Webhook
	for rows.Next() {
		var w models.Webhook
		var events string
		var active int
		if err := rows.Scan(&w.ID, &w.URL, &events, &w.Secret, &active, &w.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		if events != "" {
			w.Events = strings.Split(events, ",")
		}
		w.Active = active == 1
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) InsertWebhook(ctx context.Context, w models.Webhook) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
        INSERT INTO webhooks (url, events, secret, active, created_at) VALUES (?, ?, ?, ?, ?)`,
		w.URL, strings.Join(w.Events, ","), w.Secret, btoi(w.Active), time.Now())
	if err != nil {
		return 0, fmt.Errorf("insert webhook: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) DeleteWebhook(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	return nil
}

func (s *Store) InsertWebhookDelivery(ctx context.Context, d models.WebhookDelivery) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO webhook_deliveries (webhook_id, event, payload, success, status_code, response, attempted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.WebhookID, d.Event, d.Payload, btoi(d.Success), d.StatusCode, d.Response, time.Now())
	if err != nil {
		return fmt.Errorf("insert webhook delivery: %w", err)
	}
	return nil
}

// ---- Deliverability (aggregated from the mail-log ingester's mail_events) ---

// DeliverabilityMetric is one (recipient domain, status) aggregate.
type DeliverabilityMetric struct {
	Domain string
	Status string
	Count  int64
}

// Deliverability returns sent/deferred/bounced counts grouped by recipient
// domain since the given time. mail_events is populated in real time by
// internal/logs, so this is the single source of truth for the dashboard.
// listOutboundIPsTx loads the outbound registry (with its rules) inside a
// transaction, for the reconciler's snapshot.
func (s *Store) listOutboundIPsTx(ctx context.Context, tx *sql.Tx) ([]models.OutboundIP, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT id, ip, mode, priority, active, ptr_ok, ptr_record, notes, created_at, updated_at
        FROM outbound_ips ORDER BY priority DESC, ip ASC`)
	if err != nil {
		return nil, fmt.Errorf("list outbound ips: %w", err)
	}
	defer rows.Close()

	var ips []models.OutboundIP
	for rows.Next() {
		var ip models.OutboundIP
		var active int
		var ptrOK sql.NullInt64
		if err := rows.Scan(&ip.ID, &ip.IP, &ip.Mode, &ip.Priority, &active,
			&ptrOK, &ip.PTRRecord, &ip.Notes, &ip.CreatedAt, &ip.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan outbound ip: %w", err)
		}
		ip.Active = active == 1
		if ptrOK.Valid {
			b := ptrOK.Int64 == 1
			ip.PTROK = &b
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rules, err := tx.QueryContext(ctx, `SELECT id, ip_id, match_type, match_value, priority FROM outbound_rules ORDER BY priority DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list outbound rules: %w", err)
	}
	defer rules.Close()

	byIP := map[int64][]models.OutboundRule{}
	for rules.Next() {
		var r models.OutboundRule
		if err := rules.Scan(&r.ID, &r.IPID, &r.MatchType, &r.MatchValue, &r.Priority); err != nil {
			return nil, fmt.Errorf("scan outbound rule: %w", err)
		}
		byIP[r.IPID] = append(byIP[r.IPID], r)
	}
	if err := rules.Err(); err != nil {
		return nil, err
	}
	for i := range ips {
		ips[i].Rules = byIP[ips[i].ID]
	}
	return ips, nil
}

// listSuppressionsTx loads the suppression list inside a transaction.
func (s *Store) listSuppressionsTx(ctx context.Context, tx *sql.Tx) ([]models.Suppression, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT id, email, reason, source, notes, created_at, expires_at, direction, match_type
        FROM suppressions ORDER BY direction ASC, email ASC`)
	if err != nil {
		return nil, fmt.Errorf("list suppressions: %w", err)
	}
	defer rows.Close()

	var out []models.Suppression
	for rows.Next() {
		var sup models.Suppression
		var expires sql.NullTime
		if err := rows.Scan(&sup.ID, &sup.Email, &sup.Reason, &sup.Source, &sup.Notes, &sup.CreatedAt, &expires, &sup.Direction, &sup.MatchType); err != nil {
			return nil, fmt.Errorf("scan suppression: %w", err)
		}
		if expires.Valid {
			sup.ExpiresAt = &expires.Time
		}
		out = append(out, sup)
	}
	return out, rows.Err()
}

func (s *Store) Deliverability(ctx context.Context, since time.Time) ([]DeliverabilityMetric, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT COALESCE(domain, ''), status, COUNT(*)
        FROM mail_events
        WHERE ts >= ? AND status IN ('sent', 'deferred', 'bounced')
        GROUP BY COALESCE(domain, ''), status
        ORDER BY domain ASC, status ASC`, since)
	if err != nil {
		return nil, fmt.Errorf("deliverability: %w", err)
	}
	defer rows.Close()

	var out []DeliverabilityMetric
	for rows.Next() {
		var m DeliverabilityMetric
		if err := rows.Scan(&m.Domain, &m.Status, &m.Count); err != nil {
			return nil, fmt.Errorf("scan deliverability: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeliverabilityAccount is one sending account's delivery aggregate, derived by
// joining delivery events back to their queue event (which records the sender).
type DeliverabilityAccount struct {
	Account  string
	Sent     int64
	Bounced  int64
	Deferred int64
}

// DeliverabilityByAccount returns sent/deferred/bounced counts grouped by the
// sending account (envelope sender) since the given time. The sender is stored
// on the delivery event at ingest time (see internal/logs), so this is a
// single-table aggregate with no self join.
func (s *Store) DeliverabilityByAccount(ctx context.Context, since time.Time) ([]DeliverabilityAccount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(from_addr, ''),
		       COALESCE(SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status = 'bounced' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END), 0)
		FROM mail_events
		WHERE ts >= ? AND action = 'delivery' AND status IN ('sent', 'deferred', 'bounced')
		GROUP BY COALESCE(from_addr, '')
		ORDER BY 2 DESC, 1 ASC`, since)
	if err != nil {
		return nil, fmt.Errorf("deliverability by account: %w", err)
	}
	defer rows.Close()

	var out []DeliverabilityAccount
	for rows.Next() {
		var a DeliverabilityAccount
		if err := rows.Scan(&a.Account, &a.Sent, &a.Bounced, &a.Deferred); err != nil {
			return nil, fmt.Errorf("scan deliverability account: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// BackfillDeliverySenders copies the envelope sender onto delivery events that
// predate the ingester denormalization. It updates up to limit rows per call so
// callers can loop in small chunks that neither hold a long write lock nor block
// the panel. It returns the number of rows updated; 0 means the backfill is
// complete.
func (s *Store) BackfillDeliverySenders(ctx context.Context, limit int) (int64, error) {
	if limit <= 0 {
		limit = 5000
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE mail_events
		SET from_addr = (
			SELECT q.from_addr FROM mail_events q
			WHERE q.queue_id = mail_events.queue_id AND q.action = 'queue'
			ORDER BY q.ts ASC LIMIT 1
		)
		WHERE id IN (
			SELECT id FROM mail_events
			WHERE action = 'delivery' AND (from_addr IS NULL OR from_addr = '')
			ORDER BY id LIMIT ?
		)`, limit)
	if err != nil {
		return 0, fmt.Errorf("backfill delivery senders: %w", err)
	}
	return res.RowsAffected()
}

// DayVolume is one day of mail traffic, split by outcome.
type DayVolume struct {
	Day      time.Time
	Sent     int64 // outbound (postfix/smtp) deliveries that completed
	Received int64 // local deliveries (virtual/dovecot/lmtp) that completed
	Bounced  int64
	Deferred int64
}

// MailVolumeByDay returns per-day traffic counts from since (inclusive, truncated
// to midnight) through today, filling days with no traffic with zeroes so the
// chart axis is continuous. Days are UTC, matching the mail_events timestamps.
func (s *Store) MailVolumeByDay(ctx context.Context, since time.Time) ([]DayVolume, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT strftime('%Y-%m-%d', ts) AS day,
		       COALESCE(SUM(CASE WHEN service = 'postfix/smtp' AND action = 'delivery' AND status = 'sent' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN action = 'delivery' AND status = 'sent' AND service <> 'postfix/smtp' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status = 'bounced' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status = 'deferred' THEN 1 ELSE 0 END), 0)
		FROM mail_events
		WHERE ts >= ?
		GROUP BY day
		ORDER BY day ASC`, since)
	if err != nil {
		return nil, fmt.Errorf("mail volume by day: %w", err)
	}
	defer rows.Close()

	byDay := map[string]DayVolume{}
	for rows.Next() {
		var day string
		var v DayVolume
		if err := rows.Scan(&day, &v.Sent, &v.Received, &v.Bounced, &v.Deferred); err != nil {
			return nil, fmt.Errorf("scan mail volume: %w", err)
		}
		if t, err := time.Parse("2006-01-02", day); err == nil {
			v.Day = t
			byDay[day] = v
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	start := since.UTC().Truncate(24 * time.Hour)
	end := time.Now().UTC().Truncate(24 * time.Hour)
	var out []DayVolume
	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		key := d.Format("2006-01-02")
		if v, ok := byDay[key]; ok {
			out = append(out, v)
		} else {
			out = append(out, DayVolume{Day: d})
		}
	}
	return out, nil
}

// DomainCount is one recipient domain's traffic count.
type DomainCount struct {
	Domain string
	Count  int64
}

// TopOutboundDomains returns the recipient domains the server has sent the most
// mail to since the given time, up to n.
func (s *Store) TopOutboundDomains(ctx context.Context, since time.Time, n int) ([]DomainCount, error) {
	if n <= 0 {
		n = 5
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(domain, ''), COUNT(*)
		FROM mail_events
		WHERE ts >= ? AND service = 'postfix/smtp' AND action = 'delivery' AND status = 'sent'
		GROUP BY COALESCE(domain, '')
		ORDER BY COUNT(*) DESC
		LIMIT ?`, since, n)
	if err != nil {
		return nil, fmt.Errorf("top outbound domains: %w", err)
	}
	defer rows.Close()

	var out []DomainCount
	for rows.Next() {
		var d DomainCount
		if err := rows.Scan(&d.Domain, &d.Count); err != nil {
			return nil, fmt.Errorf("scan top domain: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
