package logs

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Ingester struct {
	db       *sql.DB
	logger   *slog.Logger
	path     string
	interval time.Duration
}

func NewIngester(db *sql.DB, logger *slog.Logger, path string) *Ingester {
	return &Ingester{
		db:       db,
		logger:   logger,
		path:     path,
		interval: 2 * time.Second,
	}
}

// Source reports where mail events come from on this host: the configured log
// file when it exists, otherwise the systemd journal when journalctl is
// available. The ingester and the "Log source" panel both use it, so they can
// never disagree.
func Source(path string) string {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return "file"
		}
	}
	if _, err := exec.LookPath("journalctl"); err == nil {
		return "journal"
	}
	return "file"
}

// Run tails the mail log forever, or until ctx is cancelled. On a systemd host
// with no log file (Postfix and Dovecot log to the journal), it follows
// journalctl instead of waiting forever for a file that will never appear.
func (ing *Ingester) Run(ctx context.Context) error {
	if Source(ing.path) == "journal" {
		return ing.runJournal(ctx)
	}
	return ing.runFile(ctx)
}

// runFile polls the configured file on a timer, the behaviour for rsyslog-style
// setups where a mail log file does exist.
func (ing *Ingester) runFile(ctx context.Context) error {
	ticker := time.NewTicker(ing.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := ing.ingestOnce(ctx); err != nil {
				ing.logger.Warn("log ingest failed", "err", err)
			}
		}
	}
}

func (ing *Ingester) ingestOnce(ctx context.Context) error {
	f, err := os.Open(ing.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // log file doesn't exist yet
		}
		return err
	}
	defer f.Close()

	// Get current inode + size to detect rotation
	currentInode, currentSize, err := fileIdentity(ing.path)
	if err != nil {
		return err
	}

	// Load position
	var lastInode, lastOffset int64
	var lastSeen sql.NullTime
	err = ing.db.QueryRowContext(ctx,
		`SELECT inode, offset, last_seen_ts FROM log_state WHERE path = ?`,
		ing.path,
	).Scan(&lastInode, &lastOffset, &lastSeen)
	if err == sql.ErrNoRows {
		lastInode = int64(currentInode)
		lastOffset = 0
	} else if err != nil {
		return err
	}

	// Rotation detection
	if int64(currentInode) != lastInode {
		ing.logger.Info("log rotated", "old_inode", lastInode, "new_inode", currentInode)
		lastOffset = 0
	}

	if currentSize <= lastOffset {
		// Nothing new (or shrunk — likely rotation, re-read from 0)
		if currentSize < lastOffset {
			lastOffset = 0
		} else {
			return nil
		}
	}

	if _, err := f.Seek(lastOffset, io.SeekStart); err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // allow up to 1MB lines

	var events []Event
	var consumed int64 = lastOffset

	for scanner.Scan() {
		line := scanner.Text()
		consumed += int64(len(line)) + 1 // +1 for newline

		ev := ParseLine(line, time.Now())
		if ev != nil {
			events = append(events, *ev)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	if len(events) == 0 {
		// Update offset even if no events (log had other services' lines)
		return ing.saveState(ctx, int64(currentInode), consumed, nil)
	}

	// Insert events in a transaction
	tx, err := ing.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var lastTs time.Time
	for _, ev := range events {
		if ev.Ts.After(lastTs) {
			lastTs = ev.Ts
		}
		_, err := tx.ExecContext(ctx, `
            INSERT INTO mail_events
              (ts, queue_id, service, action, status, from_addr, to_addr, domain,
               client_ip, client_hostname, relay, size_bytes, delay_sec, dsn, message, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, ev.Ts, nullStr(ev.QueueID), ev.Service, nullStr(ev.Action), nullStr(ev.Status),
			nullStr(ev.FromAddr), nullStr(ev.ToAddr), nullStr(ev.Domain),
			nullStr(ev.ClientIP), nullStr(ev.ClientHostname), nullStr(ev.Relay),
			nullInt(ev.SizeBytes), nullFloat(ev.DelaySec), nullStr(ev.DSN),
			ev.Message, ev.Raw)
		if err != nil {
			return fmt.Errorf("insert event: %w", err)
		}

		// A Dovecot login (webmail/IMAP/POP3) is the moment the mailbox owner
		// really used the account. Mirror it onto users.last_login so the user
		// page's "Last login" reflects actual usage, not just panel activity.
		if ev.Action == "login" && ev.FromAddr != "" {
			if _, err := tx.ExecContext(ctx,
				`UPDATE users SET last_login = ? WHERE LOWER(email) = LOWER(?)`, ev.Ts, ev.FromAddr); err != nil {
				return fmt.Errorf("update last login: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	ing.logger.Debug("ingested events", "count", len(events), "up_to", lastTs)
	return ing.saveState(ctx, int64(currentInode), consumed, &lastTs)
}

func (ing *Ingester) saveState(ctx context.Context, inode, offset int64, lastSeen *time.Time) error {
	_, err := ing.db.ExecContext(ctx, `
        INSERT INTO log_state (path, inode, offset, last_read_ts, last_seen_ts)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            inode = excluded.inode,
            offset = excluded.offset,
            last_read_ts = excluded.last_read_ts,
            last_seen_ts = COALESCE(excluded.last_seen_ts, log_state.last_seen_ts)
    `, ing.path, inode, offset, time.Now(), lastSeen)
	return err
}

// ---- systemd journal source ----

// journalUnits are the systemd units whose mail entries we follow when there is
// no mail log file. Postfix (delivery) and Dovecot (login) are what the events
// page cares about; opendkim signing is deliberately left out.
var journalUnits = []string{"postfix", "dovecot"}

// runJournal follows journalctl for the mail units, reconnecting when the
// process exits or errors. It stops only when ctx is cancelled.
func (ing *Ingester) runJournal(ctx context.Context) error {
	ing.logger.Info("log ingester following systemd journal", "units", strings.Join(journalUnits, ","))
	for {
		if err := ing.journalLoop(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			ing.logger.Warn("journal ingest failed; retrying", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
}

func (ing *Ingester) journalLoop(ctx context.Context) error {
	args := []string{"-o", "json", "-f"}
	for _, u := range journalUnits {
		args = append(args, "-u", u)
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Wait() }()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		ev := eventFromJournal(scanner.Bytes())
		if ev == nil {
			continue
		}
		if err := ing.insertEvent(ctx, ev); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan journal: %w", err)
	}
	if stderr.Len() > 0 {
		return fmt.Errorf("journalctl: %s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

// eventFromJournal turns one journalctl JSON record into an Event, reusing the
// same postfix/dovecot parsers the file ingester uses. It returns nil for
// entries that are not mail, or that carry no message.
func eventFromJournal(line []byte) *Event {
	var rec map[string]any
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil
	}

	service := journalService(rec)
	msg, _ := rec["MESSAGE"].(string)
	if service == "" || msg == "" {
		return nil
	}

	ts := time.Now()
	if rt, ok := rec["__REALTIME_TIMESTAMP"].(string); ok {
		if us, err := strconv.ParseInt(rt, 10, 64); err == nil {
			ts = time.Unix(us/1_000_000, (us%1_000_000)*1_000)
		}
	}

	return ParseEvent(service, msg, ts)
}

// journalService maps a journal record to the service name the parser expects:
// postfix/smtpd, postfix/qmgr, dovecot/imap-login, and so on.
func journalService(rec map[string]any) string {
	ident, _ := rec["SYSLOG_IDENTIFIER"].(string)
	if ident = strings.TrimSpace(ident); ident != "" {
		return normalizeJournalIdent(ident)
	}
	if unit, _ := rec["_SYSTEMD_UNIT"].(string); unit != "" {
		return strings.TrimSuffix(unit, ".service")
	}
	return ""
}

// normalizeJournalIdent folds Dovecot's varying syslog identifiers ("dovecot",
// "dovecot/imap-login", "imap-login", "pop3-login") under a "dovecot/..." prefix
// so parseDovecot runs for all of them.
func normalizeJournalIdent(ident string) string {
	if strings.HasPrefix(ident, "dovecot") || strings.HasPrefix(ident, "imap") || strings.HasPrefix(ident, "pop3") {
		if strings.HasPrefix(ident, "dovecot") {
			return ident
		}
		return "dovecot/" + ident
	}
	return ident
}

// insertEvent writes one parsed event, mirroring Dovecot logins onto
// users.last_login the same way the file ingester does.
func (ing *Ingester) insertEvent(ctx context.Context, ev *Event) error {
	tx, err := ing.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO mail_events
          (ts, queue_id, service, action, status, from_addr, to_addr, domain,
           client_ip, client_hostname, relay, size_bytes, delay_sec, dsn, message, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, ev.Ts, nullStr(ev.QueueID), ev.Service, nullStr(ev.Action), nullStr(ev.Status),
		nullStr(ev.FromAddr), nullStr(ev.ToAddr), nullStr(ev.Domain),
		nullStr(ev.ClientIP), nullStr(ev.ClientHostname), nullStr(ev.Relay),
		nullInt(ev.SizeBytes), nullFloat(ev.DelaySec), nullStr(ev.DSN),
		ev.Message, ev.Raw); err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	if ev.Action == "login" && ev.FromAddr != "" {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET last_login = ? WHERE LOWER(email) = LOWER(?)`, ev.Ts, ev.FromAddr); err != nil {
			return fmt.Errorf("update last login: %w", err)
		}
	}

	return tx.Commit()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullInt(i int64) any {
	if i == 0 {
		return nil
	}
	return i
}
func nullFloat(f float64) any {
	if f == 0 {
		return nil
	}
	return f
}

// PruneOld removes events older than retention.
func (ing *Ingester) PruneOld(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention)
	res, err := ing.db.ExecContext(ctx, `DELETE FROM mail_events WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
