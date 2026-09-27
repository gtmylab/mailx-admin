package logs

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
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

// Run tails the log file forever, or until ctx is cancelled.
func (ing *Ingester) Run(ctx context.Context) error {
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
