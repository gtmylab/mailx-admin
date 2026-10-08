// Package dbmigrate copies a SQLite panel database into a fresh Postgres
// database, so a host that has outgrown SQLite can switch without losing state.
// It runs the Postgres migrations to create the schema, copies every table row
// for row (preserving ids so foreign keys line up), and resets the sequences so
// the panel's next insert does not collide with a copied id.
package dbmigrate

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/db"
)

// tables is the copy order: a table's foreign-key parents are copied first.
var tables = []string{
	"domains",
	"admin_users",
	"users",
	"aliases",
	"policies",
	"settings",
	"sessions",
	"audit_log",
	"reconcile_runs",
	"dns_checks",
	"ssl_certs",
	"test_sends",
	"mail_events",
	"log_state",
	"sieve_rules",
	"port_listeners",
	"queue_actions",
	"backups",
	"outbound_ips",
	"outbound_rules",
	"blocklist_checks",
	"suppressions",
	"quota_samples",
	"api_keys",
	"webhooks",
	"webhook_deliveries",
	"cron_jobs",
}

// serialTables are the tables whose "id" column is backed by a sequence. After
// a bulk copy that writes explicit ids, each sequence must be advanced past the
// highest copied id or the panel's next insert collides with a copied row.
var serialTables = []string{
	"domains", "users", "aliases", "policies", "admin_users", "audit_log",
	"reconcile_runs", "dns_checks", "ssl_certs", "test_sends", "mail_events",
	"sieve_rules", "port_listeners", "queue_actions", "backups", "outbound_ips",
	"outbound_rules", "blocklist_checks", "suppressions", "quota_samples",
	"api_keys", "webhooks", "webhook_deliveries", "cron_jobs",
}

// Result reports how many rows were copied, per table.
type Result struct {
	Tables map[string]int64
}

// Total returns the number of rows copied across every table.
func (r *Result) Total() int64 {
	var n int64
	for _, c := range r.Tables {
		n += c
	}
	return n
}

// Migrate copies the SQLite database at sqlitePath into the Postgres database
// described by dst. It is safe to run while the panel is serving from SQLite:
// the source is opened read-only and the copy is a single Postgres transaction,
// so a failure leaves the target unchanged.
func Migrate(ctx context.Context, sqlitePath string, dst db.Config) (*Result, error) {
	src, err := openSQLiteReadOnly(sqlitePath)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	dstDB, err := db.Open(dst)
	if err != nil {
		return nil, err
	}
	defer dstDB.Close()

	// Create the Postgres schema. Running goose here (rather than copying the
	// SQLite files) records the migration versions, so the panel's own startup
	// migration is a no-op once the config points at Postgres.
	if err := dstDB.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("create postgres schema: %w", err)
	}

	// A retry after a half-copied attempt starts clean.
	if err := truncateAll(ctx, dstDB.DB); err != nil {
		return nil, err
	}

	// A read-only transaction gives the SQLite side one consistent snapshot for
	// the whole copy, so a concurrent write cannot produce half of a change.
	srcTx, err := src.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin read transaction: %w", err)
	}
	defer srcTx.Rollback()

	dstTx, err := dstDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin write transaction: %w", err)
	}
	defer dstTx.Rollback()

	res := &Result{Tables: make(map[string]int64, len(tables))}
	for _, t := range tables {
		n, err := copyTable(ctx, srcTx, dstTx, t)
		if err != nil {
			return nil, fmt.Errorf("copy %s: %w", t, err)
		}
		res.Tables[t] = n
	}
	for _, t := range serialTables {
		if err := resetSequence(ctx, dstTx, t); err != nil {
			return nil, fmt.Errorf("reset sequence %s: %w", t, err)
		}
	}

	if err := dstTx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return res, nil
}

// openSQLiteReadOnly opens the source database without taking a write lock, so
// the panel can keep serving while the migration reads it.
func openSQLiteReadOnly(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return db, nil
}

// truncateAll clears every target table, so a retry after a failed attempt does
// not duplicate rows. The sequences are reset explicitly after the copy.
func truncateAll(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, "TRUNCATE "+strings.Join(tables, ", ")+" CASCADE"); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}
	return nil
}

// copyTable streams every row of one table from src into dst. Columns are read
// from the driver, so the copy stays correct if the schema grows a column.
func copyTable(ctx context.Context, src, dst *sql.Tx, name string) (int64, error) {
	rows, err := src.QueryContext(ctx, "SELECT * FROM "+name)
	if err != nil {
		return 0, fmt.Errorf("select: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}

	placeholders := make([]string, len(cols))
	for i := range placeholders {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	insert := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		name, strings.Join(cols, ", "), strings.Join(placeholders, ", "))

	stmt, err := dst.PrepareContext(ctx, insert)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	var count int64
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range ptrs {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return count, err
		}
		if _, err := stmt.ExecContext(ctx, vals...); err != nil {
			return count, fmt.Errorf("insert: %w", err)
		}
		count++
	}
	return count, rows.Err()
}

// resetSequence advances a table's id sequence past its highest copied id.
func resetSequence(ctx context.Context, tx *sql.Tx, name string) error {
	q := fmt.Sprintf(
		"SELECT setval(pg_get_serial_sequence('%s', 'id'), COALESCE((SELECT MAX(id) FROM %s), 0) + 1, false)",
		name, name,
	)
	if _, err := tx.ExecContext(ctx, q); err != nil {
		return err
	}
	return nil
}
