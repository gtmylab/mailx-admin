package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestDriverNamesAreRegistered is the regression test for the first production
// release. mattn/go-sqlite3 registers itself as "sqlite3" and pgx' stdlib as
// "pgx", but Open passed the canonical names from admin.toml ("sqlite" /
// "postgres") straight to sql.Open. Every migrate/reconcile/serve on a freshly
// installed server therefore died with
//
//	open sqlite: sql: unknown driver "sqlite" (forgotten import?)
//
// The driver was linked all along; only the name was wrong. sql.Open rejects an
// unknown name without opening a connection, so this needs neither a running
// database nor cgo.
func TestDriverNamesAreRegistered(t *testing.T) {
	registered := sql.Drivers()

	for _, d := range []Driver{DriverSQLite, DriverPostgres} {
		name := sqlDriverName(d)
		if !slices.Contains(registered, name) {
			t.Errorf("driver %s opens as %q, which nothing registered (linked: %v)", d, name, registered)
		}
		if _, err := sql.Open(name, "the-dsn-is-not-parsed-here"); err != nil {
			t.Errorf("sql.Open(%q, ...) = %v, want nil: sql.Open only fails for an unregistered driver", name, err)
		}
	}
}

// TestNormalizeDriver — admin.toml is hand-editable and the installer writes the
// canonical names, so both spellings have to be understood.
func TestNormalizeDriver(t *testing.T) {
	cases := []struct {
		in     string
		want   Driver
		wantOK bool
	}{
		{"sqlite", DriverSQLite, true},
		{"sqlite3", DriverSQLite, true},
		{"SQLite3", DriverSQLite, true},
		{" SQLITE ", DriverSQLite, true},
		{"postgres", DriverPostgres, true},
		{"postgresql", DriverPostgres, true},
		{"pgx", DriverPostgres, true},
		{"pgx/v5", DriverPostgres, true},
		{"", "", false},
		{"   ", "", false},
		{"mysql", "", false},
		{"sqlite4", "", false},
	}

	for _, tc := range cases {
		got, ok := NormalizeDriver(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("NormalizeDriver(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

// TestOpenRejectsUnknownDriver — a typo in admin.toml must fail loudly, not
// fall back to a half-built DSN.
func TestOpenRejectsUnknownDriver(t *testing.T) {
	_, err := Open(Config{Driver: "mysql"})
	if err == nil || !strings.Contains(err.Error(), "unknown driver") {
		t.Errorf("Open(mysql) error = %v, want an \"unknown driver\" error", err)
	}
}

// TestOpenRejectsIncompleteConfig — a missing [database.sqlite] path used to
// build the DSN "file:?_foreign_keys=on…", i.e. it created a database file
// named "?", and a missing Postgres host/dbname only failed deep inside the
// driver. Both are validated before sql.Open runs.
func TestOpenRejectsIncompleteConfig(t *testing.T) {
	if _, err := Open(Config{Driver: DriverSQLite}); err == nil {
		t.Error("Open(sqlite without a path) = nil error, want a config error")
	}
	if _, err := Open(Config{Driver: DriverPostgres, PGUser: "mailx_admin"}); err == nil {
		t.Error("Open(postgres without host/dbname) = nil error, want a config error")
	}
}

// TestGooseDialectAcceptsCanonicalNames — Migrate passes the canonical driver
// name to goose.SetDialect, so "sqlite" and "postgres" (not just "sqlite3")
// must be dialects goose knows. Otherwise fixing Open would only move the
// failure one line down.
func TestGooseDialectAcceptsCanonicalNames(t *testing.T) {
	t.Cleanup(func() { _ = goose.SetDialect(string(DriverPostgres)) })

	for _, d := range []Driver{DriverSQLite, DriverPostgres} {
		if err := goose.SetDialect(string(d)); err != nil {
			t.Errorf("goose.SetDialect(%q) = %v, want nil", d, err)
		}
	}
}

// TestSQLiteMigrateCreatesSchema walks the whole fresh-install path: sql.Open
// with the mapped driver name, Ping, the PRAGMAs and goose over the embedded
// migrations. The SQLite driver is cgo-only, so a stub build (make
// build-windows, make build-static) skips instead of failing.
func TestSQLiteMigrateCreatesSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	database, err := Open(Config{Driver: DriverSQLite, SQLitePath: path})
	if err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skipf("sqlite driver is a non-cgo stub in this build: %v", err)
		}
		t.Fatalf("Open(sqlite, %s) = %v", path, err)
	}
	defer database.Close()

	ctx := context.Background()
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("Migrate = %v", err)
	}

	// Tables from the first and from the last embedded migration.
	for _, table := range []string{"domains", "users", "aliases", "admin_users", "backups", "queue_actions"} {
		var n int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Errorf("SELECT from %s after Migrate: %v", table, err)
		}
	}

	var maxVersion int64
	if err := database.QueryRowContext(ctx, "SELECT MAX(version_id) FROM goose_db_version").Scan(&maxVersion); err != nil {
		t.Fatalf("read goose_db_version: %v", err)
	}
	if maxVersion < 5 {
		t.Errorf("goose applied up to version %d, want all 5 embedded migrations", maxVersion)
	}
}

// TestSQLitePoolIsNotASingleConnection is the regression test for the freeze
// this release fixes. With SetMaxOpenConns(1) the panel has exactly one
// connection to hand out: one slow statement, one leaked rows iterator or one
// transaction that is never committed takes it, and from then on every request
// — including the session lookup that runs before any request budget — waits
// for a connection nobody releases. The symptom is a browser that spins with no
// error and a journal with no line, so this is worth pinning in a test.
//
// Ping does not matter here, and neither does cgo: the pool bounds and the DSN
// are plain values.
func TestSQLitePoolIsNotASingleConnection(t *testing.T) {
	maxOpen, maxIdle, maxLifetime := poolSettings(DriverSQLite)
	if maxOpen <= 1 {
		t.Errorf("sqlite MaxOpenConns = %d, want more than 1: a single connection makes every stuck query a panel-wide outage", maxOpen)
	}
	if maxIdle <= 0 || maxIdle > maxOpen {
		t.Errorf("sqlite MaxIdleConns = %d, want between 1 and MaxOpenConns (%d)", maxIdle, maxOpen)
	}
	if maxLifetime != 0 {
		t.Errorf("sqlite ConnMaxLifetime = %s, want 0 (the file does not move)", maxLifetime)
	}

	dsn := sqliteDSN("/var/lib/mailx/state.db")
	// _txlock=immediate is what makes more than one connection safe: every
	// transaction takes the write lock at BEGIN, so two writers queue on
	// _busy_timeout instead of one dying halfway through with SQLITE_BUSY.
	for _, want := range []string{"_txlock=immediate", "_busy_timeout=", "_journal_mode=WAL", "_foreign_keys=on"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("dsn %q is missing %s", dsn, want)
		}
	}
}

// TestPostgresPoolIsBounded — the Postgres pool must stay bounded and recycle
// connections: it talks to a server that can be restarted underneath us.
func TestPostgresPoolIsBounded(t *testing.T) {
	maxOpen, maxIdle, maxLifetime := poolSettings(DriverPostgres)
	if maxOpen <= 1 || maxOpen > 100 {
		t.Errorf("postgres MaxOpenConns = %d, want a bounded pool", maxOpen)
	}
	if maxIdle <= 0 || maxIdle > maxOpen {
		t.Errorf("postgres MaxIdleConns = %d, want between 1 and MaxOpenConns (%d)", maxIdle, maxOpen)
	}
	if maxLifetime <= 0 {
		t.Error("postgres ConnMaxLifetime = 0, want a lifetime so restarts do not leave stale connections")
	}
}

// TestInstallerConfigDriversAreOpenable is the cross-repository contract.
// Mailx-Installer writes admin.toml (Stage 13d, write_admin_toml) from a
// different repository and shares no code with the panel, so this is the only
// place the two halves are checked against each other: every driver = "..."
// value the installer can emit must be a name this binary can actually open.
func TestInstallerConfigDriversAreOpenable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Mailx-Installer"))
	if err != nil {
		t.Fatalf("read the shipped installer: %v", err)
	}

	matches := regexp.MustCompile(`driver = "([a-z0-9_/]+)"`).FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		t.Fatal(`Mailx-Installer no longer writes a driver = "..." value, so admin.toml has no database driver`)
	}

	registered := sql.Drivers()
	for _, m := range matches {
		d, ok := NormalizeDriver(m[1])
		if !ok {
			t.Errorf("Mailx-Installer writes driver = %q, which this binary cannot open", m[1])
			continue
		}
		if !slices.Contains(registered, sqlDriverName(d)) {
			t.Errorf("installer driver %q opens as %q, which nothing registered (linked: %v)",
				m[1], sqlDriverName(d), registered)
		}
	}
}
