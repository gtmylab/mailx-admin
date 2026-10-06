package dbmigrate

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/db"
)

// TestTablesListsAreConsistent guards the two hand-maintained lists: every
// serial table must be in the copy order, and nothing may be listed twice.
func TestTablesListsAreConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range tables {
		if seen[name] {
			t.Errorf("table %q listed twice in the copy order", name)
		}
		seen[name] = true
	}
	for _, name := range serialTables {
		if !seen[name] {
			t.Errorf("serial table %q is missing from the copy order", name)
		}
	}
}

// TestMigrate runs the full SQLite -> Postgres copy. It needs a reachable
// Postgres, so it is skipped unless the standard PGHOST/PGDATABASE variables
// are set; run it on a host that has one:
//
//	PGHOST=127.0.0.1 PGPASSWORD=... PGDATABASE=mailx_test go test ./internal/dbmigrate/ -run TestMigrate
func TestMigrate(t *testing.T) {
	host := os.Getenv("PGHOST")
	dbName := os.Getenv("PGDATABASE")
	if host == "" || dbName == "" {
		t.Skip("PGHOST and PGDATABASE not set; skipping SQLite -> Postgres migration test")
	}

	// Build a SQLite source with a domain and a mailbox.
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "state.db")
	src, err := db.Open(db.Config{Driver: db.DriverSQLite, SQLitePath: srcPath})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := src.Migrate(context.Background()); err != nil {
		src.Close()
		t.Fatalf("sqlite migrate: %v", err)
	}
	if _, err := src.Exec(`INSERT INTO domains (name) VALUES ('example.com')`); err != nil {
		src.Close()
		t.Fatalf("insert domain: %v", err)
	}
	if _, err := src.Exec(`INSERT INTO users (domain_id, username, email, password_hash) VALUES (1, 'alice', 'alice@example.com', 'x')`); err != nil {
		src.Close()
		t.Fatalf("insert user: %v", err)
	}
	src.Close()

	port, _ := strconv.Atoi(envOr("PGPORT", "5432"))
	dst := db.Config{
		Driver:     db.DriverPostgres,
		PGHost:     host,
		PGPort:     port,
		PGUser:     envOr("PGUSER", "postgres"),
		PGPassword: os.Getenv("PGPASSWORD"),
		PGDatabase: dbName,
		PGSSLMode:  envOr("PGSSLMODE", "disable"),
	}

	res, err := Migrate(context.Background(), srcPath, dst)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := res.Tables["domains"]; got != 1 {
		t.Errorf("domains copied = %d, want 1", got)
	}
	if got := res.Tables["users"]; got != 1 {
		t.Errorf("users copied = %d, want 1", got)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
