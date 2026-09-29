package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strings"
	"time"

	// Linked for their side effect: registering with database/sql. Note the
	// names they register under ("pgx"/"pgx/v5", "sqlite3") — they are not the
	// names admin.toml uses. See sqlDriverName.
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Driver string

// Driver names as they appear in admin.toml. MailX uses the canonical "sqlite"
// and "postgres" spellings everywhere — the installer's write_admin_toml, its
// uninstall path, internal/backup and goose all key off them — while the linked
// database/sql drivers register themselves as "sqlite3" and "pgx".
//
// Handing the canonical name straight to sql.Open fails with
//
//	open sqlite: sql: unknown driver "sqlite" (forgotten import?)
//
// which is what every mailx-admin migrate/reconcile/serve logged on a freshly
// installed server until sqlDriverName was added: the driver was linked the
// whole time, only the name passed to database/sql was wrong.
const (
	DriverSQLite   Driver = "sqlite"
	DriverPostgres Driver = "postgres"
)

// NormalizeDriver maps a driver spelling from the config onto the canonical
// Driver value. Besides the canonical names it accepts the names the linked
// drivers register under, so a hand-written admin.toml saying "sqlite3" or
// "pgx" works as well.
func NormalizeDriver(name string) (Driver, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sqlite", "sqlite3":
		return DriverSQLite, true
	case "postgres", "postgresql", "pgx", "pgx/v5":
		return DriverPostgres, true
	default:
		return "", false
	}
}

// sqlDriverName is the name database/sql knows the driver by. Every sql.Open
// call must use it, never the canonical Driver value.
func sqlDriverName(d Driver) string {
	switch d {
	case DriverSQLite:
		return "sqlite3" // github.com/mattn/go-sqlite3
	case DriverPostgres:
		return "pgx" // github.com/jackc/pgx/v5/stdlib
	default:
		return string(d)
	}
}

type Config struct {
	Driver Driver

	// SQLite
	SQLitePath string

	// Postgres
	PGHost     string
	PGPort     int
	PGUser     string
	PGPassword string
	PGDatabase string
	PGSSLMode  string
}

type DB struct {
	*sql.DB
	driver Driver
}

func Open(cfg Config) (*DB, error) {
	driver, ok := NormalizeDriver(string(cfg.Driver))
	if !ok {
		return nil, fmt.Errorf("unknown driver: %s", cfg.Driver)
	}
	cfg.Driver = driver

	var dsn string

	switch cfg.Driver {
	case DriverSQLite:
		// An empty path would silently produce the DSN "file:?_foreign_keys=on…"
		// — a database file literally named "?" in the working directory.
		if cfg.SQLitePath == "" {
			return nil, fmt.Errorf("sqlite: no database path configured (set [database.sqlite] path in admin.toml)")
		}
		dsn = sqliteDSN(cfg.SQLitePath)
	case DriverPostgres:
		if cfg.PGHost == "" || cfg.PGDatabase == "" {
			return nil, fmt.Errorf("postgres: host and dbname must be set ([database.postgres] in admin.toml)")
		}
		dsn = fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.PGHost, cfg.PGPort, cfg.PGUser, cfg.PGPassword, cfg.PGDatabase, cfg.PGSSLMode,
		)
	default:
		return nil, fmt.Errorf("unknown driver: %s", cfg.Driver)
	}

	sqlDB, err := sql.Open(sqlDriverName(cfg.Driver), dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", cfg.Driver, err)
	}

	// Connection pool tuning. See poolSettings for why SQLite no longer gets a
	// single connection.
	maxOpen, maxIdle, maxLifetime := poolSettings(cfg.Driver)
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	if maxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(maxLifetime)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping %s: %w", cfg.Driver, err)
	}

	// For SQLite, set an aggressive page cache and enable memory-mapped I/O.
	// These are safe for our workload (a single writer at a time, mostly reads).
	if cfg.Driver == DriverSQLite {
		pragmas := []string{
			"PRAGMA cache_size = -64000",   // 64 MB page cache
			"PRAGMA mmap_size = 268435456", // 256 MB mmap
			"PRAGMA temp_store = MEMORY",
			"PRAGMA wal_autocheckpoint = 1000",
		}
		for _, p := range pragmas {
			sqlDB.Exec(p)
		}
	}

	return &DB{DB: sqlDB, driver: cfg.Driver}, nil
}

func (d *DB) Migrate(ctx context.Context) error {
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect(string(d.driver)); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}
	if err := goose.UpContext(ctx, d.DB, "migrations"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (d *DB) Driver() Driver { return d.driver }

// SQLite connection settings.
//
// v1.0.5 opened SQLite with SetMaxOpenConns(1) "to avoid SQLITE_BUSY entirely",
// and that turned a local problem into a global outage. With a single connection
// *any* holder becomes the panel's only connection: one abandoned statement, one
// slow full scan, one transaction that never commits — and from then on every
// other request waits for a connection that nobody releases. HTTP has no way to
// signal that: the handlers block in database/sql with no deadline of their own
// before the request budget applies (the session lookup runs first), so the
// browser shows a spinner forever and the journal shows nothing at all. That is
// exactly the v1.0.3/v1.0.4 freeze, and it is why the fix cannot be limited to
// "don't audit inside the transaction".
//
// WAL already allows many readers next to the one writer, so the pool can be
// widened safely as long as writers do not start in a deferred transaction and
// fail halfway through (SQLITE_BUSY on upgrade). Two settings make that safe:
//
//   - _txlock=immediate makes every transaction take the write lock at BEGIN,
//     so a second writer waits on _busy_timeout instead of dying mid-statement.
//   - _busy_timeout=5000 gives that wait a bound: after 5s the writer gets
//     "database is locked", an error the panel can show, instead of hanging.
//
// Everything in this schema that is not a request-scoped transaction is a short
// statement (the log ingester's 2s batch, the sync recorder, the metrics
// collector), so 8 connections is ample and leaves the panel a free connection
// even while several of them are busy.
const (
	sqliteMaxOpenConns = 8
	sqliteMaxIdleConns = 8
)

// sqliteDSN builds the connection string for the SQLite driver. Kept as a
// function so the pragmas are visible and testable without cgo.
func sqliteDSN(path string) string {
	return fmt.Sprintf(
		"file:%s?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_txlock=immediate",
		path,
	)
}

// poolSettings returns how many connections the driver gets. SQLite keeps idle
// connections forever (opening one costs a WAL index read, and a server that
// frequently touches the database should not pay that every time); Postgres
// recycles them because the server may itself restart.
func poolSettings(driver Driver) (maxOpen, maxIdle int, maxLifetime time.Duration) {
	if driver == DriverSQLite {
		return sqliteMaxOpenConns, sqliteMaxIdleConns, 0
	}
	return 20, 5, 30 * time.Minute
}
