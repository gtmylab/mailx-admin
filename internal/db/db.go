package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Driver string

const (
	DriverSQLite   Driver = "sqlite"
	DriverPostgres Driver = "postgres"
)

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
	var dsn string

	switch cfg.Driver {
	case DriverSQLite:
		// WAL for concurrent reads, busy_timeout to avoid "database locked"
		dsn = fmt.Sprintf(
			"file:%s?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL",
			cfg.SQLitePath,
		)
	case DriverPostgres:
		dsn = fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			cfg.PGHost, cfg.PGPort, cfg.PGUser, cfg.PGPassword, cfg.PGDatabase, cfg.PGSSLMode,
		)
	default:
		return nil, fmt.Errorf("unknown driver: %s", cfg.Driver)
	}

	sqlDB, err := sql.Open(string(cfg.Driver), dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", cfg.Driver, err)
	}

	// Connection pool tuning. SQLite wants 1 writer; Postgres is fine with more.
	if cfg.Driver == DriverSQLite {
		sqlDB.SetMaxOpenConns(1) // single writer, avoids SQLITE_BUSY entirely
		sqlDB.SetMaxIdleConns(1)
	} else {
		sqlDB.SetMaxOpenConns(20)
		sqlDB.SetMaxIdleConns(5)
		sqlDB.SetConnMaxLifetime(30 * time.Minute)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping %s: %w", cfg.Driver, err)
	}

	// For SQLite, set an aggressive page cache and enable memory-mapped I/O.
	// These are safe for our workload (single writer, mostly reads).
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
