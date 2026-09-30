package config

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/roundcube"
)

type Config struct {
	Server    ServerConfig    `toml:"server"`
	DB        DBConfig        `toml:"database"`
	Mail      MailConfig      `toml:"mail"`
	Roundcube RoundcubeConfig `toml:"roundcube"`
	DNS       DNSConfig       `toml:"dns"`
	Logs      LogsConfig      `toml:"logs"`
}

type ServerConfig struct {
	ListenAddr string `toml:"listen_addr"`
	BaseURL    string `toml:"base_url"`
	Hostname   string `toml:"hostname"`
}

type DNSConfig struct {
	Resolver string `toml:"resolver"` // e.g. "1.1.1.1:53"
}
type LogsConfig struct {
	MailLogPath   string `toml:"mail_log_path"`
	RetentionDays int    `toml:"retention_days"`
}
type DBConfig struct {
	Driver   string         `toml:"driver"`
	SQLite   SQLiteConfig   `toml:"sqlite"`
	Postgres PostgresConfig `toml:"postgres"`
}

type SQLiteConfig struct {
	Path string `toml:"path"`
}

type PostgresConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
	SSLMode  string `toml:"sslmode"`
}

type MailConfig struct {
	PostfixConfDir    string `toml:"postfix_conf_dir"`
	DovecotConfDir    string `toml:"dovecot_conf_dir"`
	OpenDKIMDir       string `toml:"opendkim_dir"`
	PrimaryDomainFile string `toml:"primary_domain_file"`

	// PasswdScheme is the password scheme new mailboxes are hashed with, and
	// the passdb's `scheme=` default. Empty and "auto" both mean "ask the
	// local Dovecot": ARGON2ID where Dovecot was built with libsodium,
	// SSHA512 where it was not. Anything else is honoured only if this
	// Dovecot can verify it.
	PasswdScheme string `toml:"passwd_scheme"`
}

// RoundcubeConfig points the panel at Roundcube's own MySQL database, which is
// what makes a mailbox usable in webmail.
//
// Roundcube keeps its own `users` and `identities` tables and is happy to
// create a row on first login, so a missing row is not what refuses a login —
// but a mailbox the panel created and Roundcube then treats as a stranger has
// no default identity and no preferences, and an operator cannot tell whether
// webmail works until somebody tries it. Pre-seeding those two rows is the
// difference between "created" and "usable".
//
// It is a separate database from the panel's own (see internal/db, which only
// ever knows sqlite and postgres): nothing here reads or writes panel state,
// and Roundcube's schema is never migrated by this panel.
type RoundcubeConfig struct {
	// Enabled turns the pre-seed on. The installer sets it; nothing starts
	// writing into a database that may not exist by accident.
	Enabled bool `toml:"enabled"`

	// Database is Roundcube's schema name (roundcubemail by default).
	Database string `toml:"database"`

	// Binary is the MySQL client used to run the two inserts. The panel
	// talks to MySQL the way the installer does — through the local
	// socket as root, which is already how every other server command
	// works — so it needs no new driver and no stored password.
	Binary string `toml:"binary"`

	// Args are extra client arguments, e.g.
	// ["--defaults-file=/root/.my.cnf"] or ["-h", "127.0.0.1"].
	Args []string `toml:"args"`

	// MailHost is written to users.mail_host and has to match Roundcube's
	// imap_host (default_host on older releases), or the row is not the one
	// the login looks up.
	MailHost string `toml:"mail_host"`

	// Language is the user's default Roundcube language.
	Language string `toml:"language"`

	// Name, when set, is the display name of the default identity. Empty
	// means the address' local part.
	Name string `toml:"name"`

	// TimeoutSeconds bounds each client call; 0 means the built-in default.
	TimeoutSeconds int `toml:"timeout_seconds"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if cfg.Server.Hostname == "" {
		h, _ := os.Hostname()
		cfg.Server.Hostname = h
	}

	// Allow env var override for password
	if v := os.Getenv("MAILX_DB_PASSWORD"); v != "" {
		cfg.DB.Postgres.Password = v
	}

	if cfg.DNS.Resolver == "" {
		cfg.DNS.Resolver = "1.1.1.1:53"
	}
	if cfg.Logs.MailLogPath == "" {
		cfg.Logs.MailLogPath = "/var/log/mail.log"
	}
	if cfg.Logs.RetentionDays == 0 {
		cfg.Logs.RetentionDays = 30
	}

	// Roundcube's defaults are filled in even when the section is disabled:
	// the panel reports what it *would* use, so "why does it not pre-seed?"
	// has an answer that does not require reading this file.
	normalized := cfg.Roundcube.ToClientConfig()
	cfg.Roundcube.Database = normalized.Database
	cfg.Roundcube.Binary = normalized.Binary
	cfg.Roundcube.MailHost = normalized.MailHost
	cfg.Roundcube.Language = normalized.Language
	cfg.Roundcube.TimeoutSeconds = int(normalized.Timeout / time.Second)

	return &cfg, nil
}

// ToClientConfig turns the [roundcube] section into a client configuration,
// with every default applied.
func (c RoundcubeConfig) ToClientConfig() roundcube.Config {
	return roundcube.Config{
		Database: c.Database,
		Binary:   c.Binary,
		Args:     c.Args,
		MailHost: c.MailHost,
		Language: c.Language,
		Name:     c.Name,
		Timeout:  time.Duration(c.TimeoutSeconds) * time.Second,
	}.Normalize()
}

func (c *DBConfig) ToDriverConfig() db.Config {
	out := db.Config{
		Driver: db.Driver(c.Driver),
	}

	// Normalize first: the driver decides which section supplies the DSN, and
	// "sqlite"/"sqlite3" (or "postgres"/"pgx") must reach the same section. An
	// unrecognized name is passed through unchanged so db.Open reports it as an
	// unknown driver.
	driver, ok := db.NormalizeDriver(c.Driver)
	if !ok {
		return out
	}
	out.Driver = driver

	switch driver {
	case db.DriverSQLite:
		out.SQLitePath = c.SQLite.Path
	case db.DriverPostgres:
		out.PGHost = c.Postgres.Host
		out.PGPort = c.Postgres.Port
		out.PGUser = c.Postgres.User
		out.PGPassword = c.Postgres.Password
		out.PGDatabase = c.Postgres.DBName
		out.PGSSLMode = c.Postgres.SSLMode
	}
	return out
}
