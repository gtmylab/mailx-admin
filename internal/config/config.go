package config

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/gtmylab/mailx-admin/internal/db"
	"os"
)

type Config struct {
	Server ServerConfig `toml:"server"`
	DB     DBConfig     `toml:"database"`
	Mail   MailConfig   `toml:"mail"`
	DNS    DNSConfig    `toml:"dns"`
	Logs   LogsConfig   `toml:"logs"`
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

	return &cfg, nil
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
