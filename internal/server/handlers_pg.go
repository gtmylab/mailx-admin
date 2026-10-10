package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/config"
	"github.com/gtmylab/mailx-admin/internal/execx"
)

// dbProvisionBudget bounds the background Postgres install + provision, which can
// take minutes for the apt install.
const dbProvisionBudget = 10 * time.Minute

// postgresStatus is the runtime state of the local PostgreSQL server.
type postgresStatus struct {
	Active      bool
	Version     string
	DBSize      string
	Connections int
}

// databaseProvisionResult is the template-facing state of the provision.
type databaseProvisionResult struct {
	Status string // "running", "done", "error"
	Error  string
}

// postgresInstalled reports whether the PostgreSQL server is installed and
// reachable.
func postgresInstalled(ctx context.Context) bool {
	_, err := execx.Output(ctx, 30*time.Second, "pg_isready")
	return err == nil
}

// installPostgres ensures the PostgreSQL server package is installed and enabled.
func installPostgres(ctx context.Context) error {
	if postgresInstalled(ctx) {
		return nil
	}
	if out, err := execx.Output(ctx, dbProvisionBudget, "apt-get", "install", "-y", "postgresql"); err != nil {
		return fmt.Errorf("apt-get install postgresql: %s", strings.TrimSpace(string(out)))
	}
	if out, err := execx.Output(ctx, 60*time.Second, "systemctl", "enable", "--now", "postgresql"); err != nil {
		return fmt.Errorf("enable postgresql: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// runAsPostgres runs a command as the postgres system user.
func runAsPostgres(ctx context.Context, name string, args ...string) ([]byte, error) {
	full := append([]string{"-u", "postgres", "--", name}, args...)
	return execx.Output(ctx, 60*time.Second, "runuser", full...)
}

// provisionPostgres creates a dedicated role and database and returns its
// connection details.
func provisionPostgres(ctx context.Context) (config.PostgresConfig, error) {
	pw, err := randomHex(32)
	if err != nil {
		return config.PostgresConfig{}, err
	}
	cfg := config.PostgresConfig{
		Host: "127.0.0.1", Port: 5432, User: "mailx",
		Password: pw, DBName: "mailx", SSLMode: "disable",
	}

	// Create or update the role (the hex password has no quotes to escape).
	roleSQL := fmt.Sprintf(
		`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mailx') THEN CREATE ROLE mailx LOGIN PASSWORD '%s'; ELSE ALTER ROLE mailx LOGIN PASSWORD '%s'; END IF; END $$;`,
		pw, pw)
	if _, err := runAsPostgres(ctx, "psql", "-v", "ON_ERROR_STOP=1", "-c", roleSQL); err != nil {
		return config.PostgresConfig{}, err
	}

	// CREATE DATABASE cannot run inside a DO block; use a conditional shell.
	out, _ := runAsPostgres(ctx, "psql", "-tAc", "SELECT 1 FROM pg_database WHERE datname = 'mailx'")
	if strings.TrimSpace(string(out)) != "1" {
		if _, err := runAsPostgres(ctx, "createdb", "-O", "mailx", "mailx"); err != nil {
			return config.PostgresConfig{}, err
		}
	}
	return cfg, nil
}

// postgresStatusView reads the running Postgres server's state.
func postgresStatusView(ctx context.Context) postgresStatus {
	st := postgresStatus{}
	if out, err := execx.Output(ctx, 30*time.Second, "systemctl", "is-active", "postgresql"); err == nil {
		st.Active = strings.TrimSpace(string(out)) == "active"
	}
	if out, err := runAsPostgres(ctx, "psql", "-tAc", "SELECT version()"); err == nil {
		st.Version = strings.TrimSpace(string(out))
	}
	if out, err := runAsPostgres(ctx, "psql", "-tAc", "SELECT pg_database_size('mailx')"); err == nil {
		if n, e := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); e == nil {
			st.DBSize = humanBytes(n)
		}
	}
	if out, err := runAsPostgres(ctx, "psql", "-tAc", "SELECT count(*) FROM pg_stat_activity WHERE datname = 'mailx'"); err == nil {
		st.Connections, _ = strconv.Atoi(strings.TrimSpace(string(out)))
	}
	return st
}

func restartPostgres(ctx context.Context) error {
	_, err := execx.Output(ctx, 60*time.Second, "systemctl", "restart", "postgresql")
	return err
}

// randomHex returns n random bytes hex-encoded.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// humanBytes renders a byte count in a compact, human-readable form.
func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	val := float64(n)
	for _, u := range units {
		val /= 1024
		if val < 1024 {
			return fmt.Sprintf("%.1f %s", val, u)
		}
	}
	return fmt.Sprintf("%.1f PiB", val/1024)
}

// handleDatabaseProvision installs PostgreSQL and provisions a dedicated role and
// database, then saves the credentials (without flipping the driver). It runs in
// the background because the apt install can take minutes.
func (s *Server) handleDatabaseProvision(w http.ResponseWriter, r *http.Request) {
	if s.dbDriver != "sqlite" {
		s.renderPartial(w, "database_provision_result", databaseProvisionResult{Status: "error", Error: "the panel is not running on SQLite"})
		return
	}

	s.dbProvisionMu.Lock()
	if s.dbProvisionState == "running" {
		s.dbProvisionMu.Unlock()
		s.renderPartial(w, "database_provision_result", databaseProvisionResult{Status: "running"})
		return
	}
	s.dbProvisionState = "running"
	s.dbProvisionErr = ""
	s.dbProvisionMu.Unlock()

	actor := s.actorName(r)
	remoteIP := clientIP(r)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dbProvisionBudget)
		defer cancel()

		err := installPostgres(ctx)
		if err == nil {
			var cfg config.PostgresConfig
			if cfg, err = provisionPostgres(ctx); err == nil {
				err = savePostgresCredentials(s.configPath, cfg)
			}
		}

		s.dbProvisionMu.Lock()
		defer s.dbProvisionMu.Unlock()
		if err != nil {
			s.dbProvisionState = "error"
			s.dbProvisionErr = err.Error()
			_ = s.auditor.Log(context.Background(), audit.Entry{
				Actor: actor, Action: "db.provision", Result: "error",
				Detail: map[string]any{"error": err.Error()}, RemoteIP: remoteIP,
			})
			return
		}
		s.dbProvisionState = "done"
		_ = s.auditor.Log(context.Background(), audit.Entry{
			Actor: actor, Action: "db.provision", Result: "ok", RemoteIP: remoteIP,
		})
	}()

	s.renderPartial(w, "database_provision_result", databaseProvisionResult{Status: "running"})
}

// handleDatabaseProvisionStatus reports the provision state for the polling
// fragment. On completion it redirects the page so the migration form is
// re-rendered with the freshly-saved credentials.
func (s *Server) handleDatabaseProvisionStatus(w http.ResponseWriter, r *http.Request) {
	s.dbProvisionMu.Lock()
	res := databaseProvisionResult{Status: s.dbProvisionState, Error: s.dbProvisionErr}
	s.dbProvisionMu.Unlock()

	if res.Status == "done" {
		w.Header().Set("HX-Redirect", "/system/database?flash="+encodeFlash("PostgreSQL installed and provisioned"))
		w.WriteHeader(http.StatusOK)
		return
	}
	s.renderPartial(w, "database_provision_result", res)
}

// handleDatabaseServiceRestart restarts the local PostgreSQL service.
func (s *Server) handleDatabaseServiceRestart(w http.ResponseWriter, r *http.Request) {
	if err := restartPostgres(r.Context()); err != nil {
		s.renderFormError(w, "restart postgresql failed: "+err.Error())
		return
	}
	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: s.actorName(r), Action: "db.restart", Result: "ok", RemoteIP: clientIP(r),
	})
	w.Header().Set("HX-Redirect", "/system/database?flash="+encodeFlash("PostgreSQL restarted"))
	w.WriteHeader(http.StatusOK)
}
