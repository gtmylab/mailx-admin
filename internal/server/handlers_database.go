package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/config"
	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/dbmigrate"
	"github.com/gtmylab/mailx-admin/internal/execx"
)

// dbMigrateBudget bounds the background SQLite -> Postgres migration, which can
// take minutes on a large mail_events table. The HTTP handlers that start and
// poll it stay fast; only the goroutine runs under this budget.
const dbMigrateBudget = 15 * time.Minute

// databaseInfo is the current database state the page shows.
type databaseInfo struct {
	Driver     string
	SQLitePath string
}

type databaseTestResult struct {
	Ok    bool
	Error string
}

// databaseMigrateResult is the template-facing state of the migration. The
// "running" fragment re-polls the status endpoint until it settles.
type databaseMigrateResult struct {
	Status     string // "running", "done", "error"
	Message    string
	Error      string
	Total      int64
	TableCount int
}

func (s *Server) handleDatabasePage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "database.html", s.newPageData(w, r, "Database", "database", map[string]any{
		"DB": databaseInfo{Driver: s.dbDriver, SQLitePath: s.cfg.DB.SQLite.Path},
	}))
}

// handleDatabaseTest opens and pings the target Postgres, so the operator can
// confirm the connection before committing to a migration.
func (s *Server) handleDatabaseTest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}
	if err := testPostgres(r.Context(), postgresFromForm(r)); err != nil {
		s.renderPartial(w, "database_test_result", databaseTestResult{Error: err.Error()})
		return
	}
	s.renderPartial(w, "database_test_result", databaseTestResult{Ok: true})
}

// handleDatabaseMigrate starts the SQLite -> Postgres migration in the
// background (a large mail_events table can take minutes) and answers with the
// "running" fragment, which polls handleDatabaseStatus until it settles.
func (s *Server) handleDatabaseMigrate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}
	if s.dbDriver != "sqlite" {
		s.renderPartial(w, "database_migrate_result", databaseMigrateResult{Status: "error", Error: "the panel is not running on SQLite"})
		return
	}

	s.dbMigrateMu.Lock()
	if s.dbMigrateState == "running" {
		s.dbMigrateMu.Unlock()
		s.renderPartial(w, "database_migrate_result", databaseMigrateResult{Status: "running"})
		return
	}
	s.dbMigrateState = "running"
	s.dbMigrateErr = ""
	s.dbMigrateMu.Unlock()

	pg := postgresFromForm(r)
	dst := db.Config{
		Driver:     db.DriverPostgres,
		PGHost:     pg.Host,
		PGPort:     pg.Port,
		PGUser:     pg.User,
		PGPassword: pg.Password,
		PGDatabase: pg.DBName,
		PGSSLMode:  pg.SSLMode,
	}
	actor := s.actorName(r)
	remoteIP := clientIP(r)

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: actor, Action: "db.migrate", Result: "ok",
		Detail: map[string]any{"phase": "started"}, RemoteIP: remoteIP,
	})

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dbMigrateBudget)
		defer cancel()

		res, err := dbmigrate.Migrate(ctx, s.cfg.DB.SQLite.Path, dst)

		s.dbMigrateMu.Lock()
		defer s.dbMigrateMu.Unlock()
		if err != nil {
			s.dbMigrateState = "error"
			s.dbMigrateErr = err.Error()
			_ = s.auditor.Log(context.Background(), audit.Entry{
				Actor: actor, Action: "db.migrate", Result: "error",
				Detail: map[string]any{"error": err.Error()}, RemoteIP: remoteIP,
			})
			return
		}

		// Data is in Postgres; flip the config so the next start reads it.
		if err := savePostgresConfig(s.configPath, pg); err != nil {
			s.dbMigrateState = "error"
			s.dbMigrateErr = "data copied, but writing config failed: " + err.Error()
			_ = s.auditor.Log(context.Background(), audit.Entry{
				Actor: actor, Action: "db.migrate", Result: "error",
				Detail: map[string]any{"error": s.dbMigrateErr}, RemoteIP: remoteIP,
			})
			return
		}

		s.dbMigrateState = "done"
		s.dbMigrateTotal = res.Total()
		s.dbMigrateTables = len(res.Tables)
		_ = s.auditor.Log(context.Background(), audit.Entry{
			Actor: actor, Action: "db.migrate", Result: "ok",
			Detail: map[string]any{"rows": res.Total()}, RemoteIP: remoteIP,
		})

		// Restart on a delay so the browser has time to render the result.
		go func() {
			time.Sleep(2 * time.Second)
			_ = execx.Run(context.Background(), 30*time.Second, "systemctl", "restart", "mailx-admin")
		}()
	}()

	s.renderPartial(w, "database_migrate_result", databaseMigrateResult{Status: "running"})
}

// handleDatabaseStatus reports the migration state for the polling fragment.
func (s *Server) handleDatabaseStatus(w http.ResponseWriter, r *http.Request) {
	s.dbMigrateMu.Lock()
	res := databaseMigrateResult{
		Status:     s.dbMigrateState,
		Error:      s.dbMigrateErr,
		Total:      s.dbMigrateTotal,
		TableCount: s.dbMigrateTables,
	}
	s.dbMigrateMu.Unlock()
	s.renderPartial(w, "database_migrate_result", res)
}

// postgresFromForm reads the Postgres connection details the page submits.
func postgresFromForm(r *http.Request) config.PostgresConfig {
	port, _ := strconv.Atoi(r.FormValue("port"))
	return config.PostgresConfig{
		Host:     r.FormValue("host"),
		Port:     port,
		User:     r.FormValue("user"),
		Password: r.FormValue("password"),
		DBName:   r.FormValue("dbname"),
		SSLMode:  r.FormValue("sslmode"),
	}
}

// testPostgres opens a connection and pings it. db.Open already pings, so a nil
// return means the target is reachable with these credentials.
func testPostgres(ctx context.Context, pg config.PostgresConfig) error {
	if pg.Host == "" || pg.DBName == "" {
		return fmt.Errorf("host and database name are required")
	}
	d, err := db.Open(db.Config{
		Driver:     db.DriverPostgres,
		PGHost:     pg.Host,
		PGPort:     pg.Port,
		PGUser:     pg.User,
		PGPassword: pg.Password,
		PGDatabase: pg.DBName,
		PGSSLMode:  pg.SSLMode,
	})
	if err != nil {
		return err
	}
	_ = d.Close()
	return nil
}

// savePostgresConfig reloads admin.toml, switches the [database] section to
// Postgres and writes it back. Loading fresh avoids mutating the running
// server's in-memory config.
func savePostgresConfig(path string, pg config.PostgresConfig) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	cfg.DB.Driver = "postgres"
	cfg.DB.Postgres = pg
	return config.Save(path, cfg)
}
