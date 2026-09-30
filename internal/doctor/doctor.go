// Package doctor answers one question: is this server's mail configuration
// actually in the state the panel thinks it is in?
//
// Every check is read-only. Nothing here writes a file, reloads a service or
// touches the database beyond SELECTs, so it is safe to run on a production box
// (that is the whole point: v1.0.4's failures were invisible because nothing
// could be inspected without guessing).
//
// It is used twice: by `mailx-admin doctor` and by the panel's diagnostics
// dialog. Both print the same checks, in the same order.
package doctor

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/gtmylab/mailx-admin/internal/config"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/store"
	"github.com/gtmylab/mailx-admin/internal/version"
)

// Status is how bad a check is. The order matters: Report.Failed uses it.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	Info Status = "info"
)

// Check is one finding.
type Check struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Hint    string `json:"hint,omitempty"`
	Command string `json:"command,omitempty"` // what to run to fix it
}

// Report is the whole run.
type Report struct {
	Version   string    `json:"version"`
	Generated time.Time `json:"generated"`
	Checks    []Check   `json:"checks"`
}

// Failed reports whether anything is broken badly enough to fail the run (and
// to make `mailx-admin doctor` exit non-zero, so it can be used in a check).
func (r *Report) Failed() bool {
	for _, c := range r.Checks {
		if c.Status == Fail {
			return true
		}
	}
	return false
}

// Health summarises a report for the panel's badge.
func (r *Report) Health() Status {
	for _, c := range r.Checks {
		if c.Status == Fail {
			return Fail
		}
	}
	for _, c := range r.Checks {
		if c.Status == Warn {
			return Warn
		}
	}
	return OK
}

// Options is what the checks need. Both callers build it from their own
// config and handles.
type Options struct {
	Config *config.Config
	DB     *sql.DB
	Store  *store.Store
	Rec    *reconciler.Reconciler

	// Sync is the last sync state, when the caller has a syncer.
	LastSync *SyncSnapshot

	// SkipServices avoids shelling out to systemctl (tests, and anything that
	// runs on a machine that is not the mail server itself).
	SkipServices bool
}

// SyncSnapshot is the last reconcile_runs row, as doctor needs it.
type SyncSnapshot struct {
	Status    string
	Trigger   string
	StartedAt time.Time
	Error     string
	Drift     int
}

const checkTimeout = 30 * time.Second

// Run performs every check. It never returns an error: a check that cannot run
// is reported as a failing or warning check, because a doctor that gives up is
// useless exactly when it is needed.
func Run(ctx context.Context, opts Options) *Report {
	report := &Report{Version: version.Full(), Generated: time.Now()}

	report.checks(versionCheck())
	report.checks(databaseCheck(ctx, opts))
	report.checks(stateCheck(ctx, opts))
	report.checks(configCheck(ctx, opts))
	report.checks(validationCheck(ctx, opts))
	report.checks(serverStateCheck(ctx, opts))
	report.checks(serviceCheck(ctx, opts))
	report.checks(schemeCheck(ctx, opts))
	report.checks(lastSyncCheck(ctx, opts))
	report.checks(roundcubeCheck(ctx, opts))

	return report
}

func (r *Report) checks(cs ...Check) {
	for _, c := range cs {
		if c.Name != "" {
			r.Checks = append(r.Checks, c)
		}
	}
}

func versionCheck() Check {
	return Check{Name: "panel version", Status: Info, Detail: version.Full()}
}

func databaseCheck(ctx context.Context, opts Options) Check {
	if opts.DB == nil {
		return Check{Name: "database", Status: Fail, Detail: "not connected"}
	}
	if err := opts.DB.PingContext(ctx); err != nil {
		return Check{Name: "database", Status: Fail, Detail: err.Error()}
	}

	var maxVersion int64
	err := opts.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version`).Scan(&maxVersion)
	if err != nil {
		return Check{
			Name:    "database",
			Status:  Fail,
			Detail:  fmt.Sprintf("reachable, but the schema version is unreadable: %v", err),
			Hint:    "the migrations have probably never run",
			Command: "mailx-admin migrate",
		}
	}
	return Check{
		Name:   "database",
		Status: OK,
		Detail: fmt.Sprintf("reachable, schema version %d", maxVersion),
	}
}

func stateCheck(ctx context.Context, opts Options) Check {
	if opts.Store == nil {
		return Check{}
	}
	snap, err := opts.Store.Snapshot(ctx)
	if err != nil {
		return Check{Name: "panel state", Status: Fail, Detail: err.Error()}
	}

	detail := fmt.Sprintf("%d domain(s), %d mailbox(es), %d alias(es)",
		len(snap.Domains), len(snap.Users), len(snap.Aliases))
	status := OK
	if len(snap.Domains) == 0 {
		status = Warn
		detail = "no domains in the database"
	}
	return Check{Name: "panel state", Status: status, Detail: detail}
}
