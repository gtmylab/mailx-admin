package mutations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/roundcube"
	"github.com/gtmylab/mailx-admin/internal/store"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrInvalidInput = errors.New("invalid input")
)

// Service orchestrates DB writes + reconciliation + audit.
//
// Layering rule that the v1.0.4 freeze violated: the transaction must never be
// open while anything else talks to the database. SQLite runs with a
// single-connection pool (see internal/db), so a second caller does not get an
// error — it waits for the connection the transaction is holding, forever.
type Service struct {
	db       *sql.DB
	store    *store.Store
	rec      *reconciler.Reconciler
	preview  *reconciler.Reconciler // dry run: never writes a file, never reloads
	auditor  *audit.Logger
	hostname string

	// roundcube pre-seeds a new mailbox in Roundcube's own database. Nil when
	// the [roundcube] section is disabled, which is the safe default: the
	// panel then never writes into a database it was not told about.
	roundcube RoundcubeSeeder

	// sync queues the config sync that used to run inside the request. When it
	// is nil (tests, and any caller that wires the service by hand) Apply falls
	// back to syncing inline, which is what the CLI-style callers want.
	sync SyncQueuer

	// syncMu serialises an inline sync. Two concurrent mutations would
	// otherwise rewrite the same config files and rebuild the same `postmap`
	// hash maps from two different states, with the slowest write winning.
	syncMu sync.Mutex
}

// RoundcubeSeeder is Roundcube's pre-seed, as the mutation service needs it:
// an idempotent "make webmail know about this mailbox".
//
// It is an interface (and the concrete type lives in internal/roundcube) so
// the service can be tested, and so a deployment without Roundcube wires
// nothing at all.
type RoundcubeSeeder interface {
	EnsureUser(ctx context.Context, login string) (roundcube.Result, error)
}

// SyncQueuer is the background syncer. Declared here as a one-method interface
// so the mutation service can be exercised without a running worker.
type SyncQueuer interface {
	Request(trigger string)
}

func New(db *sql.DB, st *store.Store, rec *reconciler.Reconciler, aud *audit.Logger, hostname string, queue SyncQueuer, roundcube RoundcubeSeeder) *Service {
	return &Service{
		db:        db,
		store:     st,
		rec:       rec,
		preview:   newPreviewReconciler(rec),
		auditor:   aud,
		hostname:  hostname,
		sync:      queue,
		roundcube: roundcube,
	}
}

// newPreviewReconciler derives the reconciler used by the preview endpoints:
// same paths and hostname, but DryRun, no service reload and no auditor.
//
// The nil auditor is not an oversight. Preview runs while a transaction is open,
// and audit writes go through the connection pool — the one connection the
// transaction holds. Logging from inside that transaction is the deadlock this
// release fixes, so the preview reconciler gets no logger at all.
func newPreviewReconciler(rec *reconciler.Reconciler) *reconciler.Reconciler {
	cfg := rec.Config()
	cfg.DryRun = true
	cfg.SkipServiceReload = true
	return reconciler.New(cfg, nil)
}

// Actor identifies who initiated a mutation.
type Actor struct {
	Name     string // "admin:alice", "cli:seed", "system:auto"
	RemoteIP string
}

// Result describes the outcome of a mutation.
type Result struct {
	Changes      []reconciler.FileChange
	ReloadedSvcs []string
	Warnings     []string

	// Maildirs names the mailbox directories the inline reconcile created.
	// Empty when the sync was queued: the worker creates them and the dashboard
	// reports it there. `mailbox add` reconciles inline precisely so that it can
	// tell the operator the mailbox is deliverable, not merely recorded.
	Maildirs []string
}

// Preview runs a mutation in "what-if" mode: it validates, renders the configs
// from the pending (uncommitted) state and returns the diff.
//
// Guarantees, all of which the previous implementation broke: the transaction is
// always rolled back, no file is written (the reconciler it borrows is DryRun),
// and no service is reloaded. Clicking "Preview" used to write the real config
// files and reload Postfix and Dovecot.
func (s *Service) Preview(ctx context.Context, fn func(tx *sql.Tx) error) (*Result, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin preview tx: %w", err)
	}
	defer tx.Rollback() // never commit in preview

	if err := fn(tx); err != nil {
		return nil, err
	}

	// Snapshot from the uncommitted tx — we need to query through the tx
	// to see the pending writes.
	snap, err := s.snapshotTx(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("snapshot for preview: %w", err)
	}

	res, err := s.preview.Reconcile(ctx, snap)
	if err != nil {
		return nil, fmt.Errorf("preview reconcile: %w", err)
	}

	return &Result{
		Changes:      res.Changes,
		ReloadedSvcs: res.ReloadedSvcs,
	}, nil
}

// Apply runs a mutation for real: commit the DB, queue the config sync, audit.
//
// Order matters, and it is the opposite of v1.0.4:
//
//  1. The transaction is opened, fn runs, and it is closed again. Nothing else
//     touches the database while it is open — no audit insert, no reconcile.
//  2. The configuration is synced *outside* the request, by the background
//     syncer.
//
// v1.0.4 did both wrong. It audited a failed mutation while its transaction
// still held the single SQLite connection, so the audit insert waited for a
// connection that only the caller could release — one failed create hung the
// request, every later request queued behind it, and Apache answered 502 until
// someone restarted the service. And it reconciled inside the request, so
// postmap, `postfix check` and `systemctl reload` all had to finish before the
// admin got an answer; a single slow helper was enough to lose the response, and
// a failure was reported nowhere.
//
// Committing before the sync means the database is the source of truth: a user
// that is in it is visible in the panel immediately, and the sync catches up.
// Its outcome is recorded in reconcile_runs and shown on the dashboard.
func (s *Service) Apply(ctx context.Context, actor Actor, action string, detail map[string]any, fn func(tx *sql.Tx) error) (*Result, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := fn(tx); err != nil {
		// Release the connection before auditing: the audit insert goes through
		// the pool, and holding the tx here is the v1.0.4 deadlock.
		_ = tx.Rollback()
		s.auditFailure(ctx, actor, action, detail, err)
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	committed = true

	res := &Result{}
	if s.sync != nil {
		// Queued, not run: the response must not wait for postmap and systemctl.
		// The run renders the latest committed state, so this action's rows are
		// already included even if it coalesces with the next click.
		s.sync.Request(action)
		res.Warnings = append(res.Warnings, "Configuration sync queued; the dashboard shows its progress.")
	} else {
		recRes, err := s.reconcileLatest(ctx)
		if err != nil {
			s.auditFailure(ctx, actor, action, detail, err)
			return nil, fmt.Errorf("saved to the database, but applying the mail configuration failed: %w", err)
		}
		res.Changes = recRes.Changes
		res.ReloadedSvcs = recRes.ReloadedSvcs
		res.Maildirs = recRes.Maildirs
		res.Warnings = append(res.Warnings, recRes.Warnings...)
		_ = s.auditor.Log(ctx, audit.Entry{
			Actor:    actor.Name,
			Action:   action,
			Result:   "ok",
			Detail:   mergeDetail(detail, recRes),
			RemoteIP: actor.RemoteIP,
		})
		return res, nil
	}

	_ = s.auditor.Log(ctx, audit.Entry{
		Actor:    actor.Name,
		Action:   action,
		Result:   "ok",
		Detail:   mergeDetail(detail, map[string]any{"sync": "queued"}),
		RemoteIP: actor.RemoteIP,
	})

	return res, nil
}

// reconcileLatest renders and applies the configuration for the current
// committed state. It is the fallback for callers without a syncer (the CLI and
// tests); the panel always has one.
//
// The snapshot is taken *inside* the lock on purpose: taking it outside would
// let a sync render a state that a later sync has already replaced, and the
// older files would win.
func (s *Service) reconcileLatest(ctx context.Context) (*reconciler.Result, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	return s.rec.Reconcile(ctx, snap)
}

// snapshotTx loads a Snapshot through the given transaction, so a preview can
// render the pending (not yet committed) writes. Reads only — the pool's single
// connection is already held by this tx and nothing else may ask for it.
func (s *Service) snapshotTx(ctx context.Context, tx *sql.Tx) (*models.Snapshot, error) {
	return s.store.SnapshotTx(ctx, tx)
}

func (s *Service) auditFailure(ctx context.Context, actor Actor, action string, detail map[string]any, err error) {
	_ = s.auditor.Log(ctx, audit.Entry{
		Actor:    actor.Name,
		Action:   action,
		Result:   "error",
		Detail:   mergeDetail(detail, map[string]any{"error": err.Error()}),
		RemoteIP: actor.RemoteIP,
	})
}

func mergeDetail(a map[string]any, extra any) map[string]any {
	out := make(map[string]any, len(a)+1)
	for k, v := range a {
		out[k] = v
	}
	switch e := extra.(type) {
	case map[string]any:
		for k, v := range e {
			out[k] = v
		}
	case *reconciler.Result:
		b, _ := json.Marshal(e.Changes)
		out["changes"] = json.RawMessage(b)
		out["reloaded"] = e.ReloadedSvcs
	}
	return out
}
