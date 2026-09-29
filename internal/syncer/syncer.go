// Package syncer renders the configs in the background.
//
// Why this exists: v1.0.4 did the whole reconcile inside the request that
// triggered it — postmap, `postfix check`, `doveconf -n` and
// `systemctl reload-or-restart` all had to finish before "Create user" answered.
// One slow or wedged helper turned an ordinary click into a 502, and the failure
// left no trace anywhere in the panel.
//
// The syncer instead:
//
//   - queues a single request per burst: mutations coalesce, so ten clicks cause
//     two reconciles, and each one renders the *latest* state from the database;
//   - records every run in reconcile_runs (trigger, status, changed files,
//     drift, error), which the dashboard, the banner and `mailx-admin doctor`
//     read;
//   - never holds a database transaction while it runs, so it cannot deadlock
//     the single SQLite connection.
package syncer

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
)

const (
	// runTimeout bounds one reconcile. The reconciler's own helpers are already
	// bounded (see internal/execx); this covers the whole run.
	runTimeout = 3 * time.Minute

	// statusTTL caches the last run for the banner, which every page render
	// asks for. Without it every page load would cost a query.
	statusTTL = 2 * time.Second

	// historyLimit is how many runs the dashboard shows.
	historyLimit = 20
)

// Snapshotter supplies the desired state. *store.Store implements it.
type Snapshotter interface {
	Snapshot(ctx context.Context) (*models.Snapshot, error)
}

// Run is one recorded reconcile, mirroring a reconcile_runs row.
type Run struct {
	ID         int64
	StartedAt  time.Time
	FinishedAt *time.Time
	Trigger    string
	DryRun     bool
	Status     string // running | ok | error
	Files      []reconciler.FileChange
	Drift      []reconciler.Drift
	Error      string
}

// Changed counts the files this run actually rewrote.
func (r Run) Changed() int {
	n := 0
	for _, f := range r.Files {
		if f.Action != "unchanged" {
			n++
		}
	}
	return n
}

// Status is what the panel renders.
type Status struct {
	Running bool
	Pending bool // a request arrived while a run was in flight
	Last    *Run
}

// Failed reports whether the last completed run failed.
func (s *Status) Failed() bool {
	return s.Last != nil && s.Last.Status == "error"
}

// Degraded reports whether the panel's config is known to be out of sync —
// either the last run failed, or it dropped entries the panel does not manage.
func (s *Status) Degraded() bool {
	if s.Failed() {
		return true
	}
	return s.Last != nil && len(s.Last.Drift) > 0
}

// recorder persists runs. Production uses sqlRecorder; tests use a fake, so the
// queueing logic is testable without a database (and therefore without cgo).
type recorder interface {
	begin(ctx context.Context, run Run) (int64, error)
	finish(ctx context.Context, id int64, res *reconciler.Result, runErr error) error
	latest(ctx context.Context) (*Run, error)
	history(ctx context.Context, limit int) ([]Run, error)
}

// Syncer owns the background reconcile loop.
type Syncer struct {
	rec      *reconciler.Reconciler
	snaps    Snapshotter
	recorder recorder
	logger   *slog.Logger

	// trigger has room for one pending request. A burst of mutations fills it
	// and every extra request is dropped on purpose: the queued run renders the
	// latest database state, so a dropped trigger has nothing left to do.
	trigger chan string

	// runMu serialises reconciles. A manual "Sync now" that arrives while the
	// background worker is running waits for it instead of racing it.
	runMu sync.Mutex

	mu       sync.Mutex
	running  bool
	cached   *Run
	cachedAt time.Time
}

// New builds the production syncer, recording into reconcile_runs.
func New(database *sql.DB, snaps Snapshotter, rec *reconciler.Reconciler, logger *slog.Logger) *Syncer {
	return newWithRecorder(snaps, rec, sqlRecorder{db: database}, logger)
}

func newWithRecorder(snaps Snapshotter, rec *reconciler.Reconciler, r recorder, logger *slog.Logger) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Syncer{
		rec:      rec,
		snaps:    snaps,
		recorder: r,
		logger:   logger,
		trigger:  make(chan string, 1),
	}
}

// Start runs the worker until ctx is done. It never blocks the caller.
func (s *Syncer) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case trigger := <-s.trigger:
				runCtx, cancel := context.WithTimeout(ctx, runTimeout)
				s.run(runCtx, trigger)
				cancel()
			}
		}
	}()
}

// Request queues a sync and returns immediately.
func (s *Syncer) Request(trigger string) {
	select {
	case s.trigger <- trigger:
	default:
		s.logger.Debug("sync already queued; request coalesced", "trigger", trigger)
	}
}

// RunNow performs a sync synchronously and returns its result. It is what the
// "Sync now" button calls: the admin asked, so the admin waits — but for one
// reconcile with a bounded deadline, not for a request that also renders a page.
func (s *Syncer) RunNow(ctx context.Context, trigger string) (*reconciler.Result, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.runOnce(ctx, trigger)
}

// run is RunNow plus logging, used by the background worker.
func (s *Syncer) run(ctx context.Context, trigger string) {
	res, err := s.RunNow(ctx, trigger)
	if err != nil {
		s.logger.Error("config sync failed", "trigger", trigger, "err", err)
		return
	}
	changed := 0
	for _, c := range res.Changes {
		if c.Action != "unchanged" {
			changed++
		}
	}
	s.logger.Info("config sync finished",
		"trigger", trigger, "changed", changed,
		"reloaded", res.ReloadedSvcs, "drift", len(res.Drift),
		"warnings", len(res.Warnings))
}

// runOnce records and executes a single reconcile.
func (s *Syncer) runOnce(ctx context.Context, trigger string) (*reconciler.Result, error) {
	s.setRunning(true)
	defer s.setRunning(false)

	runID, err := s.recorder.begin(ctx, Run{Trigger: trigger})
	if err != nil {
		// Recording is how the panel stays honest about sync state; without a
		// row the run would be invisible, so fail instead of syncing silently.
		return nil, err
	}

	snap, err := s.snaps.Snapshot(ctx)
	if err != nil {
		_ = s.recorder.finish(ctx, runID, nil, err)
		s.invalidate()
		return nil, err
	}

	// The reconciler returns a partial result even when it fails; record both,
	// so the dashboard can show which files were written before it gave up.
	res, recErr := s.rec.Reconcile(ctx, snap)
	_ = s.recorder.finish(ctx, runID, res, recErr)
	s.invalidate()
	if recErr != nil {
		return res, recErr
	}
	return res, nil
}

func (s *Syncer) invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cachedAt = time.Time{}
}

func (s *Syncer) setRunning(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = v
}

// Status reports what the panel shows. It never fails: an unreadable history
// means "unknown", which the banner renders as a neutral state rather than as an
// error on every page.
func (s *Syncer) Status(ctx context.Context) *Status {
	run := s.cachedRun(ctx)

	s.mu.Lock()
	running := s.running
	s.mu.Unlock()

	return &Status{
		Running: running,
		Pending: len(s.trigger) > 0,
		Last:    run,
	}
}

func (s *Syncer) cachedRun(ctx context.Context) *Run {
	s.mu.Lock()
	run, at := s.cached, s.cachedAt
	s.mu.Unlock()

	if run != nil && time.Since(at) < statusTTL {
		return run
	}

	fresh, err := s.recorder.latest(ctx)
	if err != nil {
		s.logger.Warn("sync history is unreadable", "err", err)
		return run
	}

	s.mu.Lock()
	s.cached, s.cachedAt = fresh, time.Now()
	s.mu.Unlock()
	return fresh
}

// History returns the most recent runs, newest first.
func (s *Syncer) History(ctx context.Context) []Run {
	runs, err := s.recorder.history(ctx, historyLimit)
	if err != nil {
		s.logger.Warn("sync history is unreadable", "err", err)
		return nil
	}
	return runs
}

// Wait blocks until the queued work has been picked up and finished. Tests use
// it; production code has no reason to.
func (s *Syncer) Wait(ctx context.Context) error {
	for {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()

		if !running && len(s.trigger) == 0 {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}
