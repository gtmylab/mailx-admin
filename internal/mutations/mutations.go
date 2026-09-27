package mutations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/store"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrInvalidInput = errors.New("invalid input")
)

// Service orchestrates DB writes + reconciliation + audit.
type Service struct {
	db       *sql.DB
	store    *store.Store
	rec      *reconciler.Reconciler
	auditor  *audit.Logger
	hostname string
}

func New(db *sql.DB, st *store.Store, rec *reconciler.Reconciler, aud *audit.Logger, hostname string) *Service {
	return &Service{
		db:       db,
		store:    st,
		rec:      rec,
		auditor:  aud,
		hostname: hostname,
	}
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
}

// Preview runs a mutation in "what-if" mode: it validates, computes the diff,
// and rolls back without touching disk or reloading services.
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

	// Dry-run reconcile
	res, err := s.rec.Reconcile(ctx, snap)
	if err != nil {
		return nil, fmt.Errorf("preview reconcile: %w", err)
	}

	return &Result{
		Changes:      res.Changes,
		ReloadedSvcs: res.ReloadedSvcs,
	}, nil
}

// Apply runs a mutation for real: commit DB, reconcile, audit.
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
		s.auditFailure(ctx, actor, action, detail, err)
		return nil, err
	}

	// Snapshot from tx so the reconcile sees the pending state
	snap, err := s.snapshotTx(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	// Reconcile BEFORE commit — if config rendering fails, we don't commit.
	recRes, err := s.rec.Reconcile(ctx, snap)
	if err != nil {
		s.auditFailure(ctx, actor, action, detail, err)
		return nil, fmt.Errorf("reconcile: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	committed = true

	// Audit success
	_ = s.auditor.Log(ctx, audit.Entry{
		Actor:    actor.Name,
		Action:   action,
		Result:   "ok",
		Detail:   mergeDetail(detail, recRes),
		RemoteIP: actor.RemoteIP,
	})

	return &Result{
		Changes:      recRes.Changes,
		ReloadedSvcs: recRes.ReloadedSvcs,
	}, nil
}

// snapshotTx loads a Snapshot through the given transaction.
// We duplicate the store's Snapshot logic here so it reads from tx, not the pool.
func (s *Service) snapshotTx(ctx context.Context, tx *sql.Tx) (*models.Snapshot, error) {
	// Reuse the store's logic by temporarily swapping... no. Cleanest is to
	// expose a tx-taking method on the store.
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

var _ = time.Now
var _ = auth.Session{}
