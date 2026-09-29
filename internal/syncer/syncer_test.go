package syncer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
)

// fakeRecorder stands in for reconcile_runs. The syncer's queueing and
// single-flight behaviour is what these tests are about, and that logic has no
// business needing a database (let alone a cgo one) to be exercised.
type fakeRecorder struct {
	mu     sync.Mutex
	runs   []Run
	nextID int64
	fail   error
}

func (f *fakeRecorder) begin(_ context.Context, run Run) (int64, error) {
	if f.fail != nil {
		return 0, f.fail
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	run.ID = f.nextID
	run.Status = "running"
	run.StartedAt = time.Now()
	f.runs = append(f.runs, run)
	return run.ID, nil
}

func (f *fakeRecorder) finish(_ context.Context, id int64, res *reconciler.Result, runErr error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.runs {
		if f.runs[i].ID != id {
			continue
		}
		now := time.Now()
		f.runs[i].FinishedAt = &now
		f.runs[i].Status = "ok"
		if runErr != nil {
			f.runs[i].Status = "error"
			f.runs[i].Error = runErr.Error()
		}
		if res != nil {
			f.runs[i].Files = res.Changes
			f.runs[i].Drift = res.Drift
		}
	}
	return nil
}

func (f *fakeRecorder) latest(_ context.Context) (*Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.runs) == 0 {
		return nil, nil
	}
	last := f.runs[len(f.runs)-1]
	return &last, nil
}

func (f *fakeRecorder) history(_ context.Context, limit int) ([]Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Run, 0, len(f.runs))
	for i := len(f.runs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, f.runs[i])
	}
	return out, nil
}

func (f *fakeRecorder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

func (f *fakeRecorder) lastRun() *Run {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.runs) == 0 {
		return nil
	}
	last := f.runs[len(f.runs)-1]
	return &last
}

// countingSnapshots returns a fixed snapshot and counts how often it was asked.
type countingSnapshots struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (c *countingSnapshots) Snapshot(context.Context) (*models.Snapshot, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	return &models.Snapshot{
		Domains: []models.Domain{{ID: 1, Name: "example.com", IsPrimary: true, Active: true}},
		Users: []models.User{{
			ID: 1, DomainID: 1, Username: "alice", Email: "alice@example.com",
			PasswordHash: "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$AAA$BBB",
			Active:       true, DomainName: "example.com",
		}},
	}, nil
}

func (c *countingSnapshots) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// testSyncer builds a syncer whose reconciler writes into a temp dir.
func testSyncer(t *testing.T, snaps Snapshotter, rec *fakeRecorder) *Syncer {
	t.Helper()

	dir := t.TempDir()
	r := reconciler.New(reconciler.Config{
		PostfixConfDir:    filepath.Join(dir, "postfix"),
		DovecotConfDir:    filepath.Join(dir, "dovecot"),
		OpenDKIMDir:       filepath.Join(dir, "opendkim"),
		Hostname:          "mail.example.test",
		SkipServiceReload: true, // no systemctl in a unit test
		SkipValidation:    true, // no postmap/postfix/doveconf on a build machine
		BackupDir:         filepath.Join(dir, "backups"),
	}, nil)

	return newWithRecorder(snaps, r, rec, nil)
}

// TestRequestCoalescesABurst — ten clicks must not mean ten reconciles. The
// trigger channel holds one request, and each run renders the latest state, so
// anything dropped is already covered.
func TestRequestCoalescesABurst(t *testing.T) {
	snaps := &countingSnapshots{}
	rec := &fakeRecorder{}
	s := testSyncer(t, snaps, rec)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	for i := 0; i < 10; i++ {
		s.Request("panel:user.create")
	}
	if err := s.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	if got := rec.count(); got == 0 || got > 2 {
		t.Errorf("reconciles = %d for 10 requests, want 1 or 2", got)
	}
	if got := snaps.count(); got != rec.count() {
		t.Errorf("snapshots = %d, reconciles = %d: every run takes exactly one snapshot", got, rec.count())
	}
}

// TestRunNowRecordsSuccess — the whole point of the syncer is that a run leaves
// a trace the panel can show.
func TestRunNowRecordsSuccess(t *testing.T) {
	snaps := &countingSnapshots{}
	rec := &fakeRecorder{}
	s := testSyncer(t, snaps, rec)

	res, err := s.RunNow(context.Background(), "panel:manual")
	if err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	if len(res.Changes) == 0 {
		t.Error("RunNow reported no file changes for a domain and a mailbox")
	}

	run := rec.lastRun()
	if run == nil {
		t.Fatal("the run was not recorded")
	}
	if run.Status != "ok" {
		t.Errorf("recorded status = %q, want ok", run.Status)
	}
	if run.Trigger != "panel:manual" {
		t.Errorf("recorded trigger = %q, want panel:manual", run.Trigger)
	}
	if run.FinishedAt == nil {
		t.Error("the recorded run has no finish time")
	}

	status := s.Status(context.Background())
	if status.Failed() {
		t.Error("Status reports a failure after a successful run")
	}
	if status.Last == nil || status.Last.ID != run.ID {
		t.Errorf("Status.Last = %+v, want the recorded run", status.Last)
	}
}

// TestRunNowRecordsFailure — a failed sync has to be visible, with its error,
// instead of being swallowed the way v1.0.4 swallowed the whole request.
func TestRunNowRecordsFailure(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "conf")
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	// A regular file where a config directory has to be, so every write fails.
	if err := os.WriteFile(filepath.Join(conf, "postfix"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := &fakeRecorder{}
	r := reconciler.New(reconciler.Config{
		PostfixConfDir:    filepath.Join(conf, "postfix"),
		DovecotConfDir:    filepath.Join(conf, "dovecot"),
		OpenDKIMDir:       filepath.Join(conf, "opendkim"),
		Hostname:          "mail.example.test",
		SkipServiceReload: true,
		SkipValidation:    true,
		BackupDir:         filepath.Join(dir, "backups"),
	}, nil)
	s := newWithRecorder(&countingSnapshots{}, r, rec, nil)

	if _, err := s.RunNow(context.Background(), "panel:user.create"); err == nil {
		t.Fatal("RunNow returned nil although no config could be written")
	}

	run := rec.lastRun()
	if run == nil {
		t.Fatal("the failed run was not recorded")
	}
	if run.Status != "error" {
		t.Errorf("recorded status = %q, want error", run.Status)
	}
	if run.Error == "" {
		t.Error("the recorded run carries no error text")
	}

	status := s.Status(context.Background())
	if !status.Failed() {
		t.Error("Status does not report the failure, so no banner would appear")
	}
	if !status.Degraded() {
		t.Error("Status.Degraded is false for a failed run, so the panel would look healthy")
	}
}

// TestRunNowRecordsASnapshotFailure — if the database cannot be read there is
// nothing to sync, and that too has to be visible.
func TestRunNowRecordsASnapshotFailure(t *testing.T) {
	snaps := &countingSnapshots{err: errors.New("database is locked")}
	rec := &fakeRecorder{}
	s := testSyncer(t, snaps, rec)

	if _, err := s.RunNow(context.Background(), "panel:user.create"); err == nil {
		t.Fatal("RunNow returned nil although the snapshot failed")
	}

	run := rec.lastRun()
	if run == nil || run.Status != "error" {
		t.Fatalf("recorded run = %+v, want a recorded error", run)
	}
	if run.Error == "" {
		t.Error("the recorded run carries no error text")
	}
}

// TestRunNowFailsLoudlyWhenTheRunCannotBeRecorded — an unrecorded run is an
// invisible one, and invisible is what v1.0.5 is fixing.
func TestRunNowFailsLoudlyWhenTheRunCannotBeRecorded(t *testing.T) {
	rec := &fakeRecorder{fail: errors.New("disk I/O error")}
	s := testSyncer(t, &countingSnapshots{}, rec)

	if _, err := s.RunNow(context.Background(), "panel:user.create"); err == nil {
		t.Fatal("RunNow returned nil although the run could not be recorded")
	}
}

// TestHistoryIsNewestFirst — the dashboard lists what happened, most recent
// first.
func TestHistoryIsNewestFirst(t *testing.T) {
	rec := &fakeRecorder{}
	s := testSyncer(t, &countingSnapshots{}, rec)

	for i := 0; i < 3; i++ {
		if _, err := s.RunNow(context.Background(), "panel:manual"); err != nil {
			t.Fatalf("RunNow %d: %v", i, err)
		}
	}

	runs := s.History(context.Background())
	if len(runs) != 3 {
		t.Fatalf("History returned %d runs, want 3", len(runs))
	}
	if runs[0].ID <= runs[2].ID {
		t.Errorf("History = %v, want the newest run first", []int64{runs[0].ID, runs[1].ID, runs[2].ID})
	}
}
