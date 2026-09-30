package mutations

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/store"
)

// ---------------------------------------------------------------------------
// A pool with exactly one connection, like the one internal/db opens for SQLite
// ---------------------------------------------------------------------------

// Why a fake driver instead of SQLite: mattn/go-sqlite3 is cgo-only, and this
// repository is also built with CGO_ENABLED=0, where the driver compiles to a
// stub that cannot open a database at all. The bug being guarded against is not
// about SQL, it is about *pool exhaustion*: SQLite is opened with
// SetMaxOpenConns(1), so whoever holds the connection holds the whole database.
// Reproducing that needs only a driver with the same property, and it then also
// runs in every build configuration.
const fakeDriverName = "mutations_single_conn"

type fakeEvent struct {
	kind  string // begin, commit, rollback, exec
	query string
}

type fakeDriver struct {
	mu     sync.Mutex
	events []fakeEvent
}

func (d *fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{drv: d}, nil }

func (d *fakeDriver) record(e fakeEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, e)
}

func (d *fakeDriver) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = nil
}

func (d *fakeDriver) snapshot() []fakeEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]fakeEvent(nil), d.events...)
}

var (
	registerFake sync.Once
	fakeRegistry = &fakeDriver{}
)

func openFakeDB(t *testing.T) *sql.DB {
	t.Helper()

	registerFake.Do(func() { sql.Register(fakeDriverName, fakeRegistry) })
	fakeRegistry.reset()

	pool, err := sql.Open(fakeDriverName, "single-connection")
	if err != nil {
		t.Fatalf("sql.Open(%s): %v", fakeDriverName, err)
	}
	// The property that matters, copied from internal/db.
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = pool.Close() })

	return pool
}

type fakeConn struct{ drv *fakeDriver }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("fakeConn: statements have to go through ExecContext")
}

func (c *fakeConn) Close() error { return nil }

func (c *fakeConn) Begin() (driver.Tx, error) {
	c.drv.record(fakeEvent{kind: "begin"})
	return &fakeTx{drv: c.drv}, nil
}

// ExecContext is what database/sql calls for both db.ExecContext and
// tx.ExecContext, because this connection implements driver.ExecerContext.
// Nothing is executed; the statement is only recorded.
func (c *fakeConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.drv.record(fakeEvent{kind: "exec", query: query})
	return driver.RowsAffected(1), nil
}

type fakeTx struct{ drv *fakeDriver }

func (t *fakeTx) Commit() error {
	t.drv.record(fakeEvent{kind: "commit"})
	return nil
}

func (t *fakeTx) Rollback() error {
	t.drv.record(fakeEvent{kind: "rollback"})
	return nil
}

// mustReturn fails the test if fn does not return in time. A deadlocked pool
// shows up as a hang rather than as an error, so a plain call would stall the
// whole test binary instead of reporting the bug.
func mustReturn(t *testing.T, budget time.Duration, fn func() error) error {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- fn() }()

	select {
	case err := <-done:
		return err
	case <-time.After(budget):
		t.Fatalf("call did not return within %s: something is holding the database connection", budget)
		return nil
	}
}

// TestApplyQueuesTheSyncInsteadOfRunningIt — the panel path. A mutation must not
// wait for postmap and systemctl; it queues a run and answers (v1.0.4 answered
// 502 instead when a helper stalled).
func TestApplyQueuesTheSyncInsteadOfRunningIt(t *testing.T) {
	pool := openFakeDB(t)
	queue := &recordingQueue{}
	svc := &Service{db: pool, auditor: audit.New(pool), sync: queue}

	var res *Result
	mustReturn(t, 15*time.Second, func() error {
		var applyErr error
		res, applyErr = svc.Apply(
			context.Background(),
			Actor{Name: "admin:test"},
			"user.create",
			map[string]any{"email": "alice@example.com"},
			func(tx *sql.Tx) error {
				_, err := tx.ExecContext(context.Background(), `INSERT INTO users (email) VALUES ('alice@example.com')`)
				return err
			},
		)
		return applyErr
	})

	if got := queue.requests(); len(got) != 1 || got[0] != "user.create" {
		t.Errorf("queued sync requests = %v, want exactly [user.create]", got)
	}
	if res == nil || len(res.Warnings) == 0 {
		t.Errorf("Apply result = %+v, want a warning that the sync is queued", res)
	}
	// The transaction must be closed by then: the audit insert goes through the
	// same pool.
	events := fakeRegistry.snapshot()
	if len(events) == 0 {
		t.Fatal("no database activity was recorded")
	}
	last := events[len(events)-1]
	if last.kind != "exec" || !strings.Contains(last.query, "audit_log") {
		t.Errorf("last database event = %+v, want the success audit insert", last)
	}
}

// recordingQueue captures what Apply asks the syncer to do.
type recordingQueue struct {
	mu    sync.Mutex
	trigs []string
}

func (q *recordingQueue) Request(trigger string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.trigs = append(q.trigs, trigger)
}

func (q *recordingQueue) requests() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.trigs...)
}

// ---------------------------------------------------------------------------
// The freeze regression
// ---------------------------------------------------------------------------

// TestApplyFailureDoesNotHoldTheTransaction is the regression test for the
// v1.0.4 panel freeze: "create user" (and everything else) answered 502 until
// the service was restarted.
//
// A failed mutation audited itself *while its transaction was still open*. With
// SQLite's single-connection pool that audit insert waited for the connection
// the transaction was holding, so the request never finished, every later
// request queued behind it, and Apache gave up after 60s with a 502.
func TestApplyFailureDoesNotHoldTheTransaction(t *testing.T) {
	pool := openFakeDB(t)
	svc := &Service{db: pool, auditor: audit.New(pool)}

	var applyErr error
	mustReturn(t, 15*time.Second, func() error {
		_, applyErr = svc.Apply(
			context.Background(),
			Actor{Name: "admin:test", RemoteIP: "203.0.113.9"},
			"user.create",
			map[string]any{"email": "alice@example.com"},
			func(*sql.Tx) error {
				return fmt.Errorf("%w: user alice@example.com already exists", ErrConflict)
			},
		)
		return applyErr
	})

	if !errors.Is(applyErr, ErrConflict) {
		t.Errorf("Apply error = %v, want ErrConflict", applyErr)
	}

	// The transaction has to be closed *before* the audit write: that is the
	// whole fix. Auditing first is what deadlocks, so assert the ordering
	// rather than just "it returned".
	events := fakeRegistry.snapshot()
	rollbackAt, auditAt := -1, -1
	for i, e := range events {
		switch {
		case e.kind == "rollback" && rollbackAt < 0:
			rollbackAt = i
		case e.kind == "exec" && strings.Contains(e.query, "audit_log") && auditAt < 0:
			auditAt = i
		}
	}
	if rollbackAt < 0 {
		t.Fatalf("the failed transaction was never rolled back: %+v", events)
	}
	if auditAt < 0 {
		t.Fatalf("the failure never reached the audit log: %+v", events)
	}
	if auditAt < rollbackAt {
		t.Errorf("audit insert (event %d) ran before the rollback (event %d): the pool is still held", auditAt, rollbackAt)
	}
}

// ---------------------------------------------------------------------------
// End-to-end tests against a real SQLite database
// ---------------------------------------------------------------------------

// sqliteTestService builds a Service on a real database with the shipped
// migrations applied, and a reconciler whose config directories live in a temp
// dir so nothing outside it is touched. It skips when this build's SQLite
// driver is the non-cgo stub (see internal/db).
func sqliteTestService(t *testing.T) (*Service, *db.DB, string) {
	t.Helper()

	dir := t.TempDir()
	database, err := db.Open(db.Config{Driver: db.DriverSQLite, SQLitePath: filepath.Join(dir, "state.db")})
	if err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skipf("sqlite driver is a non-cgo stub in this build: %v", err)
		}
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	ctx := context.Background()
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	conf := filepath.Join(dir, "conf")
	rec := reconciler.New(reconciler.Config{
		PostfixConfDir:    filepath.Join(conf, "postfix"),
		DovecotConfDir:    filepath.Join(conf, "dovecot"),
		OpenDKIMDir:       filepath.Join(conf, "opendkim"),
		Hostname:          "mail.example.test",
		SkipServiceReload: true, // there is no systemctl in a unit test
		SkipValidation:    true, // nor postmap/postfix/doveconf
		SkipMaildirs:      true, // nor a /var/mail/vhosts to write into
		BackupDir:         filepath.Join(dir, "backups"),
	}, nil)

	// nil queue: these tests exercise the inline path (the panel always passes a
	// syncer, see internal/syncer).
	svc := New(database.DB, store.New(database), rec, audit.New(database.DB), "mail.example.test", nil)
	return svc, database, conf
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()

	n := 0
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return n
}

// TestApplyCommitsBeforeSyncingConfig pins the order that replaced
// roll-back-on-reconcile-failure: the database is the source of truth, and a
// sync that fails is reported and audited instead of silently discarding the
// admin's change.
func TestApplyCommitsBeforeSyncingConfig(t *testing.T) {
	svc, database, conf := sqliteTestService(t)
	ctx := context.Background()

	// Make the reconcile fail: a regular file where a config directory has to
	// be, so WriteFile's MkdirAll fails with ENOTDIR on every managed file.
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conf, "postfix"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := mustReturn(t, 30*time.Second, func() error {
		_, err := svc.Apply(ctx, Actor{Name: "admin:test"}, "domain.create",
			map[string]any{"domain": "example.test"},
			func(tx *sql.Tx) error {
				return applyCreateDomainTx(ctx, tx, CreateDomainInput{Name: "example.test"}, "", "")
			})
		return err
	})
	if err == nil {
		t.Fatal("Apply returned nil although the config could not be written")
	}
	if !strings.Contains(err.Error(), "saved to the database") {
		t.Errorf("Apply error = %q, want it to say that the change was saved and only the sync failed", err)
	}

	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE name = 'example.test'`).Scan(&n); err != nil {
		t.Fatalf("count domains: %v", err)
	}
	if n != 1 {
		t.Errorf("domains named example.test = %d, want 1: the change must be committed even when the sync fails", n)
	}

	var result string
	if err := database.QueryRowContext(ctx, `SELECT result FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&result); err != nil {
		t.Fatalf("read audit_log: %v", err)
	}
	if result != "error" {
		t.Errorf("last audit result = %q, want %q", result, "error")
	}
}

// TestPreviewIsADryRun — the preview modal used to borrow the *live*
// reconciler, so merely opening "Create user" and letting the preview run wrote
// the real Postfix and Dovecot files and reloaded both services.
func TestPreviewIsADryRun(t *testing.T) {
	svc, database, conf := sqliteTestService(t)
	ctx := context.Background()

	// Seed one domain for real, so the preview has something to render.
	seedErr := mustReturn(t, 30*time.Second, func() error {
		_, err := svc.Apply(ctx, Actor{Name: "admin:test"}, "domain.create",
			map[string]any{"domain": "example.test"},
			func(tx *sql.Tx) error {
				return applyCreateDomainTx(ctx, tx, CreateDomainInput{Name: "example.test"}, "", "")
			})
		return err
	})
	if seedErr != nil {
		t.Fatalf("seed domain: %v", seedErr)
	}
	before := countFiles(t, conf)
	if before == 0 {
		t.Fatal("Apply wrote no config file at all: the reconcile did not run")
	}

	var res *Result
	err := mustReturn(t, 30*time.Second, func() error {
		var previewErr error
		res, previewErr = svc.Preview(ctx, func(tx *sql.Tx) error {
			return applyCreateDomainTx(ctx, tx, CreateDomainInput{Name: "preview.test"}, "", "")
		})
		return previewErr
	})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}

	if after := countFiles(t, conf); after != before {
		t.Errorf("file count under the config dir changed from %d to %d: a preview must not write", before, after)
	}

	var n int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE name = 'preview.test'`).Scan(&n); err != nil {
		t.Fatalf("count domains: %v", err)
	}
	if n != 0 {
		t.Errorf("domains named preview.test = %d, want 0: a preview must never commit", n)
	}

	// The diff modal is rendered from Before/After, which the reconciler only
	// fills in on a dry run. A preview that is not dry is also an empty diff.
	var sawVirtual bool
	for _, c := range res.Changes {
		if filepath.Base(c.Path) != "virtual" {
			continue
		}
		sawVirtual = true
		if len(c.Before) == 0 && len(c.After) == 0 {
			t.Errorf("preview change for %s carries no content: the diff modal would render empty", c.Path)
		}
	}
	if !sawVirtual {
		t.Errorf("the preview reported no change to the postfix virtual map: %+v", res.Changes)
	}
}
