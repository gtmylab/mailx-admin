package reconciler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// TestDetectDrift_ReportsHandAddedEntries — the renderer writes whole files, so
// a mailbox or alias that was added by hand (useradd + /etc/dovecot/users, an
// extra line in /etc/postfix/virtual) is not in the render and disappears. It
// has to be reported, not deleted in silence.
func TestDetectDrift_ReportsHandAddedEntries(t *testing.T) {
	before := []byte("# managed by mailx-admin\n" +
		"alice@example.com\t/var/mail/vhosts/example.com/alice/Maildir/\n" +
		"legacy@example.com\t/var/mail/vhosts/example.com/legacy/Maildir/\n")
	after := []byte("# managed by mailx-admin\n" +
		"alice@example.com\t/var/mail/vhosts/example.com/alice/Maildir/\n")

	drift := detectDrift("/etc/postfix/vmailbox", before, after)
	if drift == nil {
		t.Fatal("detectDrift returned nil, want the hand-added mailbox reported")
	}
	if drift.Count != 1 {
		t.Errorf("Count = %d, want 1", drift.Count)
	}
	if len(drift.Lines) != 1 || !strings.Contains(drift.Lines[0], "legacy@example.com") {
		t.Errorf("Lines = %q, want the legacy mailbox", drift.Lines)
	}
}

func TestDetectDrift_IgnoresCommentsAndBlanks(t *testing.T) {
	before := []byte("# comment one\n\nalice@example.com\talice@example.com\n# comment two\n")
	after := []byte("alice@example.com\talice@example.com\n")

	if drift := detectDrift("/etc/postfix/virtual", before, after); drift != nil {
		t.Errorf("detectDrift reported %q, want nil: comments and blank lines are not entries", drift.Lines)
	}
}

func TestDetectDrift_CountsDuplicateLines(t *testing.T) {
	before := []byte("dup@example.com\talice@example.com\ndup@example.com\talice@example.com\n")
	after := []byte("dup@example.com\talice@example.com\n")

	drift := detectDrift("/etc/postfix/virtual", before, after)
	if drift == nil || drift.Count != 1 {
		t.Fatalf("detectDrift = %+v, want exactly one removed duplicate", drift)
	}
}

// fixtureSnapshotForDrift is one domain with one mailbox: the smallest state the
// reconciler renders a full config set from.
func fixtureSnapshotForDrift() *models.Snapshot {
	return &models.Snapshot{
		Domains: []models.Domain{{ID: 1, Name: "example.com", IsPrimary: true, Active: true}},
		Users: []models.User{{
			ID: 1, DomainID: 1, Username: "alice", Email: "alice@example.com",
			PasswordHash: "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$AAA$BBB",
			QuotaMB:      1024, Active: true, DomainName: "example.com",
		}},
	}
}

// driftReconciler points every managed path at a temp dir, so a test never
// touches /etc and never reloads anything.
func driftReconciler(t *testing.T) (*Reconciler, string, string) {
	t.Helper()

	dir := t.TempDir()
	postfix := filepath.Join(dir, "postfix")
	if err := os.MkdirAll(postfix, 0o755); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backups")

	return New(Config{
		PostfixConfDir:    postfix,
		DovecotConfDir:    filepath.Join(dir, "dovecot"),
		OpenDKIMDir:       filepath.Join(dir, "opendkim"),
		Hostname:          "mail.example.test",
		SkipServiceReload: true,
		SkipValidation:    true, // no postmap/postfix/doveconf on a build machine
		BackupDir:         backupDir,
	}, nil), postfix, backupDir
}

// TestReconcilePreservesEntriesThePanelDoesNotManage walks the whole path: a
// hand-added line in a managed file, a sync that does not know about it, and the
// requirement that the previous file survives somewhere reachable.
func TestReconcilePreservesEntriesThePanelDoesNotManage(t *testing.T) {
	rec, postfix, _ := driftReconciler(t)

	// A Postfix virtual map with one entry the panel knows nothing about.
	virtual := filepath.Join(postfix, "virtual")
	const legacy = "legacy@example.com\tlegacy@example.com"
	if err := os.WriteFile(virtual, []byte("alice@example.com\talice@example.com\n"+legacy+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := rec.Reconcile(context.Background(), fixtureSnapshotForDrift())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(res.Drift) == 0 {
		t.Fatalf("Reconcile reported no drift; the legacy mailbox would vanish unnoticed (warnings: %v)", res.Warnings)
	}

	var found *Drift
	for i := range res.Drift {
		if res.Drift[i].Path == virtual {
			found = &res.Drift[i]
		}
	}
	if found == nil {
		t.Fatalf("drift does not mention %s: %+v", virtual, res.Drift)
	}
	if found.Count != 1 || !strings.Contains(strings.Join(found.Lines, "\n"), "legacy@example.com") {
		t.Errorf("drift = %+v, want the legacy entry", found)
	}

	if found.Backup == "" {
		t.Fatal("no copy was taken before the hand-added entry was dropped")
	}
	kept, err := os.ReadFile(found.Backup)
	if err != nil {
		t.Fatalf("read the preserved copy: %v", err)
	}
	if !strings.Contains(string(kept), legacy) {
		t.Errorf("the preserved copy %s does not contain the dropped entry:\n%s", found.Backup, kept)
	}

	// The synced file no longer contains the entry: this is the documented
	// behaviour (warn, keep a copy, offer to import) rather than silent data
	// loss.
	now, err := os.ReadFile(virtual)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(now), legacy) {
		t.Errorf("the synced file still contains the hand-added entry:\n%s", now)
	}

	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "virtual") || strings.Contains(w, "legacy") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("Warnings = %v, want one naming the file or the entry", res.Warnings)
	}
}

// TestReconcileKeepsThePreviousVersionOnPlainUpdates — even without drift the
// previous file is preserved, so an operator can always see what a sync changed.
// v1.0.4 copied the file after WriteFile had replaced it, so its "backup" was a
// copy of the new content.
func TestReconcileKeepsThePreviousVersionOnPlainUpdates(t *testing.T) {
	rec, postfix, backupDir := driftReconciler(t)

	virtual := filepath.Join(postfix, "virtual")
	if err := os.WriteFile(virtual, []byte("old@example.com\told@example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := rec.Reconcile(context.Background(), fixtureSnapshotForDrift()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("read the backup dir: %v", err)
	}
	var dirs []string
	for _, e := range entries {
		dirs = append(dirs, e.Name())
	}
	if len(dirs) == 0 {
		t.Fatal("no backup directory was created at all")
	}

	// The per-run folder is timestamped, so find the copy instead of rebuilding
	// its name.
	var kept []byte
	_ = filepath.WalkDir(backupDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, rerr := os.ReadFile(path); rerr == nil && strings.Contains(string(b), "old@example.com") {
			kept = b
		}
		return nil
	})
	if kept == nil {
		t.Fatalf("no preserved copy holds the previous content (backup dirs: %v)", dirs)
	}
}
