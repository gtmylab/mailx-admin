package seed

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/store"
)

const fakeHash = "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$AAA$BBB"

func adoptFixture() *Found {
	return &Found{
		Domains: []FoundDomain{
			{Name: "example.com", IsPrimary: true, DKIMPrivateKey: "/etc/opendkim/keys/example.com/default.private"},
			{Name: "example.org"},
		},
		Users: []FoundUser{
			{Email: "alice@example.com", Domain: "example.com", LocalPart: "alice", PasswordHash: fakeHash, QuotaMB: 2048},
			{Email: "bob@example.org", Domain: "example.org", LocalPart: "bob", PasswordHash: fakeHash, QuotaMB: 1024},
			{Email: "nohash@example.com", Domain: "example.com", LocalPart: "nohash"},
		},
		Aliases: []FoundAlias{
			{Domain: "example.com", Source: "sales", Destination: "alice@example.com"},
			{Domain: "unknown.test", Source: "info", Destination: "alice@example.com"},
		},
	}
}

// TestComputePlanImportsWhatThePanelDoesNotHave — this is the "my useradd
// mailbox is invisible in the panel" fix: what is on the server decides what the
// plan contains, not what the panel already knows.
func TestComputePlanImportsWhatThePanelDoesNotHave(t *testing.T) {
	plan := computePlan(adoptFixture(),
		map[string]bool{"example.com": true}, // the domain is already known
		map[string]bool{"alice@example.com": true},
		map[string]bool{})

	if len(plan.Domains) != 1 || plan.Domains[0].Key != "example.org" {
		t.Errorf("Domains = %+v, want only example.org", plan.Domains)
	}
	if len(plan.Users) != 1 || plan.Users[0].Key != "bob@example.org" {
		t.Errorf("Users = %+v, want only bob@example.org", plan.Users)
	}
	if len(plan.Aliases) != 1 || plan.Aliases[0].Key != "sales@example.com" {
		t.Errorf("Aliases = %+v, want only sales@example.com", plan.Aliases)
	}

	// The mailbox without a hash cannot be imported, and saying so beats
	// creating an account nobody can log into.
	if len(plan.Skipped) != 2 {
		t.Fatalf("Skipped = %+v, want the hash-less mailbox and the orphan alias", plan.Skipped)
	}
	var sawNoHash, sawOrphan bool
	for _, s := range plan.Skipped {
		if s.Key == "nohash@example.com" && strings.Contains(s.Detail, "password hash") {
			sawNoHash = true
		}
		if s.Key == "info@unknown.test" {
			sawOrphan = true
		}
	}
	if !sawNoHash || !sawOrphan {
		t.Errorf("Skipped = %+v, want the hash-less mailbox and the unknown-domain alias", plan.Skipped)
	}
}

// TestComputePlanIsIdempotent — everything already present means nothing to do,
// which is what makes pressing "Import from server" twice harmless.
func TestComputePlanIsIdempotent(t *testing.T) {
	plan := computePlan(adoptFixture(),
		map[string]bool{"example.com": true, "example.org": true},
		map[string]bool{"alice@example.com": true, "bob@example.org": true},
		map[string]bool{"sales@example.com": true})

	if !plan.Empty() {
		t.Errorf("plan = %+v, want nothing to import", plan)
	}
}

// TestAdoptWritesThenReportsNothingLeft is the database half: the plan has to be
// what actually gets written, and the state afterwards has to be stable.
//
// It needs the real SQLite driver (cgo), so it skips on stub builds; the
// decision logic above is covered in every build.
func TestAdoptWritesThenReportsNothingLeft(t *testing.T) {
	database, err := db.Open(db.Config{
		Driver:     db.DriverSQLite,
		SQLitePath: filepath.Join(t.TempDir(), "state.db"),
	})
	if err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skipf("sqlite driver is a non-cgo stub in this build: %v", err)
		}
		t.Fatalf("open sqlite: %v", err)
	}
	defer database.Close()

	ctx := context.Background()
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.New(database)
	found := adoptFixture()

	plan, err := Plan(ctx, st, found)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Empty() {
		t.Fatal("Plan is empty for a server full of unknown mailboxes")
	}

	adopted, err := Adopt(ctx, st, found)
	if err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	if adopted.Total() != plan.Total() {
		t.Errorf("Adopt wrote %d entries, Plan promised %d", adopted.Total(), plan.Total())
	}

	var users, domains int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains`).Scan(&domains); err != nil {
		t.Fatal(err)
	}
	if users != 2 {
		t.Errorf("users = %d, want 2 (the hash-less mailbox is skipped)", users)
	}
	if domains != 2 {
		t.Errorf("domains = %d, want 2", domains)
	}

	// Recorded as a mutation: an import changes who can receive mail, so it
	// belongs in the audit log.
	snap, err := st.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap.Users) != 2 || len(snap.Domains) != 2 {
		t.Errorf("snapshot after import: %d domains, %d users; want 2 and 2", len(snap.Domains), len(snap.Users))
	}

	// And a second import is a no-op.
	again, err := Plan(ctx, st, found)
	if err != nil {
		t.Fatalf("Plan after Adopt: %v", err)
	}
	if !again.Empty() {
		t.Errorf("Plan after Adopt = %+v, want nothing left to import", again)
	}
}
