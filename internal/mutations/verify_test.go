package mutations

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/dovecot"
)

// fakeTester records the logins the probe was asked to prove, and answers with
// the error it was built with. A nil error is a proven login.
type fakeTester struct {
	mu       sync.Mutex
	calls    [][2]string
	failWith error
}

func (f *fakeTester) test(_ context.Context, address, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, [2]string{address, password})
	return f.failWith
}

func (f *fakeTester) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// TestRepairScheme is the decision that decides whether a rejected password gets
// a second hash written at all. SSHA512 is tried first because it is the one
// scheme every Dovecot build can verify, and the hash that gets rejected is
// normally a {CRYPT} one imported from /etc/shadow. When the rejected hash
// already *is* SSHA512, ARGON2ID is the only option left — and it is only worth
// writing if the host was built with libsodium, because the alternative is
// replacing one hash nothing can check with another.
func TestRepairScheme(t *testing.T) {
	cases := []struct {
		name   string
		hash   string
		argon2 bool
		want   string
		ok     bool
	}{
		{
			name: "a yescrypt {CRYPT} hash on a Dovecot without libsodium",
			hash: "{CRYPT}$y$j9T$abcdefghijklmnop$0123456789abcdefghijklmnopqrstuvwxyz0123456789",
			want: dovecot.SchemeSSHA512, ok: true,
		},
		{
			name:   "the same hash on a Dovecot with libsodium",
			hash:   "{CRYPT}$y$j9T$abcdefghijklmnop$0123456789abcdefghijklmnopqrstuvwxyz0123456789",
			argon2: true,
			want:   dovecot.SchemeSSHA512, ok: true,
		},
		{
			name: "a case-insensitive prefix",
			hash: "{crypt}$6$rounds=5000$abcdefghijklmnop$0123456789abcdefghijklmnop",
			want: dovecot.SchemeSSHA512, ok: true,
		},
		{
			name: "an argon2id hash that was refused anyway",
			hash: "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$AAA$BBB",
			want: dovecot.SchemeSSHA512, ok: true,
		},
		{
			name: "an SSHA512 hash with nowhere left to go",
			hash: "{SSHA512}$6$abcdefghijklmnop$0123456789abcdefghijklmnop",
			want: "", ok: false,
		},
		{
			name:   "an SSHA512 hash on a Dovecot that has libsodium",
			hash:   "{SSHA512}$6$abcdefghijklmnop$0123456789abcdefghijklmnop",
			argon2: true,
			want:   dovecot.SchemeArgon2id, ok: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := repairScheme(tc.hash, tc.argon2)
			if ok != tc.ok || got != tc.want {
				t.Errorf("repairScheme(%q, argon2=%v) = (%q, %v), want (%q, %v)",
					tc.hash, tc.argon2, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestEnsureLoginUsableSkipsWhatItCannotProve — the probe asks the *running*
// Dovecot about the passwd-file that is on disk, so it may only run when this
// call is what put the mailbox there (res.Reconciled) and when the plaintext is
// still known. Anything else probes a state that does not describe the mutation:
// the panel queues its sync, so the row is not in /etc/dovecot/users yet, and the
// plaintext is gone when the request ends. A false failure there would be worse
// than no check at all.
func TestEnsureLoginUsableSkipsWhatItCannotProve(t *testing.T) {
	cases := []struct {
		name       string
		reconciled bool
		password   string
	}{
		{name: "the panel's queued sync", reconciled: false, password: "longenough"},
		{name: "no plaintext to prove", reconciled: true, password: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tester := &fakeTester{failWith: errors.New("doveadm: Error: Authentication failed")}
			svc := &Service{authTest: tester.test}
			res := &Result{Reconciled: tc.reconciled}

			svc.ensureLoginUsable(context.Background(), Actor{Name: "test:verify"},
				res, "alice@example.com", tc.password, "{CRYPT}$y$abcdefghijklmnop")

			if got := tester.count(); got != 0 {
				t.Errorf("probe calls = %d, want none", got)
			}
			if len(res.Warnings) != 0 {
				t.Errorf("warnings = %q, want none", res.Warnings)
			}
		})
	}
}

// TestEnsureLoginUsableIsSilentWhenTheLoginWorks — the panel must not
// congratulate itself in every sync output: a warning that appears on every
// mailbox is one nobody reads when it matters.
func TestEnsureLoginUsableIsSilentWhenTheLoginWorks(t *testing.T) {
	tester := &fakeTester{}
	svc := &Service{authTest: tester.test}
	res := &Result{Reconciled: true}

	svc.ensureLoginUsable(context.Background(), Actor{Name: "test:verify"},
		res, "alice@example.com", "longenough", "{SSHA512}$6$abcdefghijklmnop$0123456789")

	if got := tester.count(); got != 1 {
		t.Fatalf("probe calls = %d, want 1", got)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %q, want none for a login that works", res.Warnings)
	}
}

// TestEnsureLoginUsableSaysWhenThereIsNothingLeftToTry — an SSHA512 hash refused
// on a Dovecot with no libsodium: the panel has no second scheme worth writing,
// and hashing the password into argon2id would only replace one hash that cannot
// be checked with another. The operator has to be told, because nothing else in
// the panel can see it.
func TestEnsureLoginUsableSaysWhenThereIsNothingLeftToTry(t *testing.T) {
	tester := &fakeTester{failWith: errors.New("doveadm: Error: Authentication failed")}
	svc := &Service{
		authTest:         tester.test,
		supportsArgon2id: func(context.Context) bool { return false },
	}
	res := &Result{Reconciled: true}

	svc.ensureLoginUsable(context.Background(), Actor{Name: "test:verify"},
		res, "alice@example.com", "longenough", "{SSHA512}$6$abcdefghijklmnop$0123456789")

	if got := tester.count(); got != 1 {
		t.Fatalf("probe calls = %d, want 1: there is no scheme to re-test with", got)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings = %q, want exactly one", res.Warnings)
	}
	if !strings.Contains(res.Warnings[0], "no password scheme left to try") {
		t.Errorf("warning = %q, want it to say there is nothing left to try", res.Warnings[0])
	}
	if !strings.Contains(res.Warnings[0], "alice@example.com") {
		t.Errorf("warning = %q, want it to name the mailbox", res.Warnings[0])
	}
}

// TestEnsureLoginUsableRepairsARejectedHash — the whole point of the probe. The
// stored hash is a {CRYPT} one this Dovecot refused, so the password is hashed
// again with a scheme that can be verified, the rewrite goes through Apply (so it
// is audited and rendered like any other mutation), and what the operator is told
// depends on whether the rewrite could be probed.
//
// The sync queue is what lets this run without a real database: Apply then stores
// the row and asks the background syncer to render it — which is also why the
// warning says the login is not proven *yet*. The passwd-file on disk still holds
// the rejected hash, and probing it again would only repeat the first answer.
func TestEnsureLoginUsableRepairsARejectedHash(t *testing.T) {
	pool := openFakeDB(t)
	queue := &recordingQueue{}
	tester := &fakeTester{failWith: errors.New("doveadm: Error: Authentication failed")}

	svc := &Service{
		db:               pool,
		auditor:          audit.New(pool),
		sync:             queue,
		authTest:         tester.test,
		supportsArgon2id: func(context.Context) bool { return false },
	}
	res := &Result{Reconciled: true}

	svc.ensureLoginUsable(context.Background(), Actor{Name: "cli:mailbox"},
		res, "alice@example.com", "longenough", "{CRYPT}$y$j9T$abcdefghijklmnop$0123456789")

	if got := tester.count(); got != 1 {
		t.Fatalf("probe calls = %d, want 1: a queued rewrite cannot be probed yet", got)
	}

	found := false
	for _, e := range fakeRegistry.snapshot() {
		if e.kind == "exec" && strings.Contains(e.query, "UPDATE users SET password_hash") {
			found = true
		}
	}
	if !found {
		t.Error("the repaired hash was never stored: no UPDATE users SET password_hash ran")
	}
	if got := queue.requests(); len(got) != 1 || got[0] != "user.repair_password_hash" {
		t.Errorf("queued sync requests = %v, want exactly [user.repair_password_hash]", got)
	}

	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "not one this Dovecot accepts") {
		t.Errorf("warnings = %q, want the hash reported as rejected", res.Warnings)
	}
	if !strings.Contains(joined, "not proven until that run finishes") {
		t.Errorf("warnings = %q, want the login reported as not proven yet", res.Warnings)
	}
}
