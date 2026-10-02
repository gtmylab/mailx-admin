package dovecot

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestAuthTestRefusesWhatItCannotProve — the probe has to answer before it
// executes anything when there is nothing to ask about: an empty address, and
// above all an empty password. A passwd-file line with no hash would otherwise be
// "verified" against an empty client password, and the panel would report a login
// it never performed.
func TestAuthTestRefusesWhatItCannotProve(t *testing.T) {
	ctx := context.Background()

	cases := []struct{ name, address, password string }{
		{name: "no address at all", password: "longenough"},
		{name: "a blank address", address: "   ", password: "longenough"},
		{name: "no password", address: "alice@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AuthTest(ctx, tc.address, tc.password)
			if err == nil {
				t.Fatalf("AuthTest(%q, %q) = nil, want an error", tc.address, tc.password)
			}
			if !strings.Contains(err.Error(), "doveadm auth test") {
				t.Errorf("error %q does not name the probe that was not run", err)
			}
		})
	}
}

// TestAuthTestNeverReportsAnUnprovenLogin — whatever the host has installed, a
// login that cannot authenticate has to come back as an error, never as silence.
// On a build machine there is no doveadm at all; on a mail server there is, and
// this address and password belong to nobody there. Either way the answer is
// "not proven", which is the property the mutation service relies on.
func TestAuthTestNeverReportsAnUnprovenLogin(t *testing.T) {
	err := AuthTest(context.Background(), "nobody@example.invalid", "definitely-not-the-password")
	if err == nil {
		t.Fatal("AuthTest returned nil for a login no Dovecot can accept")
	}
	if !strings.Contains(err.Error(), "auth test") {
		t.Errorf("error %q does not say which probe failed", err)
	}
}

// TestAuthTestPassed pins how doveadm's own words are read. The exit status is
// the primary answer (see AuthTest) and this is the second opinion, for a
// doveadm that answers 0 while its own output says the lookup failed: a wrong
// password, a refusal, or a name no passwd-file line describes.
func TestAuthTestPassed(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "both lookups succeeded",
			out: "passdb: nobody@example.com passdb passwd-file succeeded\n" +
				"userdb: nobody@example.com userdb passwd-file succeeded",
			want: true,
		},
		{name: "a silent success", out: "", want: true},
		{name: "a refused password", out: "doveadm: Error: Authentication failed", want: false},
		{name: "the bare auth-failed spelling", out: "auth failed", want: false},
		{name: "a name no passwd-file line describes", out: "doveadm: Error: Unknown user", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authTestPassed(tc.out); got != tc.want {
				t.Errorf("authTestPassed(%q) = %v, want %v", tc.out, got, tc.want)
			}
		})
	}
}

// TestSupportsArgon2id — the question the mutation service asks before it
// re-hashes a rejected password. A probe that could not run answers no, because
// "unknown" read as "yes" means rewriting a hash nothing can check into another
// hash nothing can check (resolveAuto follows the same rule).
func TestSupportsArgon2id(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		probe ProbeFunc
		want  bool
	}{
		{
			name:  "libsodium available",
			probe: func(context.Context) (string, error) { return "PLAIN, CRYPT, SSHA512, ARGON2ID\n", nil },
			want:  true,
		},
		{
			name:  "built without libsodium",
			probe: func(context.Context) (string, error) { return "PLAIN, CRYPT, SSHA512\n", nil },
			want:  false,
		},
		{
			name:  "the probe could not run",
			probe: func(context.Context) (string, error) { return "", errors.New("doveadm: not found") },
			want:  false,
		},
		{name: "there is no probe at all", probe: nil, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SupportsArgon2id(ctx, tc.probe); got != tc.want {
				t.Errorf("SupportsArgon2id = %v, want %v", got, tc.want)
			}
		})
	}
}
