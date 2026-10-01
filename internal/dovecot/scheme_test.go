package dovecot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseSchemes: the trio of shapes `doveadm pw -l` has had, plus the prose
// that surrounds them. A missed ARGON2ID here means every new mailbox is hashed
// with something this Dovecot cannot verify, so the parser is deliberately
// forgiving about layout and strict about what counts as a name.
func TestParseSchemes(t *testing.T) {
	cases := map[string]string{
		"comma separated": "PLAIN, CLEARTEXT, CRYPT, MD5, SHA512, SSHA512, ARGON2I, ARGON2ID\n",
		"one per line":    "PLAIN\nSHA512\nSSHA512\nARGON2ID\n",
		"with a header":   "CRYPT schemes:\n\tPLAIN\n\tSHA512\nSupported schemes: SSHA512, ARGON2ID\n",
	}

	for name, out := range cases {
		schemes := ParseSchemes(out)
		for _, want := range []string{"PLAIN", "SHA512", "SSHA512", "ARGON2ID"} {
			if !schemes.Has(want) {
				t.Errorf("%s: %s missing from %v", name, want, schemes.List())
			}
		}
	}

	// Lookups are case-insensitive even though the parser only accepts the
	// spelling Dovecot prints: an operator's admin.toml may not use it.
	if !ParseSchemes("ARGON2ID, SSHA512").Has("argon2id") {
		t.Error("Has() is case sensitive, so a lower-case [mail] passwd_scheme would never match")
	}
	// Prose is dropped, not treated as a scheme.
	if ParseSchemes("Supported schemes: PLAIN").Has("SUPPORTED") {
		t.Error("the word SUPPORTED was parsed as a scheme name")
	}
}

// TestResolveAuto is the decision that decides whether a new mailbox can log in.
//
// The two cases where nobody could be asked both fall back to SSHA512, not to
// argon2id: a probe that never ran is no evidence that this Dovecot was built
// with libsodium, and argon2id written on a build without it is a mailbox whose
// password can never be checked again. SSHA512 is plain SHA-512 and is in every
// build, so it is the only answer that cannot lock a mailbox out.
func TestResolveAuto(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name     string
		probe    ProbeFunc
		want     string
		fallback bool
	}{
		{
			name:  "libsodium available",
			probe: fixed("PLAIN, SSHA512, ARGON2I, ARGON2ID"),
			want:  SchemeArgon2id,
		},
		{
			name:     "built without libsodium",
			probe:    fixed("PLAIN, CLEARTEXT, CRYPT, SHA512, SSHA512"),
			want:     SchemeSSHA512,
			fallback: true,
		},
		{
			name:     "not asked at all",
			probe:    nil,
			want:     SchemeSSHA512,
			fallback: true,
		},
		{
			name:     "probe failed",
			probe:    func(context.Context) (string, error) { return "", errors.New("doveadm: not found") },
			want:     SchemeSSHA512,
			fallback: true,
		},
	}

	for _, tc := range cases {
		got, err := Resolve(ctx, "", tc.probe)
		if err != nil {
			t.Errorf("%s: Resolve: %v", tc.name, err)
			continue
		}
		if got.Scheme != tc.want {
			t.Errorf("%s: scheme = %q, want %q", tc.name, got.Scheme, tc.want)
		}
		if got.Fallback != tc.fallback {
			t.Errorf("%s: fallback = %v, want %v", tc.name, got.Fallback, tc.fallback)
		}
		if got.Detail == "" {
			t.Errorf("%s: no detail; the operator is left guessing why", tc.name)
		}
	}
}

// TestResolveExplicit: what the operator wrote wins — unless it cannot work, in
// which case saying so is the whole point.
func TestResolveExplicit(t *testing.T) {
	ctx := context.Background()
	withoutArgon2 := fixed("PLAIN, CRYPT, SHA512, SSHA512")

	got, err := Resolve(ctx, "ssha512", withoutArgon2)
	if err != nil {
		t.Fatalf("Resolve(SSHA512) on a host that supports it: %v", err)
	}
	if got.Scheme != SchemeSSHA512 || got.Fallback || !got.Known {
		t.Errorf("Resolve = %+v, want the configured SSHA512, known and not a fallback", got)
	}

	// An explicit scheme the host cannot verify is an error, not a silent
	// downgrade: the operator asked for it, and the logins would fail.
	_, err = Resolve(ctx, SchemeArgon2id, withoutArgon2)
	if err == nil {
		t.Fatal("Resolve(ARGON2ID) on a host without libsodium returned no error")
	}
	for _, want := range []string{"ARGON2ID", "SSHA512"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s, so it cannot say what would work", err, want)
		}
	}

	// A probe that could not run at all is different: the operator's choice is
	// kept, because there is no evidence against it.
	got, err = Resolve(ctx, SchemeArgon2id, func(context.Context) (string, error) {
		return "", errors.New("doveadm: not found")
	})
	if err != nil {
		t.Fatalf("Resolve with a failing probe: %v", err)
	}
	if got.Scheme != SchemeArgon2id || got.Known {
		t.Errorf("Resolve = %+v, want the configured scheme with Known=false", got)
	}

	// Neither scheme available: do not pretend there is an answer.
	if _, err := Resolve(ctx, "", fixed("PLAIN, CRYPT")); err == nil {
		t.Error("Resolve with neither ARGON2ID nor SSHA512 returned no error")
	}
}

// TestScanHashSchemes counts what is already in the passwd-file, which is what
// turns "this mailbox cannot log in" into "its hash is one this Dovecot cannot
// verify".
func TestScanHashSchemes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users")

	content := "# Managed by mailx-admin — DO NOT EDIT\n" +
		"\n" +
		"alice@example.com:{ARGON2ID}$argon2id$v=19$m=1,t=1,p=1$AA$BB:5000:5000::/x::q\n" +
		"bob@example.com:{ARGON2ID}$argon2id$v=19$m=1,t=1,p=1$CC$DD:5000:5000::/x::q\n" +
		"test1@example.com:{CRYPT}$6$rounds=5000$abcdefgh$hash:1000:1000::/home/test1::q\n" +
		"legacy@example.com:$plain-ish:5000:5000::/x::q\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	counts, err := ScanHashSchemes(path)
	if err != nil {
		t.Fatalf("ScanHashSchemes: %v", err)
	}

	want := map[string]int{"ARGON2ID": 2, "CRYPT": 1, "(default)": 1}
	if len(counts) != len(want) {
		t.Fatalf("counts = %v, want %v", counts, want)
	}
	for scheme, n := range want {
		if counts[scheme] != n {
			t.Errorf("%s: %d hash(es), want %d", scheme, counts[scheme], n)
		}
	}
}

func fixed(out string) ProbeFunc {
	return func(context.Context) (string, error) { return out, nil }
}
