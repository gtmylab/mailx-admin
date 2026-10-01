package reconciler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/dovecot"
)

// probeFixed answers the scheme probe with a canned `doveadm pw -l` output, so
// the resolution policy is exercised on a machine with no Dovecot installed.
func probeFixed(out string) dovecot.ProbeFunc {
	return func(context.Context) (string, error) { return out, nil }
}

// probeBroken is a host where doveadm is not installed at all.
func probeBroken() dovecot.ProbeFunc {
	return func(context.Context) (string, error) { return "", errors.New("doveadm: not found") }
}

// TestRenderDovecotUsersConfNeverWritesAnUnverifiableScheme — a written scheme=
// has to name a scheme the local Dovecot was built with, and the renderer only
// writes one the caller could actually confirm. "auto", "AUTO" and "" are the
// panel's way of saying "ask the local Dovecot": when nobody could answer, no
// scheme= is written at all, which leaves Dovecot on its own default for a
// prefix-less hash (dovecot.DefaultPassdbScheme) — instead of `scheme=auto`, a
// name no build has, or a guess at argon2id, half the builds' users of which
// cannot verify.
func TestRenderDovecotUsersConfNeverWritesAnUnverifiableScheme(t *testing.T) {
	// Nobody named a scheme: the passdb carries no scheme= argument.
	for _, in := range []string{"", "auto", "AUTO", " Auto "} {
		out := string(RenderDovecotUsersConf("/etc/dovecot/users", in))

		if strings.Contains(out, "scheme=") {
			t.Errorf("scheme %q was rendered as an argument, but nobody could name one:\n%s", in, out)
		}
		if !strings.Contains(out, "driver = passwd-file") {
			t.Errorf("scheme %q lost the passdb:\n%s", in, out)
		}
		if !strings.Contains(out, "username_format=%u /etc/dovecot/users") {
			t.Errorf("scheme %q lost the passwd-file argument:\n%s", in, out)
		}
	}

	// A scheme that was confirmed is written, upper-cased: that is the spelling
	// `doveadm pw -l` prints and the one Dovecot matches against.
	for in, want := range map[string]string{
		"argon2id": dovecot.SchemeArgon2id,
		"ARGON2ID": dovecot.SchemeArgon2id,
		"CRYPT":    "CRYPT",
		"crypt":    "CRYPT",
	} {
		out := string(RenderDovecotUsersConf("/etc/dovecot/users", in))
		if !strings.Contains(out, "scheme="+want+" ") {
			t.Errorf("scheme %q did not render as scheme=%s:\n%s", in, want, out)
		}
		if strings.Contains(strings.ToLower(out), "scheme=auto") {
			t.Errorf("scheme %q rendered as scheme=auto, which no Dovecot was built with:\n%s", in, out)
		}
	}
}

// TestResolveSchemeAutoNeverAbortsTheReconcile — the v1.0.9 regression.
//
// Reconcile resolves the scheme before it renders anything and returns the error
// unchanged, so a scheme error is not a warning: the whole passwd-file is never
// written. A mailbox that is not in /etc/dovecot/users does not exist as far as
// Dovecot is concerned, so an "auto" that could not be answered used to make
// every panel mailbox unloggable, with nothing to look at. Before v1.0.9 the
// passdb's scheme= was a constant and this path did not exist.
//
// What it falls back to has to be a scheme that works on any build. For a probe
// that could not run that is SSHA512; for one that answered without either usable
// scheme there is no scheme= to write at all, and the run says so — never
// argon2id, whose absence on the host is what started this.
func TestResolveSchemeAutoNeverAbortsTheReconcile(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		probe dovecot.ProbeFunc
		want  string
		warn  bool
	}{
		{
			name:  "libsodium available",
			probe: probeFixed("PLAIN, CLEARTEXT, CRYPT, SSHA512, ARGON2I, ARGON2ID"),
			want:  dovecot.SchemeArgon2id,
		},
		{
			name:  "built without libsodium",
			probe: probeFixed("PLAIN, CLEARTEXT, CRYPT, SHA512, SSHA512"),
			want:  dovecot.SchemeSSHA512,
			warn:  true,
		},
		{
			name:  "probe could not run",
			probe: probeBroken(),
			want:  dovecot.SchemeSSHA512,
			warn:  true,
		},
		{
			// The regression itself: the probe worked and listed neither
			// usable scheme, which used to be an error that aborted the run.
			// "" means "no passdb default": the renderer then writes none, so
			// Dovecot falls back to its own, and a mailbox created in this
			// state fails loudly when its password is hashed rather than being
			// stored in a scheme this host cannot verify.
			name:  "probe answered, neither usable scheme available",
			probe: probeFixed("PLAIN, CLEARTEXT, CRYPT, SHA512"),
			want:  "",
			warn:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// "" and "auto" are the two spellings the installer and an
			// untouched config produce, and both defer to the host.
			for _, configured := range []string{"", dovecot.SchemeAuto} {
				rec := New(Config{PasswdScheme: configured, Probe: tc.probe}, nil)
				res := &Result{}

				got, err := rec.resolveScheme(ctx, res)
				if err != nil {
					t.Fatalf("passwd_scheme %q: resolveScheme failed (%v); Reconcile returns that before rendering, so every mailbox vanishes from the passwd-file", configured, err)
				}
				if got != tc.want {
					t.Errorf("passwd_scheme %q: scheme = %q, want %q", configured, got, tc.want)
				}
				if warned := len(res.Warnings) > 0; warned != tc.warn {
					t.Errorf("passwd_scheme %q: warnings = %v, want warn=%v", configured, res.Warnings, tc.warn)
				}
			}
		})
	}
}

// TestResolveSchemeExplicitUnsupportedIsStillFatal — an unanswered *auto* must
// not stop the reconcile, but a scheme the operator named and this Dovecot was
// not built with is different: writing the passdb anyway would take every login
// down, not one, so the run still has to fail with the explanation.
func TestResolveSchemeExplicitUnsupportedIsStillFatal(t *testing.T) {
	ctx := context.Background()

	rec := New(Config{
		PasswdScheme: "ARGON2ID",
		Probe:        probeFixed("PLAIN, CLEARTEXT, CRYPT, SHA512, SSHA512"),
	}, nil)
	if _, err := rec.resolveScheme(ctx, &Result{}); err == nil {
		t.Fatal("an explicit scheme this Dovecot cannot verify did not fail the run")
	}

	// The same scheme on a host that has it is fine, whatever its spelling.
	rec = New(Config{
		PasswdScheme: "ssha512",
		Probe:        probeFixed("PLAIN, CLEARTEXT, CRYPT, SSHA512"),
	}, nil)
	got, err := rec.resolveScheme(ctx, &Result{})
	if err != nil {
		t.Fatalf("resolveScheme(ssha512) on a host that supports it: %v", err)
	}
	if got != dovecot.SchemeSSHA512 {
		t.Errorf("scheme = %q, want %q", got, dovecot.SchemeSSHA512)
	}
}

// TestResolveSchemeSkipValidationResolvesAuto — SkipValidation is the test-suite
// switch and the only path that skips the probe, so nothing here has asked what
// the host can verify. "auto"/"" used to be handed straight back (upper-cased, so
// "AUTO") and the renderer then wrote `scheme=AUTO` into the passdb: a name no
// Dovecot was built with. Resolving them to argon2id instead assumed a libsodium
// this path cannot know about; SSHA512 is the one scheme no build lacks, so that
// is what a host nobody asked gets.
func TestResolveSchemeSkipValidationResolvesAuto(t *testing.T) {
	ctx := context.Background()

	for _, in := range []string{"", "auto", "AUTO", " Auto "} {
		rec := New(Config{SkipValidation: true, PasswdScheme: in}, nil)
		got, err := rec.resolveScheme(ctx, &Result{})
		if err != nil {
			t.Fatalf("passwd_scheme %q: %v", in, err)
		}
		if got != dovecot.SchemeSSHA512 {
			t.Errorf("passwd_scheme %q resolved to %q, want %q", in, got, dovecot.SchemeSSHA512)
		}
		out := string(RenderDovecotUsersConf("/etc/dovecot/users", got))
		if strings.Contains(strings.ToLower(out), "scheme=auto") {
			t.Errorf("passwd_scheme %q rendered as scheme=auto:\n%s", in, out)
		}
		if !strings.Contains(out, "scheme="+dovecot.SchemeSSHA512) {
			t.Errorf("passwd_scheme %q left the passdb without a verifiable default:\n%s", in, out)
		}
	}

	// An explicit scheme is still taken at face value when the probe is off.
	rec := New(Config{SkipValidation: true, PasswdScheme: "crypt"}, nil)
	got, err := rec.resolveScheme(ctx, &Result{})
	if err != nil {
		t.Fatalf("resolveScheme(crypt): %v", err)
	}
	if got != "CRYPT" {
		t.Errorf("scheme = %q, want CRYPT", got)
	}
}

// TestReconcileWithAutoSchemeStillWritesThePasswdFile — the whole path the
// regression ran through: [mail] passwd_scheme = "auto" (what the installer
// writes) has to resolve and then actually land the files. A mailbox that never
// reaches /etc/dovecot/users is one Dovecot refuses to authenticate.
//
// The fixture runs with SkipValidation, so nothing here asked the host which
// schemes it has, and the passdb therefore gets SSHA512 — a scheme every build
// verifies — rather than an argon2id that may not exist on the server.
func TestReconcileWithAutoSchemeStillWritesThePasswdFile(t *testing.T) {
	base, _, _ := driftReconciler(t)

	cfg := base.Config()
	cfg.PasswdScheme = dovecot.SchemeAuto
	rec := New(cfg, nil)

	if _, err := rec.Reconcile(context.Background(), fixtureSnapshotForDrift()); err != nil {
		t.Fatalf("Reconcile with passwd_scheme=auto: %v", err)
	}

	passwd, err := os.ReadFile(filepath.Join(cfg.DovecotConfDir, "users"))
	if err != nil {
		t.Fatalf("read the passwd-file: %v", err)
	}
	if !strings.Contains(string(passwd), "alice@example.com:{ARGON2ID}") {
		t.Errorf("the mailbox never reached the passwd-file:\n%s", passwd)
	}

	auth, err := os.ReadFile(filepath.Join(cfg.DovecotConfDir, "conf.d", "10-auth-mailx.conf"))
	if err != nil {
		t.Fatalf("read the passdb drop-in: %v", err)
	}
	if !strings.Contains(string(auth), "scheme="+dovecot.SchemeSSHA512) {
		t.Errorf("the passdb drop-in has no scheme this Dovecot can verify:\n%s", auth)
	}
	if strings.Contains(strings.ToLower(string(auth)), "scheme=auto") {
		t.Errorf("the passdb drop-in carries scheme=auto:\n%s", auth)
	}
}
