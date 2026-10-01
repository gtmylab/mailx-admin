// Package dovecot reports which password schemes the Dovecot on this host can
// actually verify, and picks the one mailbox passwords have to be hashed with.
//
// Why it exists: the panel used to hard-code argon2id. Dovecot only knows
// ARGON2I/ARGON2ID when it was built against libsodium, and on a host without
// it the hash in the passwd-file is one Dovecot cannot check — the mailbox
// exists, the password is the right one, and the login is refused. Nothing in
// the panel could tell those two situations apart, because nothing ever asked
// the local Dovecot what it supports.
//
// This is deliberately a probe, not a version check: `doveadm pw -l` lists the
// schemes the running binary itself was built with, so a distro package, a
// backport or a hand-built Dovecot all answer truthfully.
package dovecot

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/execx"
)

const (
	// SchemeArgon2id is the panel's preferred scheme: memory-hard, and the
	// one Dovecot's own documentation recommends.
	SchemeArgon2id = auth.SchemeArgon2id

	// SchemeSSHA512 is the fallback. Any Dovecot supports it, because it is
	// plain SHA-512 — at the price of a single round, no salt stretching and
	// no memory hardness.
	//
	// It is also what an unanswerable probe falls back to (see resolveAuto).
	// When nobody can say what this Dovecot was built with, the only safe
	// answer is the scheme no build lacks: argon2id would be a hash this host
	// may be unable to verify at all, which is a mailbox nobody can log into.
	SchemeSSHA512 = auth.SchemeSSHA512

	// SchemeAuto lets the host decide: argon2id where it exists, SSHA512
	// where it does not.
	SchemeAuto = "auto"

	// DefaultPassdbScheme is the scheme Dovecot verifies a hash with when the
	// passwd-file passdb carries no `scheme=` and the hash has no {SCHEME}
	// prefix. It is Dovecot's own compiled-in default for that passdb
	// (PASSWD_FILE_DEFAULT_SCHEME in db-passwd-file.h), which is also the
	// convention /etc/shadow lines rely on — and it is what the panel leaves
	// such a hash to when it could not ask the host which schemes it supports,
	// rather than writing a name the build may not know.
	DefaultPassdbScheme = "CRYPT"
)

// probeTimeout bounds `doveadm pw -l`, which lists schemes from memory and
// answers immediately — unless doveadm is a wrapper that talks to a socket.
const probeTimeout = 10 * time.Second

// ProbeFunc returns the raw output of `doveadm pw -l`. It is a parameter rather
// than a hard-coded call so the resolution rules can be tested without Dovecot.
type ProbeFunc func(ctx context.Context) (string, error)

// Probe asks the local Dovecot which password schemes it supports.
//
// A missing doveadm binary and a failing one are both errors, never an empty
// list: the difference between "this Dovecot supports nothing" and "I could not
// ask" decides whether the caller may keep its current scheme.
func Probe(ctx context.Context) (string, error) {
	out, err := execx.Output(ctx, probeTimeout, "doveadm", "pw", "-l")
	return string(out), err
}

// The probe is memoised for the life of the process, and only on success.
//
// Two reasons. It answers a property of the installed Dovecot, which cannot
// change while the panel is running — so asking once is enough — and the
// callers include paths that must not fork: the doctor's read-only check and
// the preview dialog both resolve the scheme while a database transaction is
// open. The server converges once at startup (see syncer.Request in Serve), so
// by the time a preview runs the answer is already in memory.
//
// A failed probe is deliberately *not* remembered: a host where the
// mysql/doveadm client is installed five minutes after the panel started must
// not need a restart.
var (
	probeMu     sync.Mutex
	probedOut   string
	probeWorked bool
)

// ProbeCached is Probe with the process-wide memo described above.
func ProbeCached(ctx context.Context) (string, error) {
	probeMu.Lock()
	defer probeMu.Unlock()

	if probeWorked {
		return probedOut, nil
	}

	out, err := Probe(ctx)
	if err != nil {
		return out, err
	}
	probedOut, probeWorked = out, true
	return out, nil
}

// Probed reports whether the probe has already succeeded in this process.
func Probed() bool {
	probeMu.Lock()
	defer probeMu.Unlock()
	return probeWorked
}

// Schemes is the set of scheme names a Dovecot build reported.
type Schemes map[string]bool

// Has reports whether the set contains name, case-insensitively.
func (s Schemes) Has(name string) bool { return s[normalize(name)] }

// List returns the scheme names in a stable order, for error messages.
func (s Schemes) List() []string {
	out := make([]string, 0, len(s))
	for name := range s {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ParseSchemes reads the output of `doveadm pw -l`.
//
// The layout has changed over the years — a single comma-separated line in some
// versions, one scheme per line, a leading "CRYPT schemes:" style header in
// others — so anything that is not a scheme name is ignored rather than parsed
// as one. The names are what matter here, not the formatting.
func ParseSchemes(out string) Schemes {
	schemes := Schemes{}
	for _, tok := range strings.FieldsFunc(out, isSchemeSeparator) {
		if !isSchemeName(tok) {
			continue
		}
		schemes[normalize(tok)] = true
	}
	return schemes
}

func isSchemeSeparator(r rune) bool {
	switch r {
	case '\n', '\r', '\t', ' ', ',', ':', ';', '(', ')', '=', '[', ']':
		return true
	}
	return false
}

// isSchemeName reports whether a token can be a scheme name: upper-case letters,
// digits, '-' and '_'. It is what drops the prose around the list ("with",
// "schemes", "supported:") without having to understand it.
func isSchemeName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
		default:
			return false
		}
	}
	return true
}

func normalize(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// Resolution is the answer: which scheme to hash with, and why.
type Resolution struct {
	// Scheme is what new passwords must be hashed with.
	Scheme string

	// Known is true when the probe worked, i.e. the answer comes from the
	// local Dovecot rather than from a default.
	Known bool

	// Supported is true when the local Dovecot can verify Scheme. It is
	// false when the scheme could not be checked at all.
	Supported bool

	// Fallback is true when the configured scheme was overridden because the
	// host cannot verify it — what the reconciler warns about and what the
	// doctor check highlights.
	Fallback bool

	// Detail is one sentence for the audit trail, the sync warnings and the
	// doctor output.
	Detail string
}

// Resolve decides which scheme mailbox passwords are hashed with.
//
//	configured == "" or "auto"   the host decides
//	configured == "ARGON2ID"     that scheme, or an error if this Dovecot
//	configured == "SSHA512"      cannot verify it
//
// An explicit scheme the host cannot verify is an error rather than a silent
// downgrade: the operator asked for it, and a mailbox whose hash cannot be
// checked never logs in.
func Resolve(ctx context.Context, configured string, probe ProbeFunc) (Resolution, error) {
	explicit := normalize(configured)

	if explicit != "" && explicit != normalize(SchemeAuto) {
		return resolveExplicit(ctx, explicit, probe)
	}
	return resolveAuto(ctx, probe)
}

func resolveExplicit(ctx context.Context, explicit string, probe ProbeFunc) (Resolution, error) {
	if probe == nil {
		return Resolution{
			Scheme: explicit,
			Detail: "the local Dovecot was not asked; using the configured " + explicit,
		}, nil
	}

	out, err := probe(ctx)
	if err != nil {
		return Resolution{
			Scheme: explicit,
			Detail: fmt.Sprintf("could not list the password schemes Dovecot supports (%v); "+
				"keeping the configured %s", err, explicit),
		}, nil
	}

	schemes := ParseSchemes(out)
	if !schemes.Has(explicit) {
		return Resolution{}, fmt.Errorf(
			"this Dovecot cannot verify %s (it supports: %s); "+
				"set [mail] passwd_scheme to one of those, or to %q",
			explicit, strings.Join(schemes.List(), ", "), SchemeAuto)
	}
	return Resolution{
		Scheme: explicit, Known: true, Supported: true,
		Detail: "dovecot supports " + explicit,
	}, nil
}

func resolveAuto(ctx context.Context, probe ProbeFunc) (Resolution, error) {
	if probe == nil {
		return Resolution{
			Scheme: SchemeSSHA512, Fallback: true,
			Detail: "the local Dovecot was not asked; hashing with " + SchemeSSHA512 +
				", which every Dovecot can verify",
		}, nil
	}

	out, err := probe(ctx)
	if err != nil {
		return Resolution{
			Scheme: SchemeSSHA512, Fallback: true,
			Detail: fmt.Sprintf("could not list the password schemes Dovecot supports (%v); "+
				"hashing with %s, which every Dovecot can verify — set [mail] passwd_scheme "+
				"to %s once the probe answers again", err, SchemeSSHA512, SchemeArgon2id),
		}, nil
	}

	schemes := ParseSchemes(out)
	switch {
	case schemes.Has(SchemeArgon2id):
		return Resolution{
			Scheme: SchemeArgon2id, Known: true, Supported: true,
			Detail: "dovecot supports " + SchemeArgon2id,
		}, nil
	case schemes.Has(SchemeSSHA512):
		return Resolution{
			Scheme: SchemeSSHA512, Known: true, Supported: true, Fallback: true,
			Detail: "this Dovecot was built without libsodium, so it cannot verify " +
				SchemeArgon2id + "; new passwords are hashed with " + SchemeSSHA512,
		}, nil
	default:
		return Resolution{}, fmt.Errorf(
			"this Dovecot supports neither %s nor %s (it supports: %s); "+
				"fix the Dovecot installation or set [mail] passwd_scheme explicitly",
			SchemeArgon2id, SchemeSSHA512, strings.Join(schemes.List(), ", "))
	}
}

// ScanHashSchemes returns how many hashes in a Dovecot passwd-file use each
// scheme, e.g. {"ARGON2ID": 4, "CRYPT": 2}. Hashes without a {SCHEME} prefix
// are counted under "(default)".
//
// It is what turns "this mailbox cannot log in" into "its hash is one this
// Dovecot cannot verify": the passwd-file is the only place that knows which
// scheme each mailbox's password was written in.
func ScanHashSchemes(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return countHashSchemes(string(data)), nil
}

func countHashSchemes(data string) map[string]int {
	counts := map[string]int{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		password := passwdField(line, 1)
		if !strings.HasPrefix(password, "{") {
			counts["(default)"]++
			continue
		}
		name, _, ok := strings.Cut(strings.TrimPrefix(password, "{"), "}")
		if !ok {
			continue
		}
		counts[normalize(name)]++
	}
	return counts
}

// passwdField splits a passwd-file line on ':' and returns the n-th field, or
// "" when the line is shorter. The password is always field 1.
func passwdField(line string, n int) string {
	parts := strings.Split(line, ":")
	if n >= len(parts) {
		return ""
	}
	return parts[n]
}
