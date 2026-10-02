package dovecot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
)

// authTestTimeout bounds `doveadm auth test`.
//
// It is longer than the scheme probe because a *failed* login is deliberately
// slow: Dovecot sleeps auth_failure_delay (2 seconds by default) before it
// answers, so a wrong password costs seconds rather than milliseconds.
const authTestTimeout = 20 * time.Second

// AuthTester asks the local Dovecot to authenticate address with password, and
// returns nil only when it did.
//
// It is a function rather than a hard-coded call so the mutation service can be
// exercised without a running Dovecot — the same reason ProbeFunc is a parameter
// to Resolve.
type AuthTester func(ctx context.Context, address, password string) error

// AuthTest proves that a mailbox can log in, by asking Dovecot itself to do it:
// `doveadm auth test` runs exactly the passdb and userdb lookups an IMAP or
// submission login performs.
//
// Why it exists: nothing in the panel ever performed a login. A hash Dovecot
// cannot verify — the {CRYPT} prefix around a yescrypt ($y$) hash read out of
// /etc/shadow is the one that reached users — is stored happily, rendered into
// the passwd-file, reported as a successful sync, and the only way to find out
// was for the mailbox' owner to open webmail. This turns that into an answer
// while the operator is still setting the password (see
// mutations.Service.ensureLoginUsable).
//
// The password goes in argv, as it does in the installer's verify_login, which
// makes it briefly visible to `ps`. The alternative — an IMAP login against
// 127.0.0.1 — proves less: it needs a maildir to exist, and it writes a login
// the mailbox' owner did not make.
func AuthTest(ctx context.Context, address, password string) error {
	if strings.TrimSpace(address) == "" {
		return errors.New("doveadm auth test: no address to test")
	}
	if password == "" {
		// Never ask Dovecot to verify an empty password: the question would be
		// answered by the absence of a hash rather than by a password.
		return errors.New("doveadm auth test: refusing to test an empty password")
	}

	out, err := execx.Output(ctx, authTestTimeout, "doveadm", "auth", "test", address, password)
	text := strings.TrimSpace(string(out))

	if err != nil {
		return fmt.Errorf("doveadm auth test %s: %w%s", address, err, outputSuffix(text))
	}
	// The exit status is the answer; the text is a second opinion, for a
	// doveadm that answers 0 while its own output says the lookup failed.
	if !authTestPassed(text) {
		return fmt.Errorf("doveadm auth test %s: %s", address, text)
	}
	return nil
}

// hashTestTimeout bounds `doveadm pw -t`.
const hashTestTimeout = 10 * time.Second

// HashTester asks the local Dovecot whether it can verify password against hash.
// It is a function rather than a hard-coded call so the mutation service can be
// exercised without a running Dovecot — the same reason AuthTester is a
// parameter.
type HashTester func(ctx context.Context, password, hash string) error

// VerifyHash asks the local Dovecot whether password verifies against hash, by
// running `doveadm pw -t` with the password on stdin. It needs no passwd-file
// entry, so it is the check a queued sync (the panel's web path) can run before
// the file on disk holds the mailbox — the one place a hash this Dovecot cannot
// check would otherwise be stored with nothing to say so.
func VerifyHash(ctx context.Context, password, hash string) error {
	if password == "" {
		return errors.New("doveadm pw -t: refusing to test an empty password")
	}
	if strings.TrimSpace(hash) == "" {
		return errors.New("doveadm pw -t: no hash to test")
	}

	out, err := execx.OutputStdin(ctx, hashTestTimeout, []byte(password+"\n"), "doveadm", "pw", "-t", hash)
	text := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("doveadm pw -t: %w%s", err, outputSuffix(text))
	}
	return nil
}

// authTestPassed reports whether doveadm's output means the login worked.
//
// The markers are Dovecot's own words for the three ways a lookup fails: a wrong
// password, a passdb that refused the credentials, and a user that no passwd-file
// line describes. None of them can appear in the output of a login that passed.
func authTestPassed(out string) bool {
	lower := strings.ToLower(out)
	for _, marker := range []string{"auth failed", "authentication fail", "unknown user"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

// outputSuffix renders doveadm's own words for an error message, or nothing when
// it said nothing.
func outputSuffix(out string) string {
	if out == "" {
		return ""
	}
	return ": " + out
}
