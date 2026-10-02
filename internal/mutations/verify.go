package mutations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/dovecot"
)

// ensureLoginUsable proves that the credentials that were just stored actually
// authenticate, and replaces the hash when they do not.
//
// The failure it exists for: a mailbox is created, the passwd-file is rendered,
// the sync reports success — and the login is refused, because the hash that was
// written is one this Dovecot cannot check. `{CRYPT}` around a yescrypt ($y$)
// shadow hash, adopted from /etc/shadow, is the one that reached users, and
// neither the panel nor the sync output could see it.
//
// It runs only while the caller still holds the plaintext password. The inline
// path (res.Reconciled — `mailbox add`, and through it the installer) proves the
// whole login with `doveadm auth test` against the passwd-file it just wrote.
// The panel's web paths queue their sync (res.Reconciled is false), so the file
// on disk does not hold the mailbox yet and a login probe would test a stale
// state; they instead ask whether the freshly-stored hash itself is one this
// Dovecot can verify (`doveadm pw -t`).
//
// Failures are warnings, never errors. The mailbox exists, the database row is
// right and the configuration landed; failing the mutation would leave the
// operator with a half-created mailbox. What must not happen is that they find
// out from the mailbox' owner.
func (s *Service) ensureLoginUsable(ctx context.Context, actor Actor, res *Result, address, password, hash string) {
	if password == "" || res == nil {
		return
	}

	// The inline path has just written the passwd-file, so the running Dovecot
	// can be asked to authenticate the address — the same lookup an IMAP login
	// walks. The panel's web paths queue their sync (res.Reconciled is false):
	// the file on disk does not hold the mailbox yet, so a login probe would
	// test a stale state, and the only thing that can be checked is whether the
	// freshly-stored hash itself is one this Dovecot can verify (doveadm pw -t).
	var firstErr error
	if res.Reconciled {
		if s.authTest == nil {
			return
		}
		firstErr = s.authTest(ctx, address, password)
	} else {
		if s.hashTest == nil {
			return
		}
		firstErr = s.hashTest(ctx, password, hash)
	}
	if firstErr == nil {
		return
	}

	argon2 := s.supportsArgon2id != nil && s.supportsArgon2id(ctx)
	alt, ok := repairScheme(hash, argon2)
	if !ok {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the login for %s could not be verified (%v), and there is no password scheme "+
				"left to try: check `doveadm pw -l` on the server and set the password again "+
				"with one of the schemes it lists", address, firstErr))
		return
	}

	repaired, err := auth.DovecotHashScheme(password, alt)
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the login for %s could not be verified (%v), and re-hashing the password with %s failed: %v",
			address, firstErr, alt, err))
		return
	}

	// Through Apply, so the rewrite is audited and rendered like any other
	// mutation rather than being a silent UPDATE.
	repair, err := s.Apply(ctx, actor, "user.repair_password_hash",
		map[string]any{"email": address, "failed": firstErr.Error(), "scheme": alt},
		func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx,
				`UPDATE users SET password_hash = ?, updated_at = ? WHERE email = ?`,
				repaired, time.Now(), address)
			return err
		})
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the login for %s could not be verified (%v), and rewriting its password hash failed: %v",
			address, firstErr, err))
		return
	}
	res.Changes = append(res.Changes, repair.Changes...)
	res.ReloadedSvcs = append(res.ReloadedSvcs, repair.ReloadedSvcs...)
	res.Warnings = append(res.Warnings, repair.Warnings...)

	if !repair.Reconciled {
		// The rewrite is queued, so the passwd-file still holds the rejected
		// hash and a second probe would only repeat the first answer.
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the password hash stored for %s is not one this Dovecot accepts (%v); it was "+
				"rewritten with %s and the configuration sync is queued — the login is not "+
				"proven until that run finishes", address, firstErr, alt))
		return
	}

	if err := s.authTest(ctx, address, password); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%s still does not authenticate after its password hash was rewritten with %s (%v): "+
				"the mailbox is in the panel but cannot log in — check `doveadm pw -l` and the "+
				"line for it in /etc/dovecot/users", address, alt, err))
		return
	}

	res.Warnings = append(res.Warnings, fmt.Sprintf(
		"the password hash stored for %s was not one this Dovecot could verify (%v); "+
			"it was rewritten with %s and the login now works", address, firstErr, alt))
}

// repairScheme picks the scheme to re-hash a password with when the stored one
// did not authenticate, and reports whether there is one worth trying.
//
// argon2 says whether this Dovecot can verify ARGON2ID at all (see
// dovecot.SupportsArgon2id). It is a parameter rather than a probe inside so the
// choice can be tested without a Dovecot and the probe is paid for once.
//
// SSHA512 comes first, because it is the one scheme no build lacks: the rejected
// hash is normally a {CRYPT} one imported from /etc/shadow, and re-hashing it
// into argon2id on a Dovecot built without libsodium would replace one hash
// nothing can check with another. When the rejected hash already *is* SSHA512,
// argon2id is the only scheme left — and it is only worth writing if the host was
// built with it.
func repairScheme(hash string, argon2 bool) (string, bool) {
	upper := strings.ToUpper(strings.TrimSpace(hash))

	if !strings.HasPrefix(upper, "{"+dovecot.SchemeSSHA512+"}") {
		return dovecot.SchemeSSHA512, true
	}
	if argon2 {
		return dovecot.SchemeArgon2id, true
	}
	return "", false
}
