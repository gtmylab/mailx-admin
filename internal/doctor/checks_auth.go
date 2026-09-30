package doctor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/dovecot"
	"github.com/gtmylab/mailx-admin/internal/roundcube"
)

// schemeCheck answers the first question a failed login raises: can this
// Dovecot verify the hashes the panel writes?
//
// There are two ways it cannot, and they look identical from the outside. The
// passdb's `scheme=` default can name a scheme the build does not know, in
// which case the passdb does not initialise at all; or one mailbox's hash can
// carry a {SCHEME} the build does not know, in which case exactly that mailbox
// is refused — created in the panel or imported years ago, the panel cannot
// tell the difference. The second is invisible everywhere else in this panel,
// which is why it is checked here.
func schemeCheck(ctx context.Context, opts Options) Check {
	const name = "password scheme"
	if opts.Config == nil {
		return Check{}
	}

	out, err := dovecot.ProbeCached(ctx)
	if err != nil {
		return Check{
			Name:    name,
			Status:  Warn,
			Detail:  "this Dovecot could not be asked which password schemes it supports: " + err.Error(),
			Hint:    "run doctor on the mail server itself; until then the panel keeps using ARGON2ID",
			Command: "doveadm pw -l",
		}
	}
	schemes := dovecot.ParseSchemes(out)

	// The same answer the reconciler and the mutation service use, from the
	// output we already have.
	resolution, err := dovecot.Resolve(ctx, opts.Config.Mail.PasswdScheme,
		func(context.Context) (string, error) { return out, nil })
	if err != nil {
		return Check{
			Name:    name,
			Status:  Fail,
			Detail:  err.Error(),
			Hint:    "a mailbox hashed with a scheme this Dovecot cannot verify never logs in",
			Command: "doveadm pw -l",
		}
	}

	passwdFile := filepath.Join(opts.Config.Mail.DovecotConfDir, "users")
	counts, err := dovecot.ScanHashSchemes(passwdFile)
	if err != nil && !os.IsNotExist(err) {
		return Check{Name: name, Status: Warn, Detail: err.Error()}
	}

	unverifiable := unverifiableHashes(counts, schemes, resolution.Scheme)
	mailboxes := 0
	for _, n := range counts {
		mailboxes += n
	}

	if len(unverifiable) > 0 {
		return Check{
			Name:   name,
			Status: Fail,
			Detail: "this Dovecot cannot verify " + strings.Join(unverifiable, ", ") +
				"; those mailboxes are refused at login",
			Hint: "set their password again in the panel (Users → the mailbox → password): " +
				"a fresh hash is written in " + resolution.Scheme + ", which this Dovecot can verify",
			Command: "doveadm pw -l",
		}
	}

	if resolution.Fallback {
		return Check{
			Name:   name,
			Status: Warn,
			Detail: resolution.Detail + fmt.Sprintf(" (%d mailbox hash(es) in %s, all verifiable)",
				mailboxes, passwdFile),
			Hint:    "install libsodium (apt install libsodium23) and restart Dovecot to get the memory-hard scheme back",
			Command: "doveadm pw -l",
		}
	}

	return Check{
		Name:   name,
		Status: OK,
		Detail: fmt.Sprintf("%s; %d mailbox hash(es) in %s, all verifiable",
			resolution.Detail, mailboxes, passwdFile),
	}
}

// unverifiableHashes lists what in a passwd-file this Dovecot cannot check.
//
// It is the whole point of the check, and it is pure so it can be tested
// without a Dovecot: counts comes from the passwd-file, schemes from
// `doveadm pw -l`, and defaultScheme is what an unprefixed hash would be
// verified with (the passdb's `scheme=`).
func unverifiableHashes(counts map[string]int, schemes dovecot.Schemes, defaultScheme string) []string {
	var unverifiable []string
	for scheme, n := range counts {
		if n == 0 {
			continue
		}
		if scheme == "(default)" {
			if !schemes.Has(defaultScheme) {
				unverifiable = append(unverifiable,
					fmt.Sprintf("%d hash(es) with no {SCHEME} (the passdb default, %s)", n, defaultScheme))
			}
			continue
		}
		if !schemes.Has(scheme) {
			unverifiable = append(unverifiable, fmt.Sprintf("%d {%s} hash(es)", n, scheme))
		}
	}
	sort.Strings(unverifiable)
	return unverifiable
}

// roundcubeCheck reports whether the panel's mailboxes have an account in
// Roundcube's own database.
//
// It is the check for "the mailbox exists, the password is right, and webmail
// still treats it as new". Roundcube creates the row itself at first login, so
// a missing row is not a refused login — it is a login without the mailbox' own
// From: address, language and preferences, and nothing in the panel shows that.
func roundcubeCheck(ctx context.Context, opts Options) Check {
	const name = "roundcube accounts"
	if opts.Config == nil {
		return Check{}
	}

	rc := opts.Config.Roundcube
	if !rc.Enabled {
		return Check{
			Name:   name,
			Status: Info,
			Detail: "the panel does not pre-seed Roundcube's database ([roundcube] is disabled)",
			Hint: "webmail still works — Roundcube creates the account at first login, " +
				"without the mailbox' own identity or preferences",
			Command: "mailx-admin roundcube sync",
		}
	}

	client := roundcube.New(rc.ToClientConfig())
	known, err := client.ListUsers(ctx)
	if err != nil {
		return Check{
			Name:    name,
			Status:  Warn,
			Detail:  fmt.Sprintf("Roundcube's database (%s) could not be read: %v", rc.Database, err),
			Hint:    "a mailbox created while this was failing has no webmail account yet",
			Command: "mailx-admin roundcube sync",
		}
	}

	if opts.Store == nil {
		return Check{
			Name:   name,
			Status: OK,
			Detail: fmt.Sprintf("%d account(s) in %s on %s", len(known), rc.Database, rc.MailHost),
		}
	}

	snap, err := opts.Store.Snapshot(ctx)
	if err != nil {
		return Check{Name: name, Status: Warn, Detail: err.Error()}
	}

	have := make(map[string]bool, len(known))
	for _, login := range known {
		have[login] = true
	}

	var missing []string
	for _, u := range snap.Users {
		if email := strings.ToLower(u.Email); !have[email] {
			missing = append(missing, email)
		}
	}
	sort.Strings(missing)

	detail := fmt.Sprintf("%d account(s) in %s on %s; %d of %d mailbox(es) have no account",
		len(known), rc.Database, rc.MailHost, len(missing), len(snap.Users))

	if len(missing) == 0 {
		return Check{Name: name, Status: OK, Detail: detail}
	}
	return Check{
		Name:   name,
		Status: Warn,
		Detail: detail + ": " + firstFew(missing, 5),
		Hint: "webmail creates them at first login, without the mailbox' own identity, " +
			"language and preferences",
		Command: "mailx-admin roundcube sync",
	}
}

// firstFew renders a list for a one-line detail, so a server with 400 mailboxes
// does not produce a 400-address check.
func firstFew(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" (+%d more)", len(items)-n)
}
