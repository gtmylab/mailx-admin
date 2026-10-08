package reconciler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/dovecot"
	"github.com/gtmylab/mailx-admin/internal/execx"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/ports"
)

// Timeouts for the external helpers. They exist so a wedged helper cannot hold
// the caller (and, before v1.0.5, the request that triggered it) forever.
const (
	// commandTimeout bounds the cheap validation helpers: postmap (3 hash maps),
	// `postfix check` and `doveconf -n`.
	commandTimeout = 45 * time.Second

	// reloadTimeout is longer: `systemctl reload-or-restart` waits for the
	// service's own ExecReload / ExecStop to finish, and Dovecot flushing its
	// mailboxes is not instant.
	reloadTimeout = 120 * time.Second
)

type Config struct {
	PostfixConfDir    string // /etc/postfix
	DovecotConfDir    string // /etc/dovecot
	OpenDKIMDir       string // /etc/opendkim
	Hostname          string
	DryRun            bool
	SkipServiceReload bool // for tests

	// SkipMaildirs disables the mailbox directory pass (see ensureMaildirs).
	// Set by the test suite and by nothing else: every reconcile that is
	// allowed to write files also has to make sure the directories the
	// daemons were just told about exist, or the first delivery after a
	// "successful" sync fails.
	SkipMaildirs bool

	// SkipValidation disables the external validators (postmap, `postfix
	// check`, `doveconf -n`). The panel never sets it: postmap also *builds* the
	// hash maps Postfix reads, so skipping it in production would leave the
	// server without usable lookup tables. It exists so the test suite can run
	// on a machine with no mail stack installed.
	SkipValidation bool

	// BackupDir is where the previous version of a managed file is preserved
	// before it is overwritten. Empty means /var/backups/mailx.
	BackupDir string

	// PasswdScheme is what new mailbox passwords are hashed with, and the
	// passdb's default scheme — [mail] passwd_scheme in admin.toml.
	//
	// Empty and "auto" both mean "ask the local Dovecot", which is what a
	// server wants: argon2id where Dovecot supports it, SSHA512 where it was
	// built without libsodium — and SSHA512 too when the question cannot be
	// answered at all, because the scheme no build lacks is the only safe guess
	// when hashing a password nobody can check later would lock the mailbox out.
	// An explicit name is honoured only if the local
	// Dovecot can verify it; otherwise the sync fails with an explanation
	// rather than writing hashes nothing can check.
	PasswdScheme string

	// Probe asks the local Dovecot which password schemes it supports. It is a
	// field rather than a hard-coded call so the resolution policy in
	// resolveScheme can be tested without Dovecot installed — the same reason
	// dovecot.ProbeFunc is a parameter to dovecot.Resolve. Nil means
	// dovecot.ProbeCached, which is what the panel uses; nothing in production
	// sets it.
	Probe dovecot.ProbeFunc
}

// backupRoot is the directory the per-run backup folders are created in.
func (c Config) backupRoot() string {
	if c.BackupDir != "" {
		return c.BackupDir
	}
	return defaultBackupDir
}

type Result struct {
	Changes      []FileChange
	ReloadedSvcs []string
	StartedAt    time.Time
	FinishedAt   time.Time

	// Warnings are non-fatal problems the operator has to see: an entry that
	// was dropped because the panel does not manage it, a backup that could not
	// be written.
	Warnings []string `json:"warnings,omitempty"`

	// Drift lists the entries this run removed because they are not in the
	// panel (see Drift).
	Drift []Drift `json:"drift,omitempty"`

	// Maildirs names the mailbox directories this run created. It is what the
	// CLI prints after `mailbox add` and what the sync banner reports, so an
	// operator can tell "the mailbox exists" from "the mailbox can receive".
	Maildirs []string `json:"maildirs,omitempty"`
}

type Reconciler struct {
	cfg     Config
	auditor *audit.Logger

	// hostMu guards cfg.Hostname, which the server-settings page updates while
	// a reconcile may be running.
	hostMu sync.RWMutex
}

func New(cfg Config, auditor *audit.Logger) *Reconciler {
	return &Reconciler{cfg: cfg, auditor: auditor}
}

// SetHostname updates the hostname used when rendering Postfix configs. The
// server-settings page calls it after the operator changes the hostname, so the
// next reconcile uses the new value without restarting the panel.
func (r *Reconciler) SetHostname(h string) {
	r.hostMu.Lock()
	r.cfg.Hostname = h
	r.hostMu.Unlock()
}

// hostname is the mutex-guarded read of cfg.Hostname, used by Reconcile so a
// concurrent SetHostname can never race a render.
func (r *Reconciler) hostname() string {
	r.hostMu.RLock()
	defer r.hostMu.RUnlock()
	return r.cfg.Hostname
}

// Config returns the configuration this reconciler was built with.
//
// It exists so the mutation service can build a second reconciler that shares
// the paths but runs in DryRun mode: a preview must never write a file or reload
// a service, which is what v1.0.4 did by borrowing the live reconciler.
func (r *Reconciler) Config() Config {
	r.hostMu.RLock()
	defer r.hostMu.RUnlock()
	return r.cfg
}

// managedFile is a single file the reconciler owns.
// Extracted as a named type so we can append dynamic entries
// (per-user Sieve scripts) to the static list.
type managedFile struct {
	path    string
	content []byte
	mode    os.FileMode
	service string // which service to reload if this changes ("" = no reload)

	// owner, when set, is the uid/gid the file has to be given. Only Dovecot's
	// passwd-file uses it: it is the one managed file read by a process that is
	// not this one (see dovecotPasswdOwner).
	owner *Ownership

	// merge, when true, injects content into the file's existing bytes instead
	// of replacing the file wholesale. Only main.cf uses it: the installer
	// downloads the rest of that file from a template, so the panel owns just
	// the delimited managed block at the end (see mergeMainCF).
	merge bool
}

// resolvesToHostScheme reports whether a configured value means "ask the local
// Dovecot" rather than naming a scheme itself: empty and "auto", case- and
// space-insensitively, because it comes from a config file a human edited.
//
// dovecot.Resolve routes both to its auto path. If either spelling still reaches
// the passdb renderer — a direct call — it is rendered as "no scheme= at all"
// rather than as `scheme=auto`: a Dovecot cannot resolve that name, so writing it
// leaves the passdb with a default no build has, where writing nothing leaves it
// on its own (dovecot.DefaultPassdbScheme).
func resolvesToHostScheme(scheme string) bool {
	scheme = strings.TrimSpace(scheme)
	return scheme == "" || strings.EqualFold(scheme, dovecot.SchemeAuto)
}

// resolveScheme decides which password scheme this host's Dovecot can verify,
// and records a warning when the panel had to fall back from argon2id.
//
// The probe is skipped when the caller asked for no external helpers (the test
// suite, and anything that is not the mail server itself): the configured scheme
// is then taken at face value, and an unset one resolves to SSHA512 — the scheme
// every build can verify, since nothing on this path has asked what this one
// has.
//
// Otherwise it goes through the scheme probe (dovecot.ProbeCached by default),
// which answers from memory after the first call: this runs inside a dry run
// too, where a database transaction is open and forking would be a very bad
// idea (see internal/mutations).
//
// The one thing it must not do is fail the run over a scheme the panel chose for
// itself. Reconcile calls this before it renders anything and returns the error
// unchanged, so aborting here leaves /etc/dovecot/users unrendered: on a host
// that has never been synced that is every mailbox missing from the passdb, and
// logins refused with nothing to look at. That is the v1.0.9 regression — before
// it, the passdb's scheme= was a constant and this path did not exist.
//
// So a probe that could not run is neither fatal nor a guess at argon2id: the
// answer is SSHA512, which every Dovecot can verify, and the run warns about it.
// Neither is a probe that answered without listing either usable scheme (an
// installation that needs fixing, and what the doctor reports): the run carries
// on with no passdb default at all — Dovecot's own default then applies, which is
// what a prefix-less hash expects — and creating a mailbox fails at hash time with
// the list of schemes this Dovecot does have, instead of quietly writing a hash it
// cannot check.
//
// An *explicit* scheme this Dovecot cannot verify stays fatal: the operator asked
// for it, and every password hashed in it would be one this Dovecot refuses.
func (r *Reconciler) resolveScheme(ctx context.Context, res *Result) (string, error) {
	configured := strings.TrimSpace(r.cfg.PasswdScheme)

	// "" and "auto" both defer to the host; anything else names a scheme the
	// operator asked for.
	hostDecides := resolvesToHostScheme(configured)

	if r.cfg.SkipValidation {
		// "auto"/"" name no scheme of their own and nothing on this path
		// asked the host, so they resolve to the one that needs no answer:
		// SSHA512 is plain SHA-512 and is in every build. Handing them back
		// as they came (upper-cased, at that) put `scheme=AUTO` in the
		// passdb, and resolving them to argon2id assumed a libsodium this
		// path has no way to know about. Only tests set SkipValidation, but
		// the value goes through the same renderer production uses.
		if hostDecides {
			return dovecot.SchemeSSHA512, nil
		}
		return strings.ToUpper(configured), nil
	}

	probe := r.cfg.Probe
	if probe == nil {
		probe = dovecot.ProbeCached
	}

	resolution, err := dovecot.Resolve(ctx, r.cfg.PasswdScheme, probe)
	if err != nil {
		if !hostDecides {
			// The operator named a scheme this Dovecot cannot verify: fail the
			// run and let the error name the ones it does have, rather than
			// hash a password nothing on this host can ever check.
			return "", fmt.Errorf("password scheme: %w", err)
		}
		// "auto" could not be answered: the probe that ran said this Dovecot
		// has neither usable scheme. Write no passdb default rather than a
		// name this build may not know — scheme= only ever applies to a hash
		// with no {SCHEME} prefix, and the panel prefixes every hash it
		// creates, so nothing the panel wrote depends on it. Aborting instead
		// would leave the passwd-file unrendered; a mailbox created in this
		// state fails loudly when its password is hashed.
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"could not work out which password schemes this Dovecot supports (%v); "+
				"writing no passdb default — set [mail] passwd_scheme to one of the "+
				"schemes it does support", err,
		))
		return "", nil
	}
	if resolution.Fallback {
		res.Warnings = append(res.Warnings, resolution.Detail)
	}
	return resolution.Scheme, nil
}

// Reconcile renders all configs from snap and applies them.
//
// Guarantees:
//   - Files that don't change are not touched (no spurious mtime bumps)
//   - All writes are atomic (temp + rename)
//   - Services are reloaded at most once, only if their configs changed
//   - On any error, no service is reloaded (fail-safe)
func (r *Reconciler) Reconcile(ctx context.Context, snap *models.Snapshot) (*Result, error) {
	res := &Result{StartedAt: time.Now()}
	defer func() { res.FinishedAt = time.Now() }()

	// Snapshot the hostname once: the server-settings page may change it while
	// this reconcile runs, and every rendered file must agree on the same value.
	hostname := r.hostname()

	// ------------------------------------------------------------------
	// Password scheme.
	//
	// This is decided before anything is rendered, and it is what the
	// mutation service hashes new passwords with too: a hash written in one
	// scheme while Dovecot is told to treat another as the default is a
	// mailbox nobody can log into. The probe also has to happen before the
	// configs are written, because an explicit scheme this Dovecot cannot
	// verify must fail the run rather than reach the daemons.
	// ------------------------------------------------------------------
	scheme, err := r.resolveScheme(ctx, res)
	if err != nil {
		return res, err
	}

	// ------------------------------------------------------------------
	// Build all desired file contents first. Nothing touches disk yet.
	// ------------------------------------------------------------------

	files := []managedFile{
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "main.cf"),
			content: RenderPostfixMainCF(snap, hostname),
			mode:    0o644,
			service: "postfix",
			merge:   true,
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "virtual"),
			content: RenderVirtualMap(snap),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "vmailbox"),
			content: RenderVmailboxMap(snap),
			mode:    0o644,
			service: "postfix",
		},
		{
			// Per-recipient delivery ownership. Without these two maps a
			// mailbox on a real account is looked up in vmailbox (delivery
			// path /home/<user>/Maildir) and then delivered as uid 5000,
			// which cannot write there.
			path:    filepath.Join(r.cfg.PostfixConfDir, "vuidmaps"),
			content: RenderVirtualUidMaps(snap),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "vgidmaps"),
			content: RenderVirtualGidMaps(snap),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "helo_access"),
			content: RenderHeloAccess(snap, hostname),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "header_checks"),
			content: RenderHeaderChecks(hostname),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "master.cf"),
			content: RenderMasterCF(ports.Render, snap.Ports, filepath.Join(r.cfg.PostfixConfDir, "master.cf"), RenderOutboundTransports(snap.OutboundIPs)),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "sender_transport"),
			content: RenderSenderTransport(snap.OutboundIPs),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "suppressions"),
			content: RenderSuppressions(snap.Suppressions),
			mode:    0o644,
			service: "postfix",
		},
		{
			// smarthost credentials. 0600 root:root: this file holds the relay
			// password in plaintext and must not be world-readable.
			path:    filepath.Join(r.cfg.PostfixConfDir, "sasl_passwd"),
			content: RenderSaslPasswd(snap.Relay),
			mode:    0o600,
			service: "postfix",
		},
		{
			// 0640 root:dovecot, not 0600 root:root as this used to be written.
			// Dovecot's auth process drops to the unprivileged `dovecot` user
			// (default_internal_user) and is the process that opens this file:
			// 0600 root:root is a passdb it cannot read, and the failure surfaces
			// as a refused login rather than as a permissions error. 0640 keeps
			// the hashes away from everybody except root and the auth process.
			path:    filepath.Join(r.cfg.DovecotConfDir, "users"),
			content: RenderDovecotPasswd(snap),
			mode:    0o640,
			owner:   dovecotPasswdOwner(),
			service: "dovecot",
		},
		{
			path:    filepath.Join(r.cfg.DovecotConfDir, "conf.d", "90-quota.conf"),
			content: RenderDovecotQuotaConf(),
			mode:    0o644,
			service: "dovecot",
		},
		{
			path:    filepath.Join(r.cfg.DovecotConfDir, "conf.d", "10-auth-mailx.conf"),
			content: RenderDovecotUsersConf(filepath.Join(r.cfg.DovecotConfDir, "users"), scheme),
			mode:    0o644,
			service: "dovecot",
		},
		{
			path:    filepath.Join(r.cfg.OpenDKIMDir, "KeyTable"),
			content: RenderKeyTable(snap, r.cfg.OpenDKIMDir),
			mode:    0o644,
			service: "opendkim",
		},
		{
			path:    filepath.Join(r.cfg.OpenDKIMDir, "SigningTable"),
			content: RenderSigningTable(snap),
			mode:    0o644,
			service: "opendkim",
		},
		{
			path:    filepath.Join(r.cfg.OpenDKIMDir, "TrustedHosts"),
			content: RenderTrustedHosts(snap, hostname),
			mode:    0o644,
			service: "opendkim",
		},
		{
			// The main config lives one level up (/etc/opendkim.conf). It must be
			// managed too: the installer left it in single-domain mode
			// (Domain/Selector/KeyFile), which made OpenDKIM ignore the tables
			// above and sign with a single hardcoded key.
			path:    filepath.Join(filepath.Dir(r.cfg.OpenDKIMDir), "opendkim.conf"),
			content: RenderOpenDKIMConf(r.cfg.OpenDKIMDir),
			mode:    0o644,
			service: "opendkim",
		},
	}

	// ------------------------------------------------------------------
	// Per-user Sieve scripts.
	//
	// Rules are optional — a user with no rules has no managed script.
	// We only emit a file when the user actually has rules, so we don't
	// create empty sieve scripts that would suppress a user's own script
	// (e.g. one they uploaded via ManageSieve).
	// ------------------------------------------------------------------
	for _, u := range snap.Users {
		rules := snap.SieveRules[u.ID]
		if len(rules) == 0 {
			continue
		}

		content, err := RenderUserSieve(u, rules)
		if err != nil {
			return res, fmt.Errorf("render sieve for %s: %w", u.Email, err)
		}

		files = append(files, managedFile{
			path:    UserSievePath(u),
			content: content,
			mode:    0o600,
			service: "dovecot",
		})
	}

	// ------------------------------------------------------------------
	// Apply each file. Collect changes and which services need reloading.
	// ------------------------------------------------------------------

	// Everything above only rendered bytes. From here on the filesystem and
	// the services are touched, so a caller that has already given up (request
	// deadline, shutdown) must get an error instead of half-applied config.
	if err := ctx.Err(); err != nil {
		return res, err
	}

	servicesToReload := map[string]bool{}
	backupDir := filepath.Join(r.cfg.backupRoot(), time.Now().Format("20060102_150405"))

	for _, f := range files {
		// Read the current content first: it is what the drift check compares
		// against, and what the pre-write copy has to hold. v1.0.4 copied the
		// file *after* WriteFile had already replaced it, so its "backup" held
		// the new content — no way back to a mailbox the sync had just dropped.
		before, readErr := os.ReadFile(f.path)
		if readErr != nil && !os.IsNotExist(readErr) {
			return res, fmt.Errorf("read %s: %w", f.path, readErr)
		}

		content := f.content
		if f.merge {
			// main.cf is not owned whole: merge the managed block into the
			// template the installer downloaded, so Postfix actually reads it.
			content = mergeMainCF(before, f.content)
		}

		change, err := WriteFileOwned(f.path, content, f.mode, f.owner, r.cfg.DryRun)
		if errors.Is(err, ErrOwnership) {
			// The content is in place; only the owner could not be set. Warn
			// and carry on: see ErrOwnership, and doctor.passwdFileCheck, which
			// reports the resulting file.
			res.Warnings = append(res.Warnings, err.Error())
			err = nil
		}
		if err != nil {
			return res, fmt.Errorf("write %s: %w", f.path, err)
		}
		res.Changes = append(res.Changes, change)

		if change.Action == "unchanged" || change.Action == "delete" {
			continue
		}

		// Entries the renderer no longer produces: hand-added mailboxes, aliases
		// or keys. Report them, and preserve the file they came from. main.cf is
		// a merged template, not a rendered list, so drift does not apply to it.
		if !f.merge {
			if drift := detectDrift(f.path, before, content); drift != nil {
				if !r.cfg.DryRun {
					drift.Backup = backupCopy(backupDir, f.path, before)
				}
				res.Drift = append(res.Drift, *drift)
				res.Warnings = append(res.Warnings, driftWarning(*drift))
			} else if !r.cfg.DryRun && change.Action == "update" {
				// Ordinary update: still keep the previous version around.
				_ = backupCopy(backupDir, f.path, before)
			}
		} else if !r.cfg.DryRun && change.Action == "update" {
			_ = backupCopy(backupDir, f.path, before)
		}

		if f.service != "" {
			servicesToReload[f.service] = true
		}
	}

	// ------------------------------------------------------------------
	// Mailbox directories.
	//
	// The configs above describe mailboxes that have to exist on disk before
	// the daemons can deliver into them: nothing in this project ever created
	// /var/mail/vhosts/<domain>/<user>, which is why a mailbox created in the
	// panel could be listed, rendered into every map, and still bounce.
	//
	// Failures are warnings (see ensureMaildirs): the files are already
	// written and valid, and refusing to reload on top of a directory the
	// panel cannot create would turn a permissions problem into a broken
	// mailserver.
	// ------------------------------------------------------------------
	if !r.cfg.DryRun && !r.cfg.SkipMaildirs {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		created, warnings := ensureMaildirs(ctx, snap)
		res.Maildirs = created
		res.Warnings = append(res.Warnings, warnings...)
	}

	// ------------------------------------------------------------------
	// DKIM key ownership.
	//
	// The OpenDKIM daemon runs as opendkim:opendkim; it must be able to
	// traverse into /etc/opendkim/keys/<domain> and read the private key.
	// dkim.Generate chowns the key files but not the directory it creates, so a
	// key added through the panel ends up in a 0750 root:root directory the
	// daemon cannot enter — signing fails with "Permission denied" and every
	// message is deferred. Re-apply the ownership on every reconcile so an
	// already-broken install heals on the next update.
	// ------------------------------------------------------------------
	if !r.cfg.DryRun {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Warnings = append(res.Warnings, ensureDKIMKeyOwnership(ctx, snap)...)
	}

	// ------------------------------------------------------------------
	// Postfix hash maps: virtual, vmailbox, vuidmaps, vgidmaps and
	// helo_access need `postmap`.
	// ------------------------------------------------------------------
	if !r.cfg.DryRun && !r.cfg.SkipValidation {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		for _, name := range []string{"virtual", "vmailbox", "vuidmaps", "vgidmaps", "helo_access", "sender_transport", "suppressions", "sasl_passwd"} {
			path := filepath.Join(r.cfg.PostfixConfDir, name)
			if fileChanged(res.Changes, path) {
				if err := runCmd(ctx, commandTimeout, "postmap", path); err != nil {
					return res, fmt.Errorf("postmap %s: %w", path, err)
				}
			}
		}
	}

	// ------------------------------------------------------------------
	// Validate configs before reloading services.
	// ------------------------------------------------------------------
	if !r.cfg.DryRun && !r.cfg.SkipValidation {
		if servicesToReload["postfix"] {
			if err := runCmd(ctx, commandTimeout, "postfix", "check"); err != nil {
				return res, fmt.Errorf("postfix check failed: %w", err)
			}
		}
		if servicesToReload["dovecot"] {
			if err := runCmd(ctx, commandTimeout, "doveconf", "-n"); err != nil {
				return res, fmt.Errorf("dovecot config check failed: %w", err)
			}
		}
	}

	// ------------------------------------------------------------------
	// Reload services (once each), in dependency order.
	//
	// OpenDKIM first so the milter socket exists before Postfix starts
	// trying to connect to it. Dovecot next (SASL socket for Postfix).
	// Postfix last.
	// ------------------------------------------------------------------
	if !r.cfg.SkipServiceReload && !r.cfg.DryRun {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		order := []string{"opendkim", "dovecot", "postfix"}
		for _, svc := range order {
			if !servicesToReload[svc] {
				continue
			}
			if err := runCmd(ctx, reloadTimeout, "systemctl", "reload-or-restart", svc); err != nil {
				return res, fmt.Errorf("reload %s: %w", svc, err)
			}
			res.ReloadedSvcs = append(res.ReloadedSvcs, svc)
		}
	}

	// ------------------------------------------------------------------
	// Audit log
	// ------------------------------------------------------------------
	if r.auditor != nil {
		_ = r.auditor.Log(ctx, audit.Entry{
			Actor:  "system:reconciler",
			Action: "reconcile",
			Result: "ok",
			Detail: map[string]any{
				"dry_run":           r.cfg.DryRun,
				"files_changed":     countChanged(res.Changes),
				"services_reloaded": res.ReloadedSvcs,
				"drift":             len(res.Drift),
				"maildirs_created":  len(res.Maildirs),
				"warnings":          res.Warnings,
			},
		})
	}

	return res, nil
}

func countChanged(changes []FileChange) int {
	n := 0
	for _, c := range changes {
		if c.Action != "unchanged" {
			n++
		}
	}
	return n
}

func fileChanged(changes []FileChange, path string) bool {
	for _, c := range changes {
		if c.Path == path && (c.Action == "create" || c.Action == "update") {
			return true
		}
	}
	return false
}

// runCmd executes one external helper under a hard deadline and with the whole
// process group killed on expiry. See package execx for why.
func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) error {
	return execx.Run(ctx, timeout, name, args...)
}
