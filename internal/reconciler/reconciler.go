package reconciler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
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
}

func New(cfg Config, auditor *audit.Logger) *Reconciler {
	return &Reconciler{cfg: cfg, auditor: auditor}
}

// Config returns the configuration this reconciler was built with.
//
// It exists so the mutation service can build a second reconciler that shares
// the paths but runs in DryRun mode: a preview must never write a file or reload
// a service, which is what v1.0.4 did by borrowing the live reconciler.
func (r *Reconciler) Config() Config { return r.cfg }

// managedFile is a single file the reconciler owns.
// Extracted as a named type so we can append dynamic entries
// (per-user Sieve scripts) to the static list.
type managedFile struct {
	path    string
	content []byte
	mode    os.FileMode
	service string // which service to reload if this changes ("" = no reload)
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

	// ------------------------------------------------------------------
	// Build all desired file contents first. Nothing touches disk yet.
	// ------------------------------------------------------------------

	files := []managedFile{
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "main.cf.managed"),
			content: RenderPostfixMainCF(snap, r.cfg.Hostname),
			mode:    0o644,
			service: "postfix",
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
			content: RenderHeloAccess(snap, r.cfg.Hostname),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "header_checks"),
			content: RenderHeaderChecks(r.cfg.Hostname),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.PostfixConfDir, "master.cf"),
			content: RenderMasterCF(ports.Render, snap.Ports, filepath.Join(r.cfg.PostfixConfDir, "master.cf")),
			mode:    0o644,
			service: "postfix",
		},
		{
			path:    filepath.Join(r.cfg.DovecotConfDir, "users"),
			content: RenderDovecotPasswd(snap),
			mode:    0o600,
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
			content: RenderDovecotUsersConf(filepath.Join(r.cfg.DovecotConfDir, "users")),
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
			content: RenderTrustedHosts(snap, r.cfg.Hostname),
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

		change, err := WriteFile(f.path, f.content, f.mode, r.cfg.DryRun)
		if err != nil {
			return res, fmt.Errorf("write %s: %w", f.path, err)
		}
		res.Changes = append(res.Changes, change)

		if change.Action == "unchanged" || change.Action == "delete" {
			continue
		}

		// Entries the renderer no longer produces: hand-added mailboxes, aliases
		// or keys. Report them, and preserve the file they came from.
		if drift := detectDrift(f.path, before, f.content); drift != nil {
			if !r.cfg.DryRun {
				drift.Backup = backupCopy(backupDir, f.path, before)
			}
			res.Drift = append(res.Drift, *drift)
			res.Warnings = append(res.Warnings, driftWarning(*drift))
		} else if !r.cfg.DryRun && change.Action == "update" {
			// Ordinary update: still keep the previous version around.
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
	// Postfix hash maps: virtual, vmailbox, vuidmaps, vgidmaps and
	// helo_access need `postmap`.
	// ------------------------------------------------------------------
	if !r.cfg.DryRun && !r.cfg.SkipValidation {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		for _, name := range []string{"virtual", "vmailbox", "vuidmaps", "vgidmaps", "helo_access"} {
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
