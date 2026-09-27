package reconciler

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/ports"
)

type Config struct {
	PostfixConfDir    string // /etc/postfix
	DovecotConfDir    string // /etc/dovecot
	OpenDKIMDir       string // /etc/opendkim
	Hostname          string
	DryRun            bool
	SkipServiceReload bool // for tests
}

type Result struct {
	Changes      []FileChange
	ReloadedSvcs []string
	StartedAt    time.Time
	FinishedAt   time.Time
}

type Reconciler struct {
	cfg     Config
	auditor *audit.Logger
}

func New(cfg Config, auditor *audit.Logger) *Reconciler {
	return &Reconciler{cfg: cfg, auditor: auditor}
}

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

	servicesToReload := map[string]bool{}
	backupDir := filepath.Join("/var/backups/mailx", time.Now().Format("20060102_150405"))

	for _, f := range files {
		change, err := WriteFile(f.path, f.content, f.mode, r.cfg.DryRun)
		if err != nil {
			return res, fmt.Errorf("write %s: %w", f.path, err)
		}
		res.Changes = append(res.Changes, change)

		if change.Action == "unchanged" || change.Action == "delete" {
			continue
		}

		// Back up before overwriting (only in real runs)
		if !r.cfg.DryRun && change.Action == "update" {
			if err := os.MkdirAll(backupDir, 0o755); err == nil {
				backupPath := filepath.Join(backupDir, filepath.Base(f.path))
				if _, err := BackupFileTo(f.path, backupPath); err != nil {
					// Non-fatal — continue
					_ = err
				}
			}
		}

		if f.service != "" {
			servicesToReload[f.service] = true
		}
	}

	// ------------------------------------------------------------------
	// Postfix hash maps: virtual, vmailbox, helo_access need `postmap`.
	// ------------------------------------------------------------------
	if !r.cfg.DryRun {
		for _, name := range []string{"virtual", "vmailbox", "helo_access"} {
			path := filepath.Join(r.cfg.PostfixConfDir, name)
			if fileChanged(res.Changes, path) {
				if err := runCmd(ctx, "postmap", path); err != nil {
					return res, fmt.Errorf("postmap %s: %w", path, err)
				}
			}
		}
	}

	// ------------------------------------------------------------------
	// Validate configs before reloading services.
	// ------------------------------------------------------------------
	if !r.cfg.DryRun {
		if servicesToReload["postfix"] {
			if err := runCmd(ctx, "postfix", "check"); err != nil {
				return res, fmt.Errorf("postfix check failed: %w", err)
			}
		}
		if servicesToReload["dovecot"] {
			if err := runCmd(ctx, "doveconf", "-n"); err != nil {
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
		order := []string{"opendkim", "dovecot", "postfix"}
		for _, svc := range order {
			if !servicesToReload[svc] {
				continue
			}
			if err := runCmd(ctx, "systemctl", "reload-or-restart", svc); err != nil {
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

func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return nil
}
