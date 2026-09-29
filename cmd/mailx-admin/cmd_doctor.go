package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/doctor"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
)

// cmdDoctor is the read-only health check. It exists because v1.0.4's failures
// were impossible to see from the outside: a stalled sync looked like a slow
// page, and a mailbox that was never imported looked like a missing feature.
// Everything it does is a read (or a dry-run render), so it is safe to run on a
// live server.
func cmdDoctor() *cobra.Command {
	var (
		cfgPath  string
		jsonOut  bool
		bundle   string
		noChecks bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that the panel, the database and the daemons agree (read-only)",
		Long: `Run every diagnostic the panel has, without changing anything.

Checks: database schema, panel state, whether the managed configuration files
match the database (dry run), whether postfix/doveconf accept them, mailboxes
that exist on the server but not in the panel, the mail services, and the
outcome of the last configuration sync.

Exits non-zero when a check fails, so it can be used from a monitoring script.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			rec := reconciler.New(reconciler.Config{
				PostfixConfDir: cfg.Mail.PostfixConfDir,
				DovecotConfDir: cfg.Mail.DovecotConfDir,
				OpenDKIMDir:    cfg.Mail.OpenDKIMDir,
				Hostname:       cfg.Server.Hostname,
			}, nil)

			report := doctor.Run(ctx, doctor.Options{
				Config:       cfg,
				DB:           database.DB,
				Store:        st,
				Rec:          rec,
				SkipServices: noChecks,
			})

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
			} else {
				printReport(report)
			}

			if bundle != "" {
				if err := writeBundle(bundle, report, cfgPath); err != nil {
					return err
				}
				fmt.Printf("\ndiagnostics written to %s\n", bundle)
			}

			if report.Failed() {
				return fmt.Errorf("doctor found problems")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	cmd.Flags().StringVar(&bundle, "bundle", "", "also write the report, a redacted admin.toml and the daemon checks to this .tar.gz")
	cmd.Flags().BoolVar(&noChecks, "skip-services", false, "skip the systemctl checks (for a host that is not the mail server)")
	return cmd
}

func printReport(report *doctor.Report) {
	fmt.Printf("mailx-admin doctor — %s\n\n", report.Version)
	for _, c := range report.Checks {
		fmt.Printf("  [%s] %-22s %s\n", marker(c.Status), c.Name, c.Detail)
		if c.Hint != "" {
			fmt.Printf("                             %s\n", c.Hint)
		}
		if c.Command != "" {
			fmt.Printf("                             → %s\n", c.Command)
		}
	}
	fmt.Printf("\nsummary: %s\n", report.Health())
}

func marker(s doctor.Status) string {
	switch s {
	case doctor.OK:
		return " ok "
	case doctor.Warn:
		return "warn"
	case doctor.Fail:
		return "FAIL"
	default:
		return "info"
	}
}

// secretValue matches the password-ish keys the installer writes into
// admin.toml. A diagnostics bundle is meant to be sent to someone else, so it
// must not carry credentials.
var secretValue = regexp.MustCompile(`(?i)((?:password|secret|key|token)\s*=\s*)"[^"]*"`)

// writeBundle collects everything needed to debug a deployment offline.
func writeBundle(path string, report *doctor.Report, cfgPath string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	entries := map[string]string{}
	if reportJSON, err := json.MarshalIndent(report, "", "  "); err == nil {
		entries["doctor.json"] = string(reportJSON)
	}
	if cfgPath != "" {
		if raw, err := os.ReadFile(cfgPath); err == nil {
			entries["admin.toml"] = secretValue.ReplaceAllString(string(raw), `$1"<redacted>"`)
		}
	}
	for _, cmdline := range [][]string{
		{"systemctl", "status", "mailx-admin", "--no-pager"},
		{"systemctl", "status", "postfix", "--no-pager"},
		{"doveconf", "-n"},
	} {
		out, err := runCapture(cmdline[0], cmdline[1:]...)
		if err == nil || out != "" {
			entries[strings.Join(cmdline, "_")+".txt"] = out
		}
	}

	return writeTarGz(path, entries)
}
