package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/seed"
)

func cmdSeed() *cobra.Command {
	var (
		cfgPath string
		dryRun  bool
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Adopt existing server state into the admin database",
		Long: `Scan the server's Postfix/Dovecot/OpenDKIM configs and populate the
admin database with what is found. This is a one-time operation after
upgrading from a shell-managed install.

Will refuse to run if any domains already exist in the DB, unless --force is set.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			// ---- Refuse if already seeded ----
			existing, err := st.Snapshot(ctx)
			if err != nil {
				return err
			}
			if len(existing.Domains) > 0 {
				return fmt.Errorf(
					"database already has %d domain(s) — refusing to seed. "+
						"Use 'mailx-admin status' to inspect, or drop tables to re-seed.",
					len(existing.Domains),
				)
			}

			// ---- Scan ----
			fmt.Println("Scanning existing server state...")
			found, err := seed.Scan(seed.Options{
				PostfixConfDir:    cfg.Mail.PostfixConfDir,
				DovecotConfDir:    cfg.Mail.DovecotConfDir,
				OpenDKIMDir:       cfg.Mail.OpenDKIMDir,
				PrimaryDomainFile: cfg.Mail.PrimaryDomainFile,
			})
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			// ---- Report ----
			fmt.Println()
			fmt.Printf("Found %d domain(s):\n", len(found.Domains))
			for _, d := range found.Domains {
				marker := ""
				if d.IsPrimary {
					marker = " (primary)"
				}
				dkim := "no DKIM key"
				if d.DKIMPrivateKey != "" {
					dkim = "DKIM key present"
				}
				fmt.Printf("  - %s%s  [%s]\n", d.Name, marker, dkim)
			}
			fmt.Println()

			fmt.Printf("Found %d user(s):\n", len(found.Users))
			for _, u := range found.Users {
				fmt.Printf("  - %s (quota=%dMB)\n", u.Email, u.QuotaMB)
			}
			fmt.Println()

			fmt.Printf("Found %d alias(es):\n", len(found.Aliases))
			for _, a := range found.Aliases {
				fmt.Printf("  - %s@%s -> %s\n", a.Source, a.Domain, a.Destination)
			}
			fmt.Println()

			if dryRun {
				fmt.Println("[dry-run] No changes written.")
				return nil
			}

			// ---- Confirm ----
			if !yes {
				fmt.Print("Import this state into the admin DB? [y/N]: ")
				var resp string
				fmt.Scanln(&resp)
				if resp != "y" && resp != "Y" {
					fmt.Println("Aborted.")
					return nil
				}
			}

			// ---- Apply ----
			fmt.Println("Writing to database...")
			if err := seed.Apply(ctx, st, found); err != nil {
				return fmt.Errorf("apply: %w", err)
			}

			// ---- Audit ----
			auditor := audit.New(database.DB)
			_ = auditor.Log(ctx, audit.Entry{
				Actor:  "cli:seed",
				Action: "seed",
				Result: "ok",
				Detail: map[string]any{
					"domains": len(found.Domains),
					"users":   len(found.Users),
					"aliases": len(found.Aliases),
				},
			})

			fmt.Println()
			fmt.Println("Seed complete. Next steps:")
			fmt.Printf("  1. Run a dry-run reconcile to verify parity:\n")
			fmt.Printf("       mailx-admin reconcile --dry-run\n")
			fmt.Printf("  2. If dry-run shows no changes, you're in sync:\n")
			fmt.Printf("       mailx-admin reconcile\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without writing")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip confirmation prompt")
	return cmd
}

// Also expose seed as a small programmatic API for auto-seed at first serve.
func autoSeedIfEmpty(ctx context.Context, cfgPath string) error {
	cfg, database, st, err := openAll(cfgPath)
	if err != nil {
		return err
	}
	defer database.Close()

	existing, err := st.Snapshot(ctx)
	if err != nil {
		return err
	}
	if len(existing.Domains) > 0 {
		return nil // already seeded
	}

	found, err := seed.Scan(seed.Options{
		PostfixConfDir:    cfg.Mail.PostfixConfDir,
		DovecotConfDir:    cfg.Mail.DovecotConfDir,
		OpenDKIMDir:       cfg.Mail.OpenDKIMDir,
		PrimaryDomainFile: cfg.Mail.PrimaryDomainFile,
	})
	if err != nil {
		return err
	}

	if len(found.Domains) == 0 {
		// Nothing on disk to adopt either — this is a fresh install path.
		return nil
	}

	fmt.Printf("Auto-seeding %d domain(s), %d user(s), %d alias(es)...\n",
		len(found.Domains), len(found.Users), len(found.Aliases))

	if err := seed.Apply(ctx, st, found); err != nil {
		return fmt.Errorf("auto-seed: %w", err)
	}

	auditor := audit.New(database.DB)
	_ = auditor.Log(ctx, audit.Entry{
		Actor:  "system:auto-seed",
		Action: "seed",
		Result: "ok",
		Detail: map[string]any{
			"domains": len(found.Domains),
			"users":   len(found.Users),
			"aliases": len(found.Aliases),
		},
	})

	return nil
}
