package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/seed"
)

// cmdAdopt imports what exists on the server but not in the panel.
//
// `seed` is the one-time adoption of a fresh install and refuses to run once the
// database has domains. `adopt` is its idempotent counterpart: it is the answer
// to "this mailbox was created with useradd and the panel never shows it", and
// it is safe to run again after every shell-side change.
func cmdAdopt() *cobra.Command {
	var (
		cfgPath string
		dryRun  bool
		yes     bool
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "adopt",
		Short: "Import domains, mailboxes and aliases that exist on the server but not in the panel",
		Long: `Scan this server's Postfix, Dovecot and OpenDKIM configuration and add every
domain, mailbox and alias the panel does not know about yet.

Nothing is deleted, and anything already imported is skipped, so this can be run
after every shell-side change. Use --dry-run to see the plan first.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			found, err := seed.Scan(seed.Options{
				PostfixConfDir:    cfg.Mail.PostfixConfDir,
				DovecotConfDir:    cfg.Mail.DovecotConfDir,
				OpenDKIMDir:       cfg.Mail.OpenDKIMDir,
				PrimaryDomainFile: cfg.Mail.PrimaryDomainFile,
			})
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			plan, err := seed.Plan(ctx, st, found)
			if err != nil {
				return fmt.Errorf("plan: %w", err)
			}

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(plan); err != nil {
					return err
				}
			} else {
				printPlan(plan, dryRun)
			}

			if dryRun {
				return nil
			}
			if plan.Empty() {
				fmt.Println("Nothing to import: the panel already knows every entry on this server.")
				return nil
			}
			if !yes && !confirm(fmt.Sprintf("Import %d entr%s into the panel? [y/N]: ", plan.Total(), pluralSuffix(plan.Total()))) {
				fmt.Println("Aborted.")
				return nil
			}

			adopted, err := seed.Adopt(ctx, st, found)
			if err != nil {
				return fmt.Errorf("adopt: %w", err)
			}

			_ = audit.New(database.DB).Log(ctx, audit.Entry{
				Actor:  "cli:adopt",
				Action: "sync.adopt",
				Result: "ok",
				Detail: map[string]any{
					"domains": len(adopted.Domains),
					"users":   len(adopted.Users),
					"aliases": len(adopted.Aliases),
					"skipped": len(adopted.Skipped),
				},
			})

			fmt.Printf("\nImported %d entr%s. Next steps:\n", adopted.Total(), pluralSuffix(adopted.Total()))
			fmt.Println("  1. Render and apply the configuration:")
			fmt.Println("       mailx-admin reconcile")
			fmt.Println("  2. Confirm the panel, the files and the daemons agree:")
			fmt.Println("       mailx-admin doctor")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be imported without writing")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output the plan as JSON")
	return cmd
}

func printPlan(plan *seed.ImportPlan, dryRun bool) {
	header := "Import plan"
	if dryRun {
		header = "Import plan (dry run — nothing will be written)"
	}
	fmt.Printf("=== %s ===\n\n", header)

	for _, group := range []struct {
		label string
		items []seed.ImportItem
	}{
		{"Domains", plan.Domains},
		{"Mailboxes", plan.Users},
		{"Aliases", plan.Aliases},
	} {
		fmt.Printf("%s (%d):\n", group.label, len(group.items))
		for _, item := range group.items {
			fmt.Printf("  + %-40s %s\n", item.Key, item.Detail)
		}
		if len(group.items) == 0 {
			fmt.Println("  (none)")
		}
		fmt.Println()
	}

	if len(plan.Skipped) > 0 {
		fmt.Printf("Skipped (%d):\n", len(plan.Skipped))
		for _, item := range plan.Skipped {
			fmt.Printf("  - %-40s %s\n", item.Key, item.Detail)
		}
		fmt.Println()
	}

	fmt.Printf("total: %d entr%s to import\n", plan.Total(), pluralSuffix(plan.Total()))
}

func confirm(prompt string) bool {
	fmt.Print(prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func pluralSuffix(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
