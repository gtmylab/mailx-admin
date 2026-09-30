package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/roundcube"
)

// roundcubeSyncRow is one mailbox's outcome, for the human and the JSON output.
type roundcubeSyncRow struct {
	Email   string `json:"email"`
	Action  string `json:"action"` // created, present, failed, would-create
	UserID  int64  `json:"user_id,omitempty"`
	Outcome string `json:"outcome,omitempty"`
	Error   string `json:"error,omitempty"`
}

// cmdRoundcube is webmail's half of a mailbox.
//
// Roundcube keeps its own `users` and `identities` tables, and it creates both
// on first login — which is why a missing row is not what refuses a login, and
// why this command is not a repair for "webmail says the password is wrong".
// What the rows carry is everything around the login: the default identity (so
// the From: address is the mailbox' own instead of Roundcube's guess), the
// user's language and the preference blob.
//
// The panel writes them when it creates a mailbox. This is the back-fill for
// the mailboxes that already existed — imported by `mailx-admin seed`/`adopt`,
// or created while MySQL was unreachable.
func cmdRoundcube() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roundcube",
		Short: "Keep Roundcube's own database in step with the panel",
	}
	cmd.AddCommand(cmdRoundcubeSync())
	return cmd
}

func cmdRoundcubeSync() *cobra.Command {
	var (
		cfgPath string
		dryRun  bool
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Create the Roundcube account of every mailbox that is missing one",
		Long: `Create the Roundcube account (a users row and its default identity) of every
mailbox the panel renders into Dovecot's passwd-file.

Every address listed by this command can already log in to IMAP and SMTP; what
the Roundcube rows add is the webmail account itself — its own From: address,
its language, its preferences. Roundcube creates them at first login too, so
this is about doing it once, deliberately, instead of once per user, and about
being able to answer "does webmail know about this mailbox?" without guessing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			if !cfg.Roundcube.Enabled {
				return fmt.Errorf(
					"[roundcube] is not enabled in %s, so nothing would be written; "+
						"set `enabled = true` in that section (the installer does) and try again", cfgPath)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			client := roundcube.New(cfg.Roundcube.ToClientConfig())
			rcCfg := client.Config()

			known, err := client.ListUsers(ctx)
			if err != nil {
				return fmt.Errorf("read Roundcube's users from %s: %w", rcCfg.Database, err)
			}
			have := make(map[string]bool, len(known))
			for _, login := range known {
				have[login] = true
			}

			snap, err := st.Snapshot(ctx)
			if err != nil {
				return fmt.Errorf("read the panel's mailboxes: %w", err)
			}

			rows := make([]roundcubeSyncRow, 0, len(snap.Users))
			var created, present, failed int
			for _, u := range snap.Users {
				email := strings.ToLower(u.Email)

				switch {
				case have[email]:
					present++
					rows = append(rows, roundcubeSyncRow{Email: email, Action: "present"})
				case dryRun:
					rows = append(rows, roundcubeSyncRow{Email: email, Action: "would-create"})
				default:
					res, err := client.EnsureUser(ctx, email)
					if err != nil {
						failed++
						rows = append(rows, roundcubeSyncRow{Email: email, Action: "failed", Error: err.Error()})
						continue
					}
					created++
					rows = append(rows, roundcubeSyncRow{
						Email: email, Action: "created", UserID: res.UserID, Outcome: res.String(),
					})
				}
			}

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"database":  rcCfg.Database,
					"mail_host": rcCfg.MailHost,
					"dry_run":   dryRun,
					"created":   created,
					"present":   present,
					"failed":    failed,
					"mailboxes": rows,
				})
			}

			printRoundcubeSync(rcCfg, rows, created, present, failed, dryRun)
			if failed > 0 {
				return fmt.Errorf("%d mailbox(es) could not be written to Roundcube", failed)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be created without writing")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

// printRoundcubeSync reports what happened, and then the one thing an operator
// has to check next: a Roundcube whose `imap_host` (or `default_host`) is not
// the mail_host we just wrote looks up a different row on every login, and the
// account looks like it was never created.
func printRoundcubeSync(cfg roundcube.Config, rows []roundcubeSyncRow, created, present, failed int, dryRun bool) {
	fmt.Printf("roundcube database %s on %s\n\n", cfg.Database, cfg.MailHost)

	for _, r := range rows {
		switch r.Action {
		case "created":
			fmt.Printf("  + %s — %s\n", r.Email, r.Outcome)
		case "would-create":
			fmt.Printf("  would create %s\n", r.Email)
		case "failed":
			fmt.Printf("  ! %s — %s\n", r.Email, r.Error)
		}
	}

	if dryRun {
		fmt.Printf("\n%d to create, %d already present, %d failed (dry run: nothing written)\n",
			len(rows)-present-failed, present, failed)
		return
	}

	fmt.Printf("\n%d created, %d already present, %d failed\n", created, present, failed)
	if created > 0 {
		fmt.Printf("\nCheck that Roundcube's `imap_host` (or `default_host`) is %q, or that\n"+
			"`username_domain` is set to the mail domain: the account is only found on\n"+
			"login if the two agree.\n", cfg.MailHost)
	}
}
