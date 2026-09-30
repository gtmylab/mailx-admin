package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/config"
	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/mutations"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/seed"
	"github.com/gtmylab/mailx-admin/internal/store"
)

// cmdMailbox is the panel's write path from a shell.
//
// It exists because "create a mailbox on this server" used to have two
// implementations that disagreed. The panel wrote a row and rendered the configs
// from it; the installer's "Add MailX User" ran useradd, appended a line to
// /etc/postfix/virtual and told the panel nothing. The mailbox then did not
// appear in the UI, and the next sync — which rewrites that file from the
// database — deleted the appended line.
//
// This command does the whole job in one place: the database row, the rendered
// configuration, the maildir, the reload. The installer calls it, an operator can
// call it, and both end up with a mailbox the panel can see and manage.
func cmdMailbox() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mailbox",
		Short: "Create, list and remove mailboxes",
		Long: `Manage mailboxes through the same path the panel uses.

A mailbox created here is in the panel's database, in Dovecot's passwd-file, in
Postfix's lookup maps and on disk, so it shows up in the UI immediately and the
next configuration sync keeps it.`,
	}
	cmd.AddCommand(cmdMailboxAdd(), cmdMailboxList(), cmdMailboxRemove())
	return cmd
}

func cmdMailboxAdd() *cobra.Command {
	var (
		cfgPath    string
		quotaMB    int
		password   string
		fromStdin  bool
		kind       string
		passwdFile string
		shadowFile string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "add <local>@<domain>",
		Short: "Create a mailbox and apply it to the mail server",
		Long: `Create one mailbox and apply the change to Postfix, Dovecot and the disk.

--kind virtual (the default) is the panel's own mailbox: the mail lives in
/var/mail/vhosts/<domain>/<local>, owned by the vmail account, and the mailbox
directory is created for you.

--kind system records a mailbox that belongs to an existing Unix account (the
one "Add MailX User" creates, or a plain ` + "`useradd -m`" + `). Its uid, gid and home
are read from /etc/passwd, and unless you set a password the account's own
password from /etc/shadow is reused, so nothing about the account changes: the
panel simply stops ignoring it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			local, domain, ok := strings.Cut(strings.ToLower(strings.TrimSpace(args[0])), "@")
			if !ok || local == "" || domain == "" {
				return fmt.Errorf("expected an address like alice@example.com, got %q", args[0])
			}
			if kind != models.KindVirtual && kind != models.KindSystem {
				return fmt.Errorf("unknown --kind %q (want %q or %q)",
					kind, models.KindVirtual, models.KindSystem)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			domainID, err := lookupDomainID(ctx, database.DB, domain)
			if err != nil {
				return err
			}

			in := mutations.CreateUserInput{
				DomainID: domainID,
				Username: local,
				QuotaMB:  quotaMB,
				Kind:     kind,
			}

			// A system mailbox is only ever *recorded*: the account has to
			// exist, and its uid/gid/home come from the server, not from the
			// panel.
			var sysAcct *seed.SystemAccount
			if kind == models.KindSystem {
				sysAcct, err = seed.LookupSystemAccount(seed.Options{
					PasswdFile: passwdFile,
					ShadowFile: shadowFile,
				}, local)
				if err != nil {
					return err
				}
				if sysAcct == nil {
					return fmt.Errorf("no Unix account named %q on this server; create it first "+
						"(useradd -m %s) or use --kind virtual", local, local)
				}
				in.SysUID, in.SysGID, in.Home = sysAcct.UID, sysAcct.GID, sysAcct.Home
			}

			switch {
			case password != "" && fromStdin:
				return fmt.Errorf("use either --password or --password-stdin, not both")
			case fromStdin:
				pw, err := readPasswordLine()
				if err != nil {
					return err
				}
				in.Password = pw
			case password != "":
				in.Password = password
			case sysAcct != nil:
				// No new password: keep the one the account already has. This
				// is the point of adopting a system mailbox — the Unix login,
				// SSH and the panel all keep agreeing.
				if sysAcct.PasswordHash == "" {
					return fmt.Errorf("account %q has no usable password in %s; "+
						"pass --password-stdin to set one in the panel instead",
						local, shadowPathOf(shadowFile))
				}
				in.PasswordHash = sysAcct.PasswordHash
			default:
				return fmt.Errorf("a password is required: pass --password-stdin (recommended) or --password")
			}

			res, email, err := applyUserMutation(ctx, cfg, database, st, in)
			if err != nil {
				return err
			}
			return printMailboxAdded(email, in, res, jsonOut)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().IntVar(&quotaMB, "quota", 1024, "mailbox quota in MB")
	cmd.Flags().StringVar(&password, "password", "", "password (prefer --password-stdin: it keeps it out of the process list)")
	cmd.Flags().BoolVar(&fromStdin, "password-stdin", false, "read the password from standard input")
	cmd.Flags().StringVar(&kind, "kind", models.KindVirtual, "mailbox kind: virtual or system")
	cmd.Flags().StringVar(&passwdFile, "passwd-file", "", "account database to read for --kind system (default /etc/passwd)")
	cmd.Flags().StringVar(&shadowFile, "shadow-file", "", "password database for --kind system (default /etc/shadow)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

// applyUserMutation writes the user through the same service the panel uses.
//
// The queue is nil on purpose: Apply then reconciles inline, so when this command
// returns the passwd-file, the Postfix maps and the maildir are already written
// and the daemons reloaded. A CLI that returns before the change is applied is
// how "I added the user but mail still bounces" gets reported.
func applyUserMutation(ctx context.Context, cfg *config.Config, database *db.DB, st *store.Store, in mutations.CreateUserInput) (*mutations.Result, string, error) {
	auditor := audit.New(database.DB)
	rec := reconciler.New(reconciler.Config{
		PostfixConfDir: cfg.Mail.PostfixConfDir,
		DovecotConfDir: cfg.Mail.DovecotConfDir,
		OpenDKIMDir:    cfg.Mail.OpenDKIMDir,
		Hostname:       cfg.Server.Hostname,
	}, auditor)

	svc := mutations.New(database.DB, st, rec, auditor, cfg.Server.Hostname, nil)
	return svc.CreateUser(ctx, mutations.Actor{Name: "cli:mailbox"}, in)
}

func printMailboxAdded(email string, in mutations.CreateUserInput, res *mutations.Result, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"email":    email,
			"kind":     in.Kind,
			"quota_mb": in.QuotaMB,
			"uid":      in.SysUID,
			"gid":      in.SysGID,
			"home":     in.Home,
			"changes":  res.Changes,
			"maildirs": res.Maildirs,
			"reloaded": res.ReloadedSvcs,
			"warnings": res.Warnings,
		})
	}

	fmt.Printf("Mailbox %s created (%s)\n", email, describeKind(in))
	for _, c := range res.Changes {
		if c.Action != "unchanged" {
			fmt.Printf("  %s %s\n", c.Action, c.Path)
		}
	}
	for _, d := range res.Maildirs {
		fmt.Printf("  created %s\n", d)
	}
	if len(res.ReloadedSvcs) > 0 {
		fmt.Printf("reloaded: %s\n", strings.Join(res.ReloadedSvcs, ", "))
	}
	for _, w := range res.Warnings {
		fmt.Printf("warning: %s\n", w)
	}
	return nil
}

// describeKind says where the mail will live, which is the one thing that really
// differs between the two kinds and the first thing to check when delivery fails.
func describeKind(in mutations.CreateUserInput) string {
	if in.Kind == models.KindSystem {
		return fmt.Sprintf("system mailbox, uid %d, %s/Maildir", in.SysUID, in.Home)
	}
	return fmt.Sprintf("virtual mailbox, quota %d MB", in.QuotaMB)
}

func cmdMailboxList() *cobra.Command {
	var (
		cfgPath string
		all     bool
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the mailboxes the panel knows about",
		Long: `List mailboxes with the shape the panel renders them in.

Use it to answer "is the mailbox the installer created actually in the panel?" —
if it is missing here, the next sync will not have it either; import it with
` + "`mailx-admin adopt`" + ` or create it with ` + "`mailbox add`" + `.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			users, err := st.Users(ctx, all)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(users)
			}

			fmt.Printf("%-32s %-8s %-9s %-26s %s\n", "EMAIL", "KIND", "UID:GID", "HOME", "QUOTA")
			for _, u := range users {
				fmt.Printf("%-32s %-8s %-9s %-26s %d MB\n",
					u.Email, u.MailboxKind(),
					fmt.Sprintf("%d:%d", u.DeliveryUID(), u.DeliveryGID()),
					u.MailHome(), u.QuotaMB)
			}
			fmt.Printf("\n%d mailbox(es)\n", len(users))
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().BoolVar(&all, "all", true, "include mailboxes that are disabled in the panel")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

// shadowPathOf reports which password database was consulted, so the error names
// the file the operator has to look at.
func shadowPathOf(path string) string {
	if path == "" {
		return "/etc/shadow"
	}
	return path
}

func cmdMailboxRemove() *cobra.Command {
	var (
		cfgPath string
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "remove <local>@<domain>",
		Short: "Remove a mailbox from the panel",
		Long: `Remove one mailbox and apply the change.

The mailbox directories are left on disk, deliberately: this stops the address
from receiving mail, it does not destroy anybody's mail. A system mailbox's Unix
account is left alone too — deleting an account is not something the panel should
do to a login that sshd also uses. Delete either by hand once the mail is no
longer needed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			email := strings.ToLower(strings.TrimSpace(args[0]))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			var (
				userID int64
				kind   string
				home   string
				domain string
			)
			err = database.DB.QueryRowContext(ctx, `
                SELECT u.id, u.kind, COALESCE(u.home, ''), d.name
                FROM users u JOIN domains d ON d.id = u.domain_id
                WHERE u.email = ?`, email).Scan(&userID, &kind, &home, &domain)
			if err == sql.ErrNoRows {
				return fmt.Errorf("no mailbox with the address %s in the panel", email)
			}
			if err != nil {
				return err
			}

			if !yes && !confirm(fmt.Sprintf("Remove %s from the panel? [y/N]: ", email)) {
				fmt.Println("Aborted.")
				return nil
			}

			auditor := audit.New(database.DB)
			rec := reconciler.New(reconciler.Config{
				PostfixConfDir: cfg.Mail.PostfixConfDir,
				DovecotConfDir: cfg.Mail.DovecotConfDir,
				OpenDKIMDir:    cfg.Mail.OpenDKIMDir,
				Hostname:       cfg.Server.Hostname,
			}, auditor)
			svc := mutations.New(database.DB, st, rec, auditor, cfg.Server.Hostname, nil)

			res, err := svc.DeleteUser(ctx, mutations.Actor{Name: "cli:mailbox"}, userID)
			if err != nil {
				return err
			}

			fmt.Printf("Mailbox %s removed\n", email)
			for _, c := range res.Changes {
				if c.Action != "unchanged" {
					fmt.Printf("  %s %s\n", c.Action, c.Path)
				}
			}
			if kind == models.KindSystem {
				fmt.Printf("the Unix account %s and its mail were left in place\n", email)
			} else {
				fmt.Printf("the mail in %s/Maildir was left in place\n", defaultHome(email, domain, home))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return cmd
}

// defaultHome works out where a virtual mailbox's mail is when the row does not
// carry a home (it never does for a virtual mailbox: the path is derived).
func defaultHome(email, domain, home string) string {
	if home != "" {
		return home
	}
	local, _, _ := strings.Cut(email, "@")
	return fmt.Sprintf("%s/%s/%s", models.VmailBase, domain, local)
}

// lookupDomainID turns a domain name into its id, and says what is available when
// it does not.
func lookupDomainID(ctx context.Context, database *sql.DB, name string) (int64, error) {
	var id int64
	err := database.QueryRowContext(ctx, `SELECT id FROM domains WHERE name = ? AND active = 1`, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}

	rows, err := database.QueryContext(ctx, `SELECT name FROM domains WHERE active = 1 ORDER BY name`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var known []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return 0, err
		}
		known = append(known, n)
	}
	if len(known) == 0 {
		return 0, fmt.Errorf("the panel has no domains yet; add one in the panel first")
	}
	return 0, fmt.Errorf("the panel has no domain %s; it knows: %s", name, strings.Join(known, ", "))
}

// readPasswordLine reads one line from stdin. The password never appears in the
// process list, which is why --password-stdin is the documented way in.
func readPasswordLine() (string, error) {
	fmt.Fprint(os.Stderr, "Password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
