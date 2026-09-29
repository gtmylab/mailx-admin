package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/config"
	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/store"
	"github.com/gtmylab/mailx-admin/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:     "mailx-admin",
		Short:   "MailX Admin — control plane for MailX mail servers",
		Version: version.Full(),
	}

	root.AddCommand(
		cmdMigrate(),
		cmdReconcile(),
		cmdStatus(),
		cmdSeed(),
		cmdAdopt(),
		cmdDoctor(),
		cmdServe(),
		cmdUser(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func openAll(cfgPath string) (*config.Config, *db.DB, *store.Store, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, nil, err
	}

	database, err := db.Open(cfg.DB.ToDriverConfig())
	if err != nil {
		return nil, nil, nil, err
	}

	st := store.New(database)
	return cfg, database, st, nil
}

func cmdMigrate() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply database migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, _, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := database.Migrate(ctx); err != nil {
				return err
			}
			fmt.Println("migrations applied")
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	return cmd
}

func cmdReconcile() *cobra.Command {
	var (
		cfgPath string
		dryRun  bool
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Render and apply daemon configs from DB state",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			snap, err := st.Snapshot(ctx)
			if err != nil {
				return fmt.Errorf("snapshot: %w", err)
			}

			auditor := audit.New(database.DB)
			rec := reconciler.New(reconciler.Config{
				PostfixConfDir: cfg.Mail.PostfixConfDir,
				DovecotConfDir: cfg.Mail.DovecotConfDir,
				OpenDKIMDir:    cfg.Mail.OpenDKIMDir,
				Hostname:       cfg.Server.Hostname,
				DryRun:         dryRun,
			}, auditor)

			res, err := rec.Reconcile(ctx, snap)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			printResult(res, dryRun)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change without applying")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return cmd
}

func printResult(res *reconciler.Result, dryRun bool) {
	mode := "APPLY"
	if dryRun {
		mode = "DRY-RUN"
	}
	fmt.Printf("=== reconcile %s ===\n\n", mode)

	var created, updated, unchanged int
	for _, c := range res.Changes {
		switch c.Action {
		case "create":
			created++
			fmt.Printf("  + %s\n", c.Path)
		case "update":
			updated++
			fmt.Printf("  ~ %s\n", c.Path)
		case "unchanged":
			unchanged++
		}
	}

	fmt.Printf("\n%d created, %d updated, %d unchanged\n",
		created, updated, unchanged)

	if len(res.ReloadedSvcs) > 0 {
		fmt.Printf("reloaded: %v\n", res.ReloadedSvcs)
	}

	fmt.Printf("took %s\n", res.FinishedAt.Sub(res.StartedAt).Round(time.Millisecond))
}

func cmdStatus() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show current DB state summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			ctx := context.Background()
			snap, err := st.Snapshot(ctx)
			if err != nil {
				return err
			}

			fmt.Printf("version: %s\n", version.Full())
			fmt.Printf("driver:  %s\n", database.Driver())
			fmt.Printf("domains: %d\n", len(snap.Domains))
			fmt.Printf("users:   %d\n", len(snap.Users))
			fmt.Printf("aliases: %d\n", len(snap.Aliases))
			if p := snap.PrimaryDomain(); p != nil {
				fmt.Printf("primary: %s\n", p.Name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	return cmd
}
