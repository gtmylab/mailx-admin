package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/config"
	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/jobs"
	"github.com/gtmylab/mailx-admin/internal/logs"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/server"
	"github.com/gtmylab/mailx-admin/internal/store"
	"github.com/gtmylab/mailx-admin/internal/version"
	"github.com/gtmylab/mailx-admin/internal/webhooks"
)

func cmdServe() *cobra.Command {
	var (
		cfgPath     string
		autoSeed    bool
		requireSeed bool
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the admin HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}

			database, err := db.Open(cfg.DB.ToDriverConfig())
			if err != nil {
				return err
			}
			defer database.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Signal handling
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				logger.Info("shutdown signal received")
				cancel()
			}()

			// Migrations first — always safe, idempotent
			if err := database.Migrate(ctx); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}

			st := store.New(database)

			rec := reconciler.New(reconciler.Config{
				PostfixConfDir: cfg.Mail.PostfixConfDir,
				DovecotConfDir: cfg.Mail.DovecotConfDir,
				OpenDKIMDir:    cfg.Mail.OpenDKIMDir,
				Hostname:       cfg.Server.Hostname,
				PasswdScheme:   cfg.Mail.PasswdScheme,
			}, audit.New(database.DB))

			srv, err := server.New(cfg, database.DB, st, rec, logger)
			if err != nil {
				return err
			}
			// Start log ingester in background
			logPath := cfg.Logs.MailLogPath
			if logPath == "" {
				logPath = "/var/log/mail.log"
			}
			ing := logs.NewIngester(database.DB, logger, logPath)
			go func() {
				if err := ing.Run(ctx); err != nil {
					logger.Warn("log ingester stopped", "err", err)
				}
			}()

			// Daily prune (30-day retention)
			go func() {
				ticker := time.NewTicker(6 * time.Hour)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if n, err := ing.PruneOld(ctx, 30*24*time.Hour); err != nil {
							logger.Warn("prune failed", "err", err)
						} else if n > 0 {
							logger.Info("pruned old events", "count", n)
						}
					}
				}
			}()

			// Scheduled monitoring jobs: hourly blocklist check, nightly quota
			// sample, daily PTR + outbound-IP discovery.
			jm := jobs.New(st, cfg.DNS.Resolver, logger)
			jm.SetWebhooks(webhooks.New(st, logger))
			jm.Start(ctx)

			// ---- Seed gate ----
			snap, err := st.Snapshot(ctx)
			if err != nil {
				return err
			}

			if len(snap.Domains) == 0 {
				if autoSeed {
					logger.Info("no domains in DB; attempting auto-seed")
					if err := autoSeedIfEmpty(ctx, cfgPath); err != nil {
						logger.Error("auto-seed failed", "err", err)
						if requireSeed {
							return fmt.Errorf("auto-seed failed and --require-seed is set: %w", err)
						}
					}
				} else if requireSeed {
					return fmt.Errorf(
						"no domains in DB and --auto-seed not set. " +
							"Run 'mailx-admin seed' first, or start with --auto-seed",
					)
				} else {
					logger.Warn("no domains in DB; panel will show an empty state. " +
						"Run 'mailx-admin seed' to adopt existing server state.")
				}
			}

			// ---- Start server ----
			logger.Info("starting MailX Admin",
				"version", versionString(),
				"listen", cfg.Server.ListenAddr,
			)

			return srv.Serve(ctx)
		},
	}

	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	cmd.Flags().BoolVar(&autoSeed, "auto-seed", false, "auto-adopt existing server state on empty DB")
	cmd.Flags().BoolVar(&requireSeed, "require-seed", false, "refuse to start if DB is empty")
	return cmd
}

// versionString is the full build string — version, commit, build date and
// platform — logged at startup, so "journalctl -u mailx-admin" on a Linux host
// identifies exactly which release the service is running.
func versionString() string { return version.Full() }
