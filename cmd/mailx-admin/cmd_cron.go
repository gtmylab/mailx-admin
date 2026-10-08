package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/gtmylab/mailx-admin/internal/cron"
)

// cmdCron groups the scheduled-job subcommands. `cron run` is invoked by the
// system cron daemon (see the rendered /etc/cron.d/mailx-admin) to execute one
// job and record the result for the panel's Scheduled tasks page.
func cmdCron() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cron",
		Short: "Manage scheduled jobs",
	}
	cmd.AddCommand(cmdCronRun())
	return cmd
}

func cmdCronRun() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "run <id>",
		Short: "Run a scheduled job and record its result",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid job id %q", args[0])
			}
			_, database, st, err := openAll(cfgPath)
			if err != nil {
				return err
			}
			defer database.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			job, err := st.GetCronJob(ctx, id)
			if err != nil {
				return err
			}
			if job == nil {
				return fmt.Errorf("cron job %d not found", id)
			}

			_ = st.MarkCronRun(ctx, id, "running", "")
			out, err := cron.RunCommand(ctx, job.Command)
			status := "ok"
			if err != nil {
				status = "error"
			}
			if recErr := st.MarkCronRun(ctx, id, status, out); recErr != nil {
				return recErr
			}
			return err
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "/etc/mailx/admin.toml", "config file path")
	return cmd
}
