// Package cron renders user-defined scheduled jobs into /etc/cron.d and runs
// their commands. Jobs live in the database (cron_jobs) and are executed by the
// system cron daemon through `mailx-admin cron run <id>`, which records the
// result back to the panel's Scheduled tasks page.
package cron

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// CronDPath is the file the panel writes enabled jobs to. The system cron
// daemon reads it automatically on Debian/Ubuntu.
const CronDPath = "/etc/cron.d/mailx-admin"

// RenderFile renders the cron.d content for the enabled jobs. Each line invokes
// the panel binary's `cron run` subcommand so the run is recorded, with output
// discarded to avoid cron mailing the operator.
func RenderFile(jobs []models.CronJob, bin, configPath string) string {
	var b strings.Builder
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n")
	b.WriteString("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")
	b.WriteString("SHELL=/bin/sh\n\n")
	for _, j := range jobs {
		if !j.Enabled {
			continue
		}
		fmt.Fprintf(&b, "%s root %s cron run --config %s %d >/dev/null 2>&1\n",
			j.Schedule, bin, configPath, j.ID)
	}
	return b.String()
}

// Validate checks a 5-field cron expression loosely: five whitespace-separated
// fields whose characters are all legal cron tokens. It does not reject
// well-formed-but-out-of-range expressions (e.g. minute 99) — the cron daemon
// reports those.
func Validate(expr string) error {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("schedule must be 5 fields (minute hour day-of-month month day-of-week), got %d", len(fields))
	}
	for i, f := range fields {
		if f == "" {
			return fmt.Errorf("schedule field %d is empty", i+1)
		}
		for _, r := range f {
			switch {
			case r == '*', r == '-', r == '/', r == ',':
			case r >= '0' && r <= '9':
			default:
				return fmt.Errorf("invalid character %q in schedule field %d", r, i+1)
			}
		}
	}
	return nil
}

// RunCommand runs a job's command in a shell (optionally as runAs, via runuser)
// and returns its combined output. input is fed to the command's stdin.
func RunCommand(ctx context.Context, runAs, command, input string) (string, error) {
	run := func(name string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if runAs == "" || runAs == "root" {
		return run("sh", "-c", command)
	}
	return run("runuser", "-u", runAs, "--", "sh", "-c", command)
}

// WithinDateRange reports whether now falls inside a job's optional annual
// month/day window. mode must be "range" for the window to apply; startMonth and
// endMonth are 1-12, startDate/endDate are "YYYY-MM-DD" (the day is used, the
// year is ignored) or a bare day-of-month. A window that wraps the year boundary
// (e.g. November to February) is handled correctly.
func WithinDateRange(now time.Time, mode, startMonth, startDate, endMonth, endDate string) bool {
	if mode != "range" {
		return true
	}
	sm := monthOf(startMonth)
	em := monthOf(endMonth)
	if sm < 1 || em < 1 {
		return true
	}
	cur := int(now.Month())*100 + now.Day()
	start := sm*100 + dayOf(startDate, 1)
	end := em*100 + dayOf(endDate, 31)
	if start <= end {
		return cur >= start && cur <= end
	}
	return cur >= start || cur <= end
}

func monthOf(v string) int {
	m, _ := strconv.Atoi(strings.TrimSpace(v))
	return m
}

func dayOf(date string, def int) int {
	date = strings.TrimSpace(date)
	if date == "" {
		return def
	}
	if t, err := time.Parse("2006-01-02", date); err == nil {
		return t.Day()
	}
	if d, err := strconv.Atoi(date); err == nil && d >= 1 && d <= 31 {
		return d
	}
	return def
}
