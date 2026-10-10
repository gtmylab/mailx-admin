package server

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/cron"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// cronRunBudget bounds a "run now" execution. Long jobs are run in a background
// goroutine, so the budget only caps the command itself, never the request.
const cronRunBudget = 10 * time.Minute

// cronOption is one labelled entry in a month/weekday picker.
type cronOption struct {
	Value string
	Label string
}

// cronFormData carries the static lists the cron form renders.
type cronFormData struct {
	Users        []string
	CronMinutes  []string
	CronHours    []string
	CronDays     []string
	CronMonths   []cronOption
	CronWeekdays []cronOption
	Months       []cronOption
}

var cronMonths = []cronOption{
	{"1", "January"}, {"2", "February"}, {"3", "March"}, {"4", "April"},
	{"5", "May"}, {"6", "June"}, {"7", "July"}, {"8", "August"},
	{"9", "September"}, {"10", "October"}, {"11", "November"}, {"12", "December"},
}

var cronWeekdays = []cronOption{
	{"0", "Sunday"}, {"1", "Monday"}, {"2", "Tuesday"}, {"3", "Wednesday"},
	{"4", "Thursday"}, {"5", "Friday"}, {"6", "Saturday"},
}

// cronFormDataFor builds the static lists the cron form's pickers render.
func cronFormDataFor() cronFormData {
	var minutes, hours, days []string
	for i := 0; i < 60; i++ {
		minutes = append(minutes, fmt.Sprintf("%02d", i))
	}
	for i := 0; i < 24; i++ {
		hours = append(hours, fmt.Sprintf("%02d", i))
	}
	for i := 1; i <= 31; i++ {
		days = append(days, fmt.Sprintf("%02d", i))
	}
	return cronFormData{
		Users:        listSystemUsers(),
		CronMinutes:  minutes,
		CronHours:    hours,
		CronDays:     days,
		CronMonths:   cronMonths,
		CronWeekdays: cronWeekdays,
		Months:       cronMonths,
	}
}

// listSystemUsers returns the accounts a job may run as: root plus every
// non-system user (uid >= 1000).
func listSystemUsers() []string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return []string{"root"}
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 3 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		if uid == 0 || uid >= 1000 {
			out = append(out, parts[0])
		}
	}
	if len(out) == 0 {
		return []string{"root"}
	}
	sort.Strings(out)
	return out
}

// cronJobName derives a display name from the command's first token.
func cronJobName(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "cron job"
	}
	name := fields[0]
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = "cron job"
	}
	return name
}

func simpleScheduleExpr(s string) string {
	switch s {
	case "hourly":
		return "0 * * * *"
	case "daily":
		return "0 0 * * *"
	case "weekly":
		return "0 0 * * 0"
	case "monthly":
		return "0 0 1 * *"
	case "yearly":
		return "0 0 1 1 *"
	default:
		return "0 * * * *"
	}
}

func cronField(mode string, selected []string) string {
	if mode != "selected" || len(selected) == 0 {
		return "*"
	}
	return strings.Join(selected, ",")
}

func cronSet(values []string) models.CronValueSet {
	s := models.CronValueSet{}
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			s[v] = true
		}
	}
	return s
}

func (s *Server) handleCronPage(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.store.ListCronJobs(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load scheduled jobs: "+err.Error())
		return
	}
	s.render(w, 200, "cron.html", s.newPageData(w, r, "Scheduled tasks", "cron", map[string]any{
		"Jobs": jobs,
	}))
}

func (s *Server) handleCronNew(w http.ResponseWriter, r *http.Request) {
	s.renderCronForm(w, r, models.CronJob{Enabled: true, ScheduleMode: "simple", RunAs: "root"})
}

func (s *Server) handleCronEdit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid job ID")
		return
	}
	job, err := s.store.GetCronJob(r.Context(), id)
	if err != nil {
		s.renderError(w, 500, err.Error())
		return
	}
	if job == nil {
		s.renderError(w, 404, "Job not found")
		return
	}
	s.renderCronForm(w, r, *job)
}

// renderCronForm renders the full-page cron form (new or edit).
func (s *Server) renderCronForm(w http.ResponseWriter, r *http.Request, job models.CronJob) {
	fd := cronFormDataFor()
	s.render(w, 200, "cron_form.html", s.newPageData(w, r, "Scheduled tasks", "cron", map[string]any{
		"Job":          job,
		"Users":        fd.Users,
		"CronMinutes":  fd.CronMinutes,
		"CronHours":    fd.CronHours,
		"CronDays":     fd.CronDays,
		"CronMonths":   fd.CronMonths,
		"CronWeekdays": fd.CronWeekdays,
		"Months":       fd.Months,
	}))
}

// handleCronSave creates or updates a job from the rich form. A hidden id field
// decides which: empty = create, numeric = update.
func (s *Server) handleCronSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	command := strings.TrimSpace(r.FormValue("command"))
	runAs := strings.TrimSpace(r.FormValue("run_as"))
	if command == "" {
		s.renderFormError(w, "Command is required")
		return
	}
	if runAs == "" {
		runAs = "root"
	}

	scheduleMode := r.FormValue("schedule_mode")
	if scheduleMode == "" {
		scheduleMode = "simple"
	}
	simpleSchedule := r.FormValue("simple_schedule")

	var schedule string
	if scheduleMode == "simple" {
		schedule = simpleScheduleExpr(simpleSchedule)
	} else {
		if manual := strings.TrimSpace(r.FormValue("schedule")); manual != "" {
			schedule = manual
		} else {
			schedule = strings.Join([]string{
				cronField(r.FormValue("minutes_mode"), r.Form["minutes"]),
				cronField(r.FormValue("hours_mode"), r.Form["hours"]),
				cronField(r.FormValue("days_mode"), r.Form["days"]),
				cronField(r.FormValue("months_mode"), r.Form["months"]),
				cronField(r.FormValue("weekdays_mode"), r.Form["weekdays"]),
			}, " ")
		}
	}
	if err := cron.Validate(schedule); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	job := models.CronJob{
		Name:           cronJobName(command),
		Schedule:       schedule,
		Command:        command,
		RunAs:          runAs,
		Input:          r.FormValue("input"),
		Description:    r.FormValue("description"),
		Enabled:        r.FormValue("enabled") == "1",
		SimpleSchedule: simpleSchedule,
		ScheduleMode:   scheduleMode,
		Minutes:        cronSet(r.Form["minutes"]),
		Hours:          cronSet(r.Form["hours"]),
		Days:           cronSet(r.Form["days"]),
		Months:         cronSet(r.Form["months"]),
		Weekdays:       cronSet(r.Form["weekdays"]),
		DateRangeMode:  r.FormValue("date_range_mode"),
		StartMonth:     r.FormValue("start_month"),
		StartDate:      r.FormValue("start_date"),
		EndMonth:       r.FormValue("end_month"),
		EndDate:        r.FormValue("end_date"),
	}

	ctx := r.Context()
	session := auth.SessionFromContext(ctx)
	action := "cron.create"
	if idStr := r.FormValue("id"); idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.renderFormError(w, "Invalid job ID")
			return
		}
		job.ID = id
		if err := s.store.UpdateCronJob(ctx, job); err != nil {
			s.renderFormError(w, err.Error())
			return
		}
		action = "cron.update"
	} else {
		if _, err := s.store.InsertCronJob(ctx, job); err != nil {
			s.renderFormError(w, err.Error())
			return
		}
	}

	if err := s.writeCronFile(ctx); err != nil {
		s.renderFormError(w, "Saved, but failed to update cron.d: "+err.Error())
		return
	}

	_ = s.auditor.Log(ctx, audit.Entry{
		Actor: "admin:" + session.Username, Action: action, TargetType: "cron",
		TargetID: job.Name, Result: "ok", RemoteIP: clientIP(r),
	})
	w.Header().Set("HX-Redirect", "/system/cron?flash="+encodeFlash("Saved \""+job.Name+"\""))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCronToggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid job ID")
		return
	}
	job, err := s.store.GetCronJob(r.Context(), id)
	if err != nil || job == nil {
		s.renderError(w, 404, "Job not found")
		return
	}
	if err := s.store.SetCronJobEnabled(r.Context(), id, !job.Enabled); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	if err := s.writeCronFile(r.Context()); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/system/cron")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCronDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid job ID")
		return
	}
	if err := s.store.DeleteCronJob(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	if err := s.writeCronFile(r.Context()); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/system/cron?flash="+encodeFlash("Job removed"))
	w.WriteHeader(http.StatusOK)
}

// handleCronRun runs a job now, in the background so the request is never held
// open by a long-running command.
func (s *Server) handleCronRun(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid job ID")
		return
	}
	job, err := s.store.GetCronJob(r.Context(), id)
	if err != nil || job == nil {
		s.renderError(w, 404, "Job not found")
		return
	}
	_ = s.store.MarkCronRun(r.Context(), id, "running", "")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), cronRunBudget)
		defer cancel()
		out, err := cron.RunCommand(ctx, job.RunAs, job.Command, job.Input)
		status := "ok"
		if err != nil {
			status = "error"
		}
		_ = s.store.MarkCronRun(context.Background(), id, status, out)
		s.logger.Info("cron job run finished", "id", id, "status", status)
	}()
	w.Header().Set("HX-Redirect", "/system/cron?flash="+encodeFlash("Started \""+job.Name+"\""))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCronLog(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid job ID")
		return
	}
	job, err := s.store.GetCronJob(r.Context(), id)
	if err != nil || job == nil {
		s.renderError(w, 404, "Job not found")
		return
	}
	s.renderPartial(w, "cron_log", map[string]any{"Job": job})
}

// writeCronFile renders the enabled jobs into /etc/cron.d/mailx-admin.
func (s *Server) writeCronFile(ctx context.Context) error {
	jobs, err := s.store.ListCronJobs(ctx)
	if err != nil {
		return err
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	return os.WriteFile(cron.CronDPath, []byte(cron.RenderFile(jobs, bin, s.configPath)), 0o644)
}
