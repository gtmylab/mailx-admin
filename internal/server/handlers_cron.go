package server

import (
	"context"
	"net/http"
	"os"
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
	s.renderPartial(w, "cron_form", map[string]any{"Job": models.CronJob{Enabled: true}})
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
	s.renderPartial(w, "cron_form", map[string]any{"Job": job})
}

// handleCronSave creates or updates a job. A hidden id field decides which:
// empty = create, numeric = update.
func (s *Server) handleCronSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	schedule := strings.TrimSpace(r.FormValue("schedule"))
	command := strings.TrimSpace(r.FormValue("command"))
	enabled := r.FormValue("enabled") == "on"

	if name == "" {
		s.renderFormError(w, "Name is required")
		return
	}
	if err := cron.Validate(schedule); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	if command == "" {
		s.renderFormError(w, "Command is required")
		return
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
		if err := s.store.UpdateCronJob(ctx, models.CronJob{
			ID: id, Name: name, Schedule: schedule, Command: command, Enabled: enabled,
		}); err != nil {
			s.renderFormError(w, err.Error())
			return
		}
		action = "cron.update"
	} else {
		if _, err := s.store.InsertCronJob(ctx, models.CronJob{
			Name: name, Schedule: schedule, Command: command, Enabled: enabled,
		}); err != nil {
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
		TargetID: name, Result: "ok", RemoteIP: clientIP(r),
	})
	w.Header().Set("HX-Redirect", "/system/cron?flash="+encodeFlash("Saved \""+name+"\""))
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
		out, err := cron.RunCommand(ctx, job.Command)
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
