package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/execx"
	"github.com/gtmylab/mailx-admin/internal/store"
	"github.com/gtmylab/mailx-admin/internal/update"
	"github.com/gtmylab/mailx-admin/internal/version"
)

// updateResult is what the apply fragment renders: a success message or an error.
type updateResult struct {
	Message string
	Error   string
}

func (s *Server) handleUpdatesPage(w http.ResponseWriter, r *http.Request) {
	var history []store.UpdateCheck
	if s.store != nil {
		history, _ = s.store.ListUpdateChecks(r.Context(), 10)
	}
	s.render(w, 200, "updates.html", s.newPageData(w, r, "Updates", "updates", map[string]any{
		"History": history,
	}))
}

// handleUpdateCheck forces a fresh release check and swaps in the status card.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	s.checkUpdates(r.Context())
	s.renderPartial(w, "update_status", map[string]any{
		"Update": s.updateStatus(),
	})
}

// handleUpdateApply downloads, verifies and installs the release over the
// running binary, then restarts the service once the response has been flushed.
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	res := updateResult{}

	// The download can outlive the default mutation budget on a slow link, so it
	// runs on its own budget (the route is also given a longer deadline).
	ctx, cancel := context.WithTimeout(context.Background(), updateApplyBudget)
	defer cancel()

	if err := s.updater.Apply(ctx); err != nil {
		res.Error = err.Error()
		_ = s.auditor.Log(r.Context(), audit.Entry{
			Actor:    s.actorName(r),
			Action:   "update.apply",
			Result:   "error",
			Detail:   map[string]any{"error": err.Error()},
			RemoteIP: clientIP(r),
		})
		s.renderPartial(w, "update_result", res)
		return
	}

	res.Message = "Update applied. Restarting the panel."
	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor:    s.actorName(r),
		Action:   "update.apply",
		Result:   "ok",
		Detail:   map[string]any{"version": version.String()},
		RemoteIP: clientIP(r),
	})

	// Restart after the answer has been flushed: systemctl kills this process, so
	// the browser must receive the result first.
	go func() {
		time.Sleep(time.Second)
		_ = execx.Run(context.Background(), 30*time.Second, "systemctl", "restart", update.ServiceName)
	}()

	s.renderPartial(w, "update_result", res)
}

// updateStatus returns the cached release-check result, or nil when the panel
// has not checked yet. Callers render from the copy, never the shared state.
func (s *Server) updateStatus() *update.Status {
	s.updateMu.RLock()
	defer s.updateMu.RUnlock()
	if s.updateState.CheckedAt == "" {
		return nil
	}
	st := s.updateState
	return &st
}

// checkUpdates re-queries the release and replaces the cached result, recording
// the outcome in the update_checks history.
func (s *Server) checkUpdates(ctx context.Context) {
	if s.updater == nil {
		return
	}
	st := s.updater.Check(ctx)
	s.updateMu.Lock()
	s.updateState = st
	s.updateMu.Unlock()

	if s.store != nil {
		_ = s.store.RecordUpdateCheck(ctx, store.UpdateCheck{
			CheckedAt: time.Now(),
			Current:   st.Current,
			Latest:    st.Latest,
			Available: st.Available,
			UpToDate:  st.UpToDate,
			Error:     st.Error,
			Notes:     st.Notes,
		})
	}
}

// periodicUpdateCheck re-checks for a release at startup and daily at 01:00
// local, so the banner is populated without every page render paying for a
// network call.
func (s *Server) periodicUpdateCheck(ctx context.Context) {
	if s.updater == nil {
		return
	}
	s.checkUpdates(ctx)
	for {
		timer := time.NewTimer(untilNext(1, 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			s.checkUpdates(ctx)
		}
	}
}

// untilNext returns the duration until the next hour:minute in local time,
// rolling into tomorrow when that time has already passed today.
func untilNext(hour, minute int) time.Duration {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next.Sub(now)
}
