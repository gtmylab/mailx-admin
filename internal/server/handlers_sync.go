package server

import (
	"context"
	"net/http"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/seed"
	"github.com/gtmylab/mailx-admin/internal/syncer"
)

// handleSyncStatus renders the dashboard's configuration-sync card. The
// dashboard polls it, so it stays cheap: one cached read of the newest
// reconcile_runs row.
func (s *Server) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	s.renderSyncStatus(w, r, "", "")
}

func (s *Server) renderSyncStatus(w http.ResponseWriter, r *http.Request, message, errMsg string) {
	s.renderPartial(w, "sync_status", map[string]any{
		"Data": syncData{
			Status:  s.syncStatus(r.Context()),
			Message: message,
			Error:   errMsg,
		},
	})
}

// handleSyncRun runs one sync and answers with the refreshed card. This is the
// "Sync now" button: the admin asked for it, so the request waits — but only for
// a bounded reconcile, and no other request is blocked behind it.
func (s *Server) handleSyncRun(w http.ResponseWriter, r *http.Request) {
	if s.syncer == nil {
		s.renderFormError(w, "This panel has no configuration syncer.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), syncRunBudget)
	defer cancel()

	res, err := s.syncer.RunNow(ctx, "panel:sync-now")

	entry := audit.Entry{
		Actor:    s.actorName(r),
		Action:   "sync.run",
		Result:   "ok",
		RemoteIP: clientIP(r),
	}
	if err != nil {
		entry.Result = "error"
		entry.Detail = map[string]any{"error": err.Error()}
		_ = s.auditor.Log(ctx, entry)
		// The card shows the failure where the admin clicked; no redirect, so
		// the error text stays on screen.
		s.renderSyncStatus(w, r, "", err.Error())
		return
	}

	changed := 0
	for _, c := range res.Changes {
		if c.Action != "unchanged" {
			changed++
		}
	}
	entry.Detail = map[string]any{
		"files_changed": changed,
		"reloaded":      res.ReloadedSvcs,
		"drift":         len(res.Drift),
	}
	_ = s.auditor.Log(ctx, entry)

	msg := "Configuration is up to date."
	switch {
	case len(res.Drift) > 0:
		msg = "Sync finished, but it removed entries the panel does not manage — see below."
	case changed > 0:
		msg = countLabel(changed, "file updated", "files updated")
		if len(res.ReloadedSvcs) > 0 {
			msg += ", reloaded " + joinWithCommas(res.ReloadedSvcs)
		}
		msg += "."
	}
	s.renderSyncStatus(w, r, msg, "")
}

// handleSyncHistory lists recent runs on demand, so the dashboard's poll does
// not pay for it.
func (s *Server) handleSyncHistory(w http.ResponseWriter, r *http.Request) {
	var runs []syncer.Run
	if s.syncer != nil {
		runs = s.syncer.History(r.Context())
	}
	views := make([]runView, 0, len(runs))
	for _, run := range runs {
		views = append(views, newRunView(run))
	}
	s.renderPartial(w, "sync_history", map[string]any{
		"Data": syncData{History: views},
	})
}

// handleSyncAdoptPreview shows what "Import from server" would bring in.
func (s *Server) handleSyncAdoptPreview(w http.ResponseWriter, r *http.Request) {
	found, err := s.scanServer(r.Context())
	if err != nil {
		s.renderFormError(w, "Could not read the server configuration: "+err.Error())
		return
	}

	plan, err := seed.Plan(r.Context(), s.store, found)
	if err != nil {
		s.renderFormError(w, "Could not compare with the database: "+err.Error())
		return
	}

	s.renderPartial(w, "adopt_preview", map[string]any{
		"Data": syncData{Plan: plan},
	})
}

// handleSyncAdopt imports the mailboxes, domains and aliases that exist on the
// server but not in the panel.
//
// This is the fix for "I created a mailbox with useradd and the panel never
// showed it": the panel renders what is in its database, so mailboxes it does
// not know about have to be brought in deliberately. Nothing is deleted on
// either side, and importing twice is a no-op.
func (s *Server) handleSyncAdopt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	found, err := s.scanServer(ctx)
	if err != nil {
		s.renderFormError(w, "Could not read the server configuration: "+err.Error())
		return
	}

	plan, err := seed.Adopt(ctx, s.store, found)
	if err != nil {
		s.renderFormError(w, "Import failed: "+err.Error())
		return
	}

	_ = s.auditor.Log(ctx, audit.Entry{
		Actor:    s.actorName(r),
		Action:   "sync.adopt",
		Result:   "ok",
		RemoteIP: clientIP(r),
		Detail: map[string]any{
			"domains": len(plan.Domains),
			"users":   len(plan.Users),
			"aliases": len(plan.Aliases),
			"skipped": len(plan.Skipped),
		},
	})

	// Imported mailboxes only reach Postfix and Dovecot after a sync, and the
	// panel already does that in the background.
	if s.syncer != nil {
		s.syncer.Request("panel:adopt")
	}

	msg := "Nothing was missing: the panel already knows every entry on this server."
	if !plan.Empty() {
		msg = "Imported " + joinWithCommas([]string{
			countLabel(len(plan.Domains), "domain", "domains"),
			countLabel(len(plan.Users), "mailbox", "mailboxes"),
			countLabel(len(plan.Aliases), "alias", "aliases"),
		}) + "."
		if len(plan.Skipped) > 0 {
			msg += " " + countLabel(len(plan.Skipped), "entry was", "entries were") +
				" skipped — open the import dialog again for the reasons."
		}
		msg += " A configuration sync has been queued."
	}

	w.Header().Set("HX-Redirect", "/users?flash="+encodeFlash(msg))
	w.WriteHeader(http.StatusOK)
}
