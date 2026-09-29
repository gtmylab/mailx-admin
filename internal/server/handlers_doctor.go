package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gtmylab/mailx-admin/internal/doctor"
)

// doctorBudget is generous: the checks run `postfix check`, `doveconf -n` and a
// dry-run render of every managed file.
const doctorBudget = 90 * time.Second

// handleDoctor runs the same read-only checks as `mailx-admin doctor` and shows
// them in a dialog. It is the panel half of "why is nothing happening?".
func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), doctorBudget)
	defer cancel()

	report := doctor.Run(ctx, doctor.Options{
		Config:   s.cfg,
		DB:       s.db,
		Store:    s.store,
		Rec:      s.rec,
		LastSync: s.lastSyncSnapshot(ctx),
	})

	s.renderPartial(w, "doctor_report", map[string]any{
		"Data": map[string]any{
			"Checks": report.Checks,
			"Health": string(report.Health()),
		},
	})
}

// lastSyncSnapshot feeds the doctor the panel's own sync history, which is the
// first thing to look at when a change "did nothing".
func (s *Server) lastSyncSnapshot(ctx context.Context) *doctor.SyncSnapshot {
	if s.syncer == nil {
		return nil
	}
	status := s.syncer.Status(ctx)
	if status.Last == nil {
		return nil
	}
	return &doctor.SyncSnapshot{
		Status:    status.Last.Status,
		Trigger:   status.Last.Trigger,
		StartedAt: status.Last.StartedAt,
		Error:     status.Last.Error,
		Drift:     len(status.Last.Drift),
	}
}
