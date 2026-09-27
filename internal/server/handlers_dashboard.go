package server

import (
	"context"
	"net/http"
	"os/exec"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/auth"
)

type serviceStatus struct {
	Name   string
	Status string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to load state: "+err.Error())
		return
	}
	counts, _ := s.store.CountUsersByDomain(ctx)

	s.render(w, 200, "dashboard.html", pageData{
		Title:     "Dashboard",
		Session:   auth.SessionFromContext(ctx),
		ActiveNav: "dashboard",
		Data: map[string]any{
			"Domains":  snap.Domains,
			"Users":    len(snap.Users),
			"Aliases":  len(snap.Aliases),
			"Counts":   counts,
			"Services": checkServices(ctx),
		},
	})
}

func (s *Server) handleServiceHealthPartial(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "service_health", map[string]any{
		"Data": map[string]any{
			"Services": checkServices(r.Context()),
		},
	})
}

func checkServices(ctx context.Context) []serviceStatus {
	names := []string{"postfix", "dovecot", "opendkim", "mysql", "apache2"}
	out := make([]serviceStatus, 0, len(names))
	for _, n := range names {
		cmd := exec.CommandContext(ctx, "systemctl", "is-active", n)
		b, _ := cmd.Output()
		status := strings.TrimSpace(string(b))
		if status == "" {
			status = "unknown"
		}
		out = append(out, serviceStatus{Name: n, Status: status})
	}
	return out
}
