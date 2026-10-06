package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
)

// serviceCheckTimeout bounds one `systemctl is-active`. The dashboard renders
// this list on every load and the health fragment refreshes it on a timer, so
// the checks run concurrently: five sequential calls that each wait for a slow
// systemd is five times the page's latency for one line of text each.
const serviceCheckTimeout = 4 * time.Second

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

	s.render(w, 200, "dashboard.html", s.newPageData(w, r, "Dashboard", "dashboard", map[string]any{
		"Domains":  snap.Domains,
		"Users":    len(snap.Users),
		"Aliases":  len(snap.Aliases),
		"Counts":   counts,
		"Services": checkServices(ctx),
		"Traffic":  s.buildTraffic(ctx),
		"System":   s.buildSystem(),
	}))
}

func (s *Server) handleServiceHealthPartial(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "service_health", map[string]any{
		"Data": map[string]any{
			"Services": checkServices(r.Context()),
		},
	})
}

// checkServices reports systemd's view of the mail services, in parallel.
func checkServices(ctx context.Context) []serviceStatus {
	names := []string{"postfix", "dovecot", "opendkim", "mysql", "apache2"}
	out := make([]serviceStatus, len(names))

	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			out[i] = serviceStatus{Name: n, Status: serviceState(ctx, n)}
		}(i, n)
	}
	wg.Wait()
	return out
}

// serviceState asks systemd about one unit. `systemctl is-active` prints the
// state on stdout even when it exits non-zero (that is how it reports
// "inactive"), so the output is the answer; an empty output means the command
// could not be run at all, which is not the same as "inactive".
func serviceState(ctx context.Context, name string) string {
	// A fresh budget per unit: the request context is shared, but one slow
	// service must not eat the time the others need.
	ctx, cancel := context.WithTimeout(ctx, serviceCheckTimeout)
	defer cancel()

	b, _ := execx.Output(ctx, serviceCheckTimeout, "systemctl", "is-active", name)
	status := strings.TrimSpace(string(b))
	if status == "" {
		return "unknown"
	}
	return status
}
