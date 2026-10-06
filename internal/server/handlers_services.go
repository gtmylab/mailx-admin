package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/execx"
)

// managedServices are the units the Services page lists and controls. They match
// the dashboard's health checks, so the two views always agree.
var managedServices = []string{"postfix", "dovecot", "opendkim", "mysql", "apache2"}

// serviceActionTimeout keeps a systemctl control under the request budget: a
// restart can wait for the unit's ExecStop, but never long enough to trip the
// panel's own 30s write budget.
const serviceActionTimeout = 25 * time.Second

// serviceInfo is one row of the Services page: systemd's answer to is-active and
// is-enabled.
type serviceInfo struct {
	Name    string
	Status  string // active, inactive, failed, unknown
	Enabled string // enabled, disabled, static, masked, unknown
}

func (s *Server) handleServicesPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "services.html", s.newPageData(w, r, "Services", "services", map[string]any{
		"Services": checkServicesFull(r.Context()),
	}))
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	action := strings.TrimSpace(r.PathValue("action"))

	if !managedServiceNames[name] || !serviceVerbs[action] {
		s.renderError(w, 400, "Unknown service or action")
		return
	}

	err := execx.Run(r.Context(), serviceActionTimeout, "systemctl", action, name)

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: s.actorName(r), Action: "service." + action, TargetType: "service", TargetID: name,
		Result: resultString(err), Detail: map[string]any{"error": serviceErr(err)}, RemoteIP: clientIP(r),
	})

	s.renderPartial(w, "service_table", map[string]any{
		"Services": checkServicesFull(r.Context()),
		"Name":     name,
		"Action":   action,
		"Error":    serviceErr(err),
	})
}

var managedServiceNames = func() map[string]bool {
	m := make(map[string]bool, len(managedServices))
	for _, n := range managedServices {
		m[n] = true
	}
	return m
}()

var serviceVerbs = map[string]bool{
	"start": true, "stop": true, "restart": true, "enable": true, "disable": true,
}

func checkServicesFull(ctx context.Context) []serviceInfo {
	out := make([]serviceInfo, len(managedServices))
	var wg sync.WaitGroup
	for i, n := range managedServices {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			out[i] = checkService(ctx, n)
		}(i, n)
	}
	wg.Wait()
	return out
}

func checkService(ctx context.Context, name string) serviceInfo {
	info := serviceInfo{Name: name}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); info.Status = serviceState(ctx, name) }()
	go func() { defer wg.Done(); info.Enabled = serviceEnabledState(ctx, name) }()
	wg.Wait()
	return info
}

// serviceEnabledState asks systemd whether a unit starts at boot. Like
// serviceState, an empty answer means the command could not run at all, which is
// reported as "unknown" rather than "disabled".
func serviceEnabledState(ctx context.Context, name string) string {
	b, _ := execx.Output(ctx, serviceCheckTimeout, "systemctl", "is-enabled", name)
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "unknown"
	}
	return s
}

func serviceErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func resultString(err error) string {
	if err == nil {
		return "ok"
	}
	return "error"
}
