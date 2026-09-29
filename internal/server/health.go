package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/gtmylab/mailx-admin/internal/version"
)

// healthPingTimeout bounds the database check. Short on purpose: /healthz is
// what an operator opens when the panel is slow, so it must stay fast even when
// the database is not.
const healthPingTimeout = 2 * time.Second

// healthResponse is the payload of GET /healthz.
//
// It exists because the two failure modes of this panel look identical from the
// outside: a service that is gone, and a service whose requests are all waiting
// for a resource that neither Apache nor the browser can see. /healthz tells
// them apart without needing a shell — the process keeps answering even while
// every handler is stuck, and RecentTimeouts names the requests that ran out of
// budget and when.
type healthResponse struct {
	OK         bool            `json:"ok"`
	Version    string          `json:"version"`
	Hostname   string          `json:"hostname"`
	UptimeSec  float64         `json:"uptime_seconds"`
	Goroutines int             `json:"goroutines"`
	Database   healthDatabase  `json:"database"`
	Sync       *healthSync     `json:"sync,omitempty"`
	Timeouts   []healthTimeout `json:"recent_timeouts,omitempty"`
}

type healthDatabase struct {
	OK     bool    `json:"ok"`
	Driver string  `json:"driver"`
	PingMS float64 `json:"ping_ms"`
	Error  string  `json:"error,omitempty"`
}

type healthSync struct {
	Running    bool   `json:"running"`
	Pending    bool   `json:"pending"`
	LastRun    string `json:"last_run,omitempty"`
	LastStatus string `json:"last_status,omitempty"`
	LastError  string `json:"last_error,omitempty"`
}

type healthTimeout struct {
	At     string `json:"at"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Budget string `json:"budget"`
}

// handleHealth reports whether the process is serving, whether it can reach its
// own database, and what the last requests were waiting for.
//
// The status code is always 200 while the process is running. A panel whose
// database is briefly locked is still up, and answering 503 there would have a
// monitor restart the one component that is working. The Database and Timeouts
// fields carry the truth.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthPingTimeout)
	defer cancel()

	resp := healthResponse{
		OK:         true,
		Version:    version.String(),
		Goroutines: runtime.NumGoroutine(),
		Database:   healthDatabase{Driver: s.dbDriver},
	}
	if s.cfg != nil {
		resp.Hostname = s.cfg.Server.Hostname
	}
	if !s.startedAt.IsZero() {
		resp.UptimeSec = time.Since(s.startedAt).Seconds()
	}

	if s.db != nil {
		start := time.Now()
		err := s.db.PingContext(ctx)
		resp.Database.PingMS = float64(time.Since(start).Microseconds()) / 1000
		if err != nil {
			resp.Database.Error = err.Error()
		} else {
			resp.Database.OK = true
		}
	}

	if s.syncer != nil {
		st := s.syncer.Status(ctx)
		sync := &healthSync{Running: st.Running, Pending: st.Pending}
		if st.Last != nil {
			sync.LastRun = st.Last.StartedAt.Format(time.RFC3339)
			sync.LastStatus = st.Last.Status
			sync.LastError = st.Last.Error
		}
		resp.Sync = sync
	}

	if s.timeouts != nil {
		for _, rec := range s.timeouts.recent() {
			resp.Timeouts = append(resp.Timeouts, healthTimeout{
				At:     rec.At.Format(time.RFC3339),
				Method: rec.Method,
				Path:   rec.Path,
				Budget: rec.Budget.String(),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		s.logger.Warn("health response failed", "err", err)
	}
}

// handleHealthStacks prints every goroutine's stack, followed by the dumps
// captured for each request that ran out of budget.
//
// This is the page that turns "the panel hangs and the logs say nothing" into a
// specific frame — a lock, a pipe, a socket read. It needs a session because a
// stack dump names paths and functions, but it deliberately needs nothing else:
// no parameters, no query, no database. When everything is stuck, it still
// answers.
func (s *Server) handleHealthStacks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	fmt.Fprintf(w, "mailx-admin %s goroutine dump\n", version.String())
	fmt.Fprintf(w, "generated %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "goroutines: %d\n", runtime.NumGoroutine())

	if s.timeouts != nil {
		recent := s.timeouts.recent()
		if len(recent) == 0 {
			io.WriteString(w, "\nno request has run out of budget since this process started\n")
		}
		for _, rec := range recent {
			fmt.Fprintf(w, "\n=== timed out: %s (captured %s) ===\n%s\n",
				rec.Summary(), rec.At.Format(time.RFC3339), rec.Stack)
		}
	}

	io.WriteString(w, "\n=== current goroutines ===\n")
	io.WriteString(w, goroutineDump())
}
