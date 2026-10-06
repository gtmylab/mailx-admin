package server

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/gtmylab/mailx-admin/internal/apt"
	"github.com/gtmylab/mailx-admin/internal/audit"
)

// lineBuffer captures command output line by line, keeping the most recent
// lines. It is the shared output sink for the apt update job, so the admin can
// leave the page and come back to see the full transcript.
type lineBuffer struct {
	mu      sync.Mutex
	lines   []string
	partial string
}

const lineBufferCap = 400

func (b *lineBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.partial + string(p)
	parts := strings.Split(s, "\n")
	b.partial = parts[len(parts)-1]
	for _, l := range parts[:len(parts)-1] {
		b.lines = append(b.lines, l)
	}
	if len(b.lines) > lineBufferCap {
		b.lines = b.lines[len(b.lines)-lineBufferCap:]
	}
	return len(p), nil
}

func (b *lineBuffer) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

// packageUpdater caches the upgradable-package list and runs one update at a
// time. Both the cached list and the running job survive page navigation.
type packageUpdater struct {
	mu sync.Mutex

	refreshing bool
	loaded     bool
	list       []apt.Package
	listErr    string

	running bool
	done    bool
	jobErr  string
	jobLog  *lineBuffer
}

func newPackageUpdater() *packageUpdater {
	return &packageUpdater{jobLog: &lineBuffer{}}
}

// view is the template-facing state of the page.
func (u *packageUpdater) view() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	return map[string]any{
		"Refreshing": u.refreshing,
		"Loaded":     u.loaded,
		"List":       u.list,
		"ListErr":    u.listErr,
		"Running":    u.running,
		"Done":       u.done,
		"Error":      u.jobErr,
		"Log":        u.jobLog.Lines(),
	}
}

// upgradableCount returns how many packages have updates, for the dashboard.
func (u *packageUpdater) upgradableCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.list)
}

// ensureList starts a background refresh if none has ever completed.
func (u *packageUpdater) ensureList() {
	u.mu.Lock()
	if u.loaded || u.refreshing {
		u.mu.Unlock()
		return
	}
	u.mu.Unlock()
	u.refresh()
}

func (u *packageUpdater) refresh() {
	u.mu.Lock()
	if u.refreshing {
		u.mu.Unlock()
		return
	}
	u.refreshing = true
	u.mu.Unlock()

	go func() {
		pkgs, err := apt.Upgradable(context.Background())
		u.mu.Lock()
		u.list = pkgs
		u.listErr = errStr(err)
		u.refreshing = false
		u.loaded = true
		u.mu.Unlock()
	}()
}

// update starts a background upgrade of the named packages. It returns false if
// an update is already running.
func (u *packageUpdater) update(names []string) bool {
	u.mu.Lock()
	if u.running {
		u.mu.Unlock()
		return false
	}
	buf := &lineBuffer{}
	u.running = true
	u.done = false
	u.jobErr = ""
	u.jobLog = buf
	u.mu.Unlock()

	go func() {
		err := apt.Upgrade(context.Background(), names, buf)
		u.mu.Lock()
		u.running = false
		u.done = true
		u.jobErr = errStr(err)
		u.mu.Unlock()
		// The upgradable set changed; refresh it in the background.
		u.refresh()
	}()
	return true
}

func (s *Server) handlePackagesPage(w http.ResponseWriter, r *http.Request) {
	s.packages.ensureList()
	s.render(w, 200, "packages.html", s.newPageData(w, r, "Software updates", "packages", s.packages.view()))
}

func (s *Server) handlePackagesList(w http.ResponseWriter, r *http.Request) {
	s.packages.ensureList()
	s.renderPartial(w, "package_list", s.packages.view())
}

func (s *Server) handlePackagesRefresh(w http.ResponseWriter, r *http.Request) {
	s.packages.refresh()
	s.renderPartial(w, "package_list", s.packages.view())
}

func (s *Server) handlePackagesUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderPartial(w, "package_status", map[string]any{"Error": "Invalid form", "Running": false})
		return
	}
	names := r.Form["packages"]
	if len(names) == 0 {
		s.renderPartial(w, "package_status", map[string]any{"Error": "Select at least one package", "Running": false})
		return
	}
	sort.Strings(names)

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: s.actorName(r), Action: "system.packages", TargetType: "system", TargetID: "apt",
		Result: "ok", Detail: map[string]any{"packages": names}, RemoteIP: clientIP(r),
	})

	s.packages.update(names)
	s.renderPartial(w, "package_status", s.packages.view())
}

func (s *Server) handlePackagesStatus(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "package_status", s.packages.view())
}
