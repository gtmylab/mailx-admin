package server

import (
	"context"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/seed"
	"github.com/gtmylab/mailx-admin/internal/syncer"
)

// syncRunBudget bounds a manual sync. Each helper the reconciler runs is bounded
// on its own (see internal/execx); this covers the whole sequence.
const syncRunBudget = 2 * time.Minute

// syncData is what the sync fragments render from.
type syncData struct {
	Status  *syncView
	History []runView
	Plan    *seed.ImportPlan
	Message string
	Error   string
}

// syncView is the template-facing shape of syncer.Status. Templates should not
// have to know the syncer package's types.
type syncView struct {
	Running  bool
	Pending  bool
	Degraded bool
	Failed   bool
	Last     *runView
}

// runView is one sync run as the panel shows it.
type runView struct {
	ID       int64
	Trigger  string
	Status   string
	Started  time.Time
	Finished *time.Time
	Duration string
	Changed  int
	Files    []fileView
	Drift    []driftView
	Error    string
}

type fileView struct {
	Name   string
	Action string
}

type driftView struct {
	Name   string
	Count  int
	Lines  []string
	More   int
	Backup string
}

func newSyncView(st *syncer.Status) *syncView {
	if st == nil {
		return nil
	}
	v := &syncView{Running: st.Running, Pending: st.Pending}
	if st.Last != nil {
		last := newRunView(*st.Last)
		v.Last = &last
	}
	v.Degraded = st.Degraded()
	v.Failed = st.Failed()
	return v
}

// newRunView converts a recorded run, shortening paths to base names so the
// dashboard stays readable (/etc/postfix/virtual -> virtual).
func newRunView(run syncer.Run) runView {
	v := runView{
		ID:      run.ID,
		Trigger: run.Trigger,
		Status:  run.Status,
		Started: run.StartedAt,
		Error:   run.Error,
	}
	if run.FinishedAt != nil {
		v.Finished = run.FinishedAt
		v.Duration = run.FinishedAt.Sub(run.StartedAt).Round(time.Millisecond).String()
	}
	for _, c := range run.Files {
		if c.Action == "unchanged" {
			continue
		}
		v.Files = append(v.Files, fileView{
			Name:   path.Base(c.Path),
			Action: c.Action,
		})
		v.Changed++
	}
	for _, d := range run.Drift {
		lines := d.Lines
		more := 0
		if len(lines) > 5 {
			more = len(lines) - 5
			lines = lines[:5]
		}
		v.Drift = append(v.Drift, driftView{
			Name:   path.Base(d.Path),
			Count:  d.Count,
			Lines:  lines,
			More:   more,
			Backup: d.Backup,
		})
	}
	return v
}

// scanServer finds what exists on the server but not in the panel. Read-only.
func (s *Server) scanServer(ctx context.Context) (*seed.Found, error) {
	return seed.Scan(seed.Options{
		PostfixConfDir:    s.cfg.Mail.PostfixConfDir,
		DovecotConfDir:    s.cfg.Mail.DovecotConfDir,
		OpenDKIMDir:       s.cfg.Mail.OpenDKIMDir,
		PrimaryDomainFile: s.cfg.Mail.PrimaryDomainFile,
	})
}

func (s *Server) actorName(r *http.Request) string {
	if sess := auth.SessionFromContext(r.Context()); sess != nil && sess.Username != "" {
		return "admin:" + sess.Username
	}
	return "admin:unknown"
}

// countLabel renders "1 mailbox" / "3 mailboxes" without a formatting helper per
// call site.
func countLabel(n int, singular, pluralForm string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + pluralForm
}

func joinWithCommas(parts []string) string {
	out := ""
	for i, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			if i == len(parts)-1 {
				out += " and "
			} else {
				out += ", "
			}
		}
		out += p
	}
	return out
}
