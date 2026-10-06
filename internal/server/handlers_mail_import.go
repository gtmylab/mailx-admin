package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/importer"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// importAddResult is the template-facing result of queueing one or more
// imports: how many were queued, plus any per-entry validation errors.
type importAddResult struct {
	Queued int
	Errors []string
}

func (s *Server) handleMailImportPage(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load mailboxes: "+err.Error())
		return
	}
	s.render(w, 200, "mail_import.html", s.newPageData(w, r, "Mail import", "mail-import", map[string]any{
		"Users": snap.Users,
		"Jobs":  s.importQueue.List(),
	}))
}

// handleMailImportAdd queues one (quick form) or many (bulk form) import jobs.
// Both forms post the same field names; the handler reads the repeated values
// in order and queues a job per entry.
func (s *Server) handleMailImportAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderPartial(w, "mail_import_add_result", importAddResult{Errors: []string{"Invalid form data"}})
		return
	}

	sources := r.Form["source"]
	if len(sources) == 0 {
		s.renderPartial(w, "mail_import_add_result", importAddResult{Errors: []string{"Add at least one import entry"}})
		return
	}

	actor := s.actorName(r)
	remoteIP := clientIP(r)
	var out importAddResult
	for i := range sources {
		src, userID, errMsg := s.parseImportEntry(r, i)
		if errMsg != "" {
			out.Errors = append(out.Errors, errMsg)
			continue
		}
		u, err := s.loadUser(r.Context(), userID)
		if err != nil {
			out.Errors = append(out.Errors, "destination mailbox not found")
			continue
		}
		id := s.importQueue.Add(src, u.MaildirPath(), u.DeliveryUID(), u.DeliveryGID(), u.Email)
		out.Queued++
		_ = s.auditor.Log(r.Context(), audit.Entry{
			Actor: actor, Action: "mail.import", TargetType: "user", TargetID: u.Email,
			Result: "ok", Detail: map[string]any{"job": id, "phase": "queued"}, RemoteIP: remoteIP,
		})
	}
	s.renderPartial(w, "mail_import_add_result", out)
}

// handleMailImportJobs renders the polling job-list fragment.
func (s *Server) handleMailImportJobs(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "mail_import_jobs", map[string]any{"Jobs": s.importQueue.List()})
}

// handleMailImportEntry renders one empty entry row for the bulk editor's
// "Add entry" button.
func (s *Server) handleMailImportEntry(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load mailboxes: "+err.Error())
		return
	}
	s.renderPartial(w, "mail_import_entry", map[string]any{"Users": snap.Users, "Bulk": true})
}

func (s *Server) handleMailImportStop(w http.ResponseWriter, r *http.Request) {
	if id := r.PathValue("id"); id != "" {
		s.importQueue.Stop(id)
	}
	s.renderPartial(w, "mail_import_jobs", map[string]any{"Jobs": s.importQueue.List()})
}

func (s *Server) handleMailImportRetry(w http.ResponseWriter, r *http.Request) {
	if id := r.PathValue("id"); id != "" {
		s.importQueue.Retry(id)
	}
	s.renderPartial(w, "mail_import_jobs", map[string]any{"Jobs": s.importQueue.List()})
}

func (s *Server) handleMailImportRemove(w http.ResponseWriter, r *http.Request) {
	if id := r.PathValue("id"); id != "" {
		s.importQueue.Remove(id)
	}
	s.renderPartial(w, "mail_import_jobs", map[string]any{"Jobs": s.importQueue.List()})
}

// parseImportEntry reads one import entry from the submitted form by index.
// Repeated fields (source, user_id, host, ...) line up by position, so the bulk
// form's rows and the quick form's single row share this parser. It returns the
// source, the destination user id and a validation error ("" if valid).
func (s *Server) parseImportEntry(r *http.Request, i int) (importer.Source, int64, string) {
	var src importer.Source
	userID, err := strconv.ParseInt(fieldAt(r, "user_id", i), 10, 64)
	if err != nil || userID <= 0 {
		return src, 0, "choose a destination mailbox"
	}

	switch fieldAt(r, "source", i) {
	case "imap":
		port, _ := strconv.Atoi(fieldAt(r, "port", i))
		src.IMAP = &importer.IMAPConfig{
			Host:     fieldAt(r, "host", i),
			Port:     port,
			TLSMode:  fieldAt(r, "tls_mode", i),
			Username: fieldAt(r, "username", i),
			Password: fieldAt(r, "password", i),
			Insecure: fieldAt(r, "verify_tls", i) == "off",
		}
		if src.IMAP.Host == "" || src.IMAP.Username == "" {
			return src, 0, "IMAP host and username are required"
		}
	case "mbox":
		src.MboxPath = fieldAt(r, "path", i)
		if src.MboxPath == "" {
			return src, 0, "mbox path is required"
		}
	case "maildir":
		src.MaildirPath = fieldAt(r, "path", i)
		if src.MaildirPath == "" {
			return src, 0, "Maildir path is required"
		}
	default:
		return src, 0, "unknown source type"
	}
	return src, userID, ""
}

// fieldAt returns the i-th value of a form field, or "" when it is absent.
func fieldAt(r *http.Request, name string, i int) string {
	vals := r.Form[name]
	if i >= 0 && i < len(vals) {
		return vals[i]
	}
	return ""
}

// loadUser loads one mailbox with its domain name, kind and ownership, so the
// import writes into the right maildir with the right uid/gid.
func (s *Server) loadUser(ctx context.Context, id int64) (models.User, error) {
	var u models.User
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.domain_id, u.username, u.email, u.quota_mb, u.active,
		       u.is_admin, d.name,
		       u.kind, COALESCE(u.sys_uid, 0), COALESCE(u.sys_gid, 0), COALESCE(u.home, '')
		FROM users u JOIN domains d ON d.id = u.domain_id
		WHERE u.id = ?
	`, id).Scan(&u.ID, &u.DomainID, &u.Username, &u.Email, &u.QuotaMB, &u.Active, &u.IsAdmin, &u.DomainName,
		&u.Kind, &u.SysUID, &u.SysGID, &u.Home)
	return u, err
}
