package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/importer"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// importBudget bounds a background mail import, which can take a long time on a
// large mailbox. The HTTP handlers that start and poll it stay fast.
const importBudget = 30 * time.Minute

// mailImportResult is the template-facing state of a mail import.
type mailImportResult struct {
	Status  string // "running", "done", "error"
	Error   string
	Total   int
	Folders []importer.FolderCount
}

func (s *Server) handleMailImportPage(w http.ResponseWriter, r *http.Request) {
	snap, err := s.store.Snapshot(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load mailboxes: "+err.Error())
		return
	}
	s.render(w, 200, "mail_import.html", s.newPageData(w, r, "Mail import", "mail-import", map[string]any{
		"Users": snap.Users,
	}))
}

// handleMailImportStart validates the form and starts the import in the
// background, answering with the "running" fragment that polls the status.
func (s *Server) handleMailImportStart(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	userID, err := strconv.ParseInt(r.FormValue("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		s.renderPartial(w, "mail_import_result", mailImportResult{Status: "error", Error: "choose a destination mailbox"})
		return
	}
	u, err := s.loadUser(r.Context(), userID)
	if err != nil {
		s.renderPartial(w, "mail_import_result", mailImportResult{Status: "error", Error: "destination mailbox not found"})
		return
	}

	src := importer.Source{}
	switch r.FormValue("source") {
	case "imap":
		port, _ := strconv.Atoi(r.FormValue("port"))
		src.IMAP = &importer.IMAPConfig{
			Host:     r.FormValue("host"),
			Port:     port,
			TLSMode:  r.FormValue("tls_mode"),
			Username: r.FormValue("username"),
			Password: r.FormValue("password"),
		}
		if src.IMAP.Host == "" || src.IMAP.Username == "" {
			s.renderPartial(w, "mail_import_result", mailImportResult{Status: "error", Error: "IMAP host and username are required"})
			return
		}
	case "mbox":
		src.MboxPath = r.FormValue("path")
		if src.MboxPath == "" {
			s.renderPartial(w, "mail_import_result", mailImportResult{Status: "error", Error: "mbox path is required"})
			return
		}
	case "maildir":
		src.MaildirPath = r.FormValue("path")
		if src.MaildirPath == "" {
			s.renderPartial(w, "mail_import_result", mailImportResult{Status: "error", Error: "Maildir path is required"})
			return
		}
	default:
		s.renderPartial(w, "mail_import_result", mailImportResult{Status: "error", Error: "unknown source type"})
		return
	}

	actor := s.actorName(r)
	remoteIP := clientIP(r)
	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: actor, Action: "mail.import", TargetType: "user", TargetID: u.Email,
		Result: "ok", Detail: map[string]any{"phase": "started"}, RemoteIP: remoteIP,
	})

	s.mailImportMu.Lock()
	s.mailImportResult = mailImportResult{Status: "running"}
	s.mailImportMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), importBudget)
		defer cancel()

		res, err := importer.Import(ctx, src, u.MaildirPath(), u.DeliveryUID(), u.DeliveryGID())

		s.mailImportMu.Lock()
		defer s.mailImportMu.Unlock()
		if err != nil {
			s.mailImportResult = mailImportResult{Status: "error", Error: err.Error()}
			_ = s.auditor.Log(context.Background(), audit.Entry{
				Actor: actor, Action: "mail.import", TargetType: "user", TargetID: u.Email,
				Result: "error", Detail: map[string]any{"error": err.Error()}, RemoteIP: remoteIP,
			})
			return
		}
		s.mailImportResult = mailImportResult{Status: "done", Total: res.Total(), Folders: res.SortedFolders()}
		_ = s.auditor.Log(context.Background(), audit.Entry{
			Actor: actor, Action: "mail.import", TargetType: "user", TargetID: u.Email,
			Result: "ok", Detail: map[string]any{"messages": res.Total()}, RemoteIP: remoteIP,
		})
	}()

	s.renderPartial(w, "mail_import_result", mailImportResult{Status: "running"})
}

// handleMailImportStatus reports the import state for the polling fragment.
func (s *Server) handleMailImportStatus(w http.ResponseWriter, r *http.Request) {
	s.mailImportMu.Lock()
	res := s.mailImportResult
	s.mailImportMu.Unlock()
	s.renderPartial(w, "mail_import_result", res)
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
