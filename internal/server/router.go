package server

import (
	"github.com/gtmylab/mailx-admin/internal/auth"
	"io/fs"
	"net/http"
)

func (s *Server) buildRouter() http.Handler {
	mux := http.NewServeMux()

	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	mux.Handle("GET /metrics", s.metrics.Handler())

	// Auth (no session, no CSRF — login itself needs protection but the
	// session cookie can't exist yet, so we use Origin/Referer checking
	// in the login handler instead)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// Protected routes
	protected := http.NewServeMux()
	protected.HandleFunc("GET /", s.handleDashboard)
	protected.HandleFunc("GET /events", s.handleSSE)

	// Service health (HTMX partial refreshed by the dashboard)
	protected.HandleFunc("GET /health/services", s.handleServiceHealthPartial)

	// Users
	protected.HandleFunc("GET /users", s.handleUsersList)
	protected.HandleFunc("GET /users/{id}", s.handleUserDetail)
	protected.HandleFunc("GET /users/new", s.handleUserNew)
	protected.HandleFunc("POST /users", s.handleUserCreate)
	protected.HandleFunc("PATCH /users/{id}", s.handleUserUpdate)
	protected.HandleFunc("DELETE /users/{id}", s.handleUserDelete)
	protected.HandleFunc("POST /users/{id}/reset-password", s.handleUserResetPassword)
	protected.HandleFunc("GET /users/{id}/reset-password-form", s.handleUserResetPasswordForm)
	protected.HandleFunc("GET /users/{id}/edit", s.handleUserEdit)

	// Domains
	protected.HandleFunc("GET /domains", s.handleDomainsList)
	protected.HandleFunc("GET /domains/{id}", s.handleDomainDetail)
	protected.HandleFunc("GET /domains/new", s.handleDomainNew)
	protected.HandleFunc("GET /domains/{id}/edit", s.handleDomainEdit)
	protected.HandleFunc("POST /domains", s.handleDomainCreate)
	protected.HandleFunc("PATCH /domains/{id}", s.handleDomainUpdate)
	protected.HandleFunc("DELETE /domains/{id}", s.handleDomainDelete)
	protected.HandleFunc("POST /domains/{id}/set-primary", s.handleDomainSetPrimary)
	protected.HandleFunc("POST /domains/{id}/regenerate-dkim", s.handleDomainRegenerateDKIM)
	protected.HandleFunc("POST /domains/{id}/preview-delete", s.handlePreviewDomainDelete)

	// Aliases
	protected.HandleFunc("POST /domains/{id}/aliases", s.handleAliasCreate)
	protected.HandleFunc("PATCH /aliases/{id}", s.handleAliasUpdate)
	protected.HandleFunc("DELETE /aliases/{id}", s.handleAliasDelete)

	// Audit
	protected.HandleFunc("GET /audit", s.handleAuditList)

	// Preview endpoints return the diff HTMX swaps into the modal.
	// The domain-delete preview used to be registered without its {id} while
	// the handler read r.PathValue("id"), so every call answered 400.
	protected.HandleFunc("POST /preview/user-create", s.handlePreviewUserCreate)
	protected.HandleFunc("POST /preview/domain-create", s.handlePreviewDomainCreate)

	protected.HandleFunc("GET /tools/test-send", s.handleTestSendPage)
	protected.HandleFunc("POST /tools/test-send", s.handleTestSendRun)
	protected.HandleFunc("GET /tools/test-send/history", s.handleTestSendHistory)

	protected.HandleFunc("GET /domains/{id}/dns", s.handleDomainDNS)
	protected.HandleFunc("GET /domains/{id}/dns/check", s.handleDomainDNSCheck)
	protected.HandleFunc("GET /domains/{id}/dns/export", s.handleDomainDNSCopy)
	protected.HandleFunc("POST /dns/server-ip", s.handleServerIPSave)

	// Config sync status: the dashboard card, a manual run, its history, and the
	// "Import from server" flow that makes shell-created mailboxes visible.
	// See internal/syncer for why the sync is no longer part of a request.
	protected.HandleFunc("GET /sync/status", s.handleSyncStatus)
	protected.HandleFunc("POST /sync/run", s.handleSyncRun)
	protected.HandleFunc("GET /sync/history", s.handleSyncHistory)
	protected.HandleFunc("GET /sync/adopt/preview", s.handleSyncAdoptPreview)
	protected.HandleFunc("POST /sync/adopt", s.handleSyncAdopt)
	protected.HandleFunc("GET /sync/doctor", s.handleDoctor)

	protected.HandleFunc("GET /logs", s.handleLogsPage)
	protected.HandleFunc("GET /logs/list", s.handleLogsList)
	protected.HandleFunc("GET /logs/live", s.handleLogsLive)
	protected.HandleFunc("GET /logs/source", s.handleLogsSource)
	protected.HandleFunc("GET /logs/queue/{qid}", s.handleLogQueueDetail)

	protected.HandleFunc("GET /ssl", s.handleSSLPage)
	protected.HandleFunc("GET /ssl/details/{name}", s.handleSSLDetails)
	protected.HandleFunc("POST /ssl/renew/{name}", s.handleSSLRenew)
	protected.HandleFunc("POST /ssl/settings", s.handleSSLSettings)
	protected.HandleFunc("POST /ssl/send-test", s.handleSSLSendTest)

	protected.HandleFunc("GET /ports", s.handlePortsPage)
	protected.HandleFunc("GET /ports/new", s.handlePortNew)
	protected.HandleFunc("POST /ports", s.handlePortCreate)
	protected.HandleFunc("POST /ports/preview", s.handlePortPreview)
	protected.HandleFunc("DELETE /ports/{id}", s.handlePortDelete)
	protected.HandleFunc("PATCH /ports/{id}", s.handlePortToggle)

	protected.HandleFunc("GET /queue", s.handleQueuePage)
	protected.HandleFunc("GET /queue/refresh", s.handleQueueRefresh)
	protected.HandleFunc("POST /queue/flush/{qid}", s.handleQueueFlush)
	protected.HandleFunc("POST /queue/delete/{qid}", s.handleQueueDelete)
	protected.HandleFunc("POST /queue/flush-all", s.handleQueueFlushAll)

	protected.HandleFunc("GET /users/{id}/sieve", s.handleUserSieve)
	protected.HandleFunc("GET /users/{id}/sieve/new", s.handleSieveRuleNew)
	protected.HandleFunc("POST /users/{id}/sieve", s.handleSieveRuleCreate)
	protected.HandleFunc("DELETE /users/{uid}/sieve/{rid}", s.handleSieveRuleDelete)

	protected.HandleFunc("GET /backup", s.handleBackupPage)
	protected.HandleFunc("POST /backup", s.handleBackupCreate)
	protected.HandleFunc("GET /backup/download/{name}", s.handleBackupDownload)
	protected.HandleFunc("DELETE /backup/{name}", s.handleBackupDelete)
	protected.HandleFunc("POST /backup/restore/{name}", s.handleBackupRestore)

	// Every protected request gets a deadline (see timeout.go). The auth check
	// runs first so an expired session is rejected without borrowing a budget.
	mux.Handle("/", auth.RequireAuth(requestTimeout(protected)))

	// CSRF middleware wraps everything except GET/HEAD/OPTIONS
	return s.sessions.Middleware(s.csrf.Middleware(mux))
}

func fsSub(fsys fs.FS, dir string) (fs.FS, error) {
	return fs.Sub(fsys, dir)
}
