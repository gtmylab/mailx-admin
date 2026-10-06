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

	// Liveness, deliberately unauthenticated and database-free enough to answer
	// while everything else is stuck: this is what an operator (or a monitor)
	// opens when the login page itself spins. The goroutine dump it points at
	// needs a session.
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Auth (no session, no CSRF — login itself needs protection but the
	// session cookie can't exist yet, so we use Origin/Referer checking
	// in the login handler instead).
	//
	// They run inside the request budget too: logging in queries the database
	// (the admin user, then the session insert) and it is the page an operator
	// opens first when something is wrong, so it has to answer or explain —
	// never spin.
	mux.Handle("GET /login", s.requestTimeout(http.HandlerFunc(s.handleLoginPage)))
	mux.Handle("POST /login", s.requestTimeout(http.HandlerFunc(s.handleLoginSubmit)))
	mux.Handle("POST /logout", s.requestTimeout(http.HandlerFunc(s.handleLogout)))

	// Protected routes
	protected := http.NewServeMux()
	protected.HandleFunc("GET /", s.handleDashboard)
	protected.HandleFunc("GET /dashboard/traffic", s.handleDashboardTraffic)
	protected.HandleFunc("GET /events", s.handleSSE)

	// Service health (HTMX partial refreshed by the dashboard)
	protected.HandleFunc("GET /health/services", s.handleServiceHealthPartial)

	// Goroutine dump: the answer to "what is the panel waiting for?" while it
	// is waiting for it (see health.go).
	protected.HandleFunc("GET /healthz/stacks", s.handleHealthStacks)

	// Account (self-service for the signed-in admin)
	protected.HandleFunc("GET /account", s.handleAccountPage)
	protected.HandleFunc("POST /account/password", s.handleChangePassword)

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
	protected.HandleFunc("GET /users/{id}/usage", s.handleUserUsage)
	protected.HandleFunc("GET /users/{id}/logs", s.handleUserLogs)

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
	protected.HandleFunc("POST /users/{uid}/sieve/{rid}/toggle", s.handleSieveRuleToggle)
	protected.HandleFunc("POST /users/{uid}/sieve/{rid}/move", s.handleSieveRuleMove)

	protected.HandleFunc("GET /backup", s.handleBackupPage)
	protected.HandleFunc("POST /backup", s.handleBackupCreate)
	protected.HandleFunc("GET /backup/download/{name}", s.handleBackupDownload)
	protected.HandleFunc("DELETE /backup/{name}", s.handleBackupDelete)
	protected.HandleFunc("POST /backup/restore/{name}", s.handleBackupRestore)

	// Deliverability & reputation
	protected.HandleFunc("GET /deliverability", s.handleDeliverabilityPage)
	protected.HandleFunc("GET /blocklists", s.handleBlocklistsPage)
	protected.HandleFunc("GET /suppressions", s.handleSuppressionsPage)
	protected.HandleFunc("POST /suppressions", s.handleSuppressionCreate)
	protected.HandleFunc("DELETE /suppressions/{id}", s.handleSuppressionDelete)

	// Outbound IP registry
	protected.HandleFunc("GET /system/outbound-ips", s.handleOutboundIPsPage)
	protected.HandleFunc("POST /system/outbound-ips", s.handleOutboundIPCreate)
	protected.HandleFunc("PATCH /system/outbound-ips/{id}", s.handleOutboundIPUpdate)
	protected.HandleFunc("DELETE /system/outbound-ips/{id}", s.handleOutboundIPDelete)
	protected.HandleFunc("POST /system/outbound-ips/{id}/rules", s.handleOutboundRuleCreate)
	protected.HandleFunc("DELETE /system/outbound-ips/{id}/rules/{rid}", s.handleOutboundRuleDelete)

	// Outbound relay (smarthost)
	protected.HandleFunc("GET /system/relay", s.handleRelayPage)
	protected.HandleFunc("POST /system/relay", s.handleRelaySave)

	// Self-update
	protected.HandleFunc("GET /system/updates", s.handleUpdatesPage)
	protected.HandleFunc("POST /system/updates/check", s.handleUpdateCheck)
	protected.HandleFunc("POST /system/updates/apply", s.handleUpdateApply)

	// Database (SQLite -> Postgres migration)
	protected.HandleFunc("GET /system/database", s.handleDatabasePage)
	protected.HandleFunc("POST /system/database/test", s.handleDatabaseTest)
	protected.HandleFunc("POST /system/database/migrate", s.handleDatabaseMigrate)
	protected.HandleFunc("GET /system/database/status", s.handleDatabaseStatus)

	// Mail import
	protected.HandleFunc("GET /system/import", s.handleMailImportPage)
	protected.HandleFunc("POST /system/import", s.handleMailImportAdd)
	protected.HandleFunc("GET /system/import/jobs", s.handleMailImportJobs)
	protected.HandleFunc("GET /system/import/entry", s.handleMailImportEntry)
	protected.HandleFunc("POST /system/import/{id}/stop", s.handleMailImportStop)
	protected.HandleFunc("POST /system/import/{id}/retry", s.handleMailImportRetry)
	protected.HandleFunc("DELETE /system/import/{id}", s.handleMailImportRemove)

	// Services (systemd unit control)
	protected.HandleFunc("GET /system/services", s.handleServicesPage)
	protected.HandleFunc("POST /system/services/{name}/{action}", s.handleServiceAction)

	// Server configuration (hostname, resolver, webmail mail host)
	protected.HandleFunc("GET /system/server", s.handleServerSettingsPage)
	protected.HandleFunc("POST /system/server", s.handleServerSettingsSave)

	// Terminal (interactive shell over WebSocket)
	protected.HandleFunc("GET /terminal", s.handleTerminalPage)
	protected.HandleFunc("GET /terminal/ws", s.handleTerminalWS)

	// Postfix config editor
	protected.HandleFunc("GET /system/postfix", s.handlePostfixPage)
	protected.HandleFunc("POST /system/postfix/file/{name}", s.handlePostfixFileSave)
	protected.HandleFunc("POST /system/postfix/check", s.handlePostfixCheck)
	protected.HandleFunc("POST /system/postfix/reload", s.handlePostfixReload)
	protected.HandleFunc("POST /system/postfix/restart", s.handlePostfixRestart)

	// API keys & webhooks
	protected.HandleFunc("GET /settings/api", s.handleAPISettingsPage)
	protected.HandleFunc("POST /settings/api/keys", s.handleAPIKeyCreate)
	protected.HandleFunc("DELETE /settings/api/keys/{id}", s.handleAPIKeyDelete)
	protected.HandleFunc("POST /settings/api/webhooks", s.handleWebhookCreate)
	protected.HandleFunc("DELETE /settings/api/webhooks/{id}", s.handleWebhookDelete)

	// Public API. Authenticated by bearer key, not the session cookie, so it
	// sits under /api/ which the CSRF middleware skips (see auth/csrf.go).
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/suppressions", s.handleAPISuppressionsList)
	api.HandleFunc("POST /api/v1/suppressions", s.handleAPISuppressionCreate)
	api.HandleFunc("DELETE /api/v1/suppressions/{email}", s.handleAPISuppressionDelete)
	api.HandleFunc("POST /api/v1/messages", s.handleAPIMessages)
	mux.Handle("/api/v1/", s.requireAPIKey(s.requestTimeout(api)))

	// Every protected request gets a deadline *and* a guaranteed answer (see
	// timeout.go). The budget wraps the auth check on purpose: the session
	// lookup is itself a database query, and with it outside the budget a
	// wedged database produced a panel where every URL — including /login —
	// spun forever without writing a single log line.
	mux.Handle("/", auth.RequireAuth(s.requestTimeout(protected)))

	// CSRF middleware wraps everything except GET/HEAD/OPTIONS
	return s.sessions.Middleware(s.csrf.Middleware(mux))
}

func fsSub(fsys fs.FS, dir string) (fs.FS, error) {
	return fs.Sub(fsys, dir)
}
