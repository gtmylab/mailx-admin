package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/dns"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/store"
)

// ---- Suppressions ----------------------------------------------------------

func (s *Server) handleSuppressionsPage(w http.ResponseWriter, r *http.Request) {
	sups, err := s.store.ListSuppressions(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load suppressions")
		return
	}
	s.render(w, http.StatusOK, "suppressions.html", s.newPageData(w, r, "Suppressions", "suppressions", map[string]any{
		"Suppressions": sups,
	}))
}

func (s *Server) handleSuppressionCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}
	value := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if value == "" {
		s.renderFormError(w, "Email or domain is required")
		return
	}
	matchType := r.FormValue("match_type")
	if matchType != "domain" {
		matchType = "email"
	}
	direction := r.FormValue("direction")
	if direction != "in" {
		direction = "out"
	}
	reason := r.FormValue("reason")
	if reason == "" {
		reason = "manual"
	}

	var expires *time.Time
	switch r.FormValue("duration") {
	case "24h":
		t := time.Now().Add(24 * time.Hour)
		expires = &t
	case "168h":
		t := time.Now().Add(7 * 24 * time.Hour)
		expires = &t
	case "720h":
		t := time.Now().Add(30 * 24 * time.Hour)
		expires = &t
	}

	_, err := s.store.InsertSuppression(r.Context(), models.Suppression{
		Email:     value,
		Reason:    reason,
		Source:    "admin",
		Direction: direction,
		MatchType: matchType,
		ExpiresAt: expires,
	})
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	s.requestSync("suppressions.change")
	w.Header().Set("HX-Redirect", "/suppressions?flash="+encodeFlash("Suppressed "+value))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSuppressionDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid suppression ID")
		return
	}
	if err := s.store.DeleteSuppression(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	s.requestSync("suppressions.change")
	w.Header().Set("HX-Redirect", "/suppressions?flash="+encodeFlash("Suppression removed"))
	w.WriteHeader(http.StatusOK)
}

// ---- Deliverability --------------------------------------------------------

func (s *Server) handleDeliverabilityPage(w http.ResponseWriter, r *http.Request) {
	days := deliverabilityDays(r)

	metrics, err := s.store.Deliverability(r.Context(), time.Now().AddDate(0, 0, -days))
	if err != nil {
		s.renderError(w, 500, "Failed to load deliverability")
		return
	}

	// The per-account breakdown is a heavy aggregate on busy servers, so it is
	// loaded lazily by its own fragment (see handleDeliverabilityAccounts) and
	// no longer blocks this page from rendering.
	summary := summarizeDeliverability(metrics, nil)

	s.render(w, http.StatusOK, "deliverability.html", s.newPageData(w, r, "Deliverability", "deliverability", map[string]any{
		"Summary": summary,
		"Days":    days,
	}))
}

// deliverabilityDays reads and clamps the ?days= query parameter (default 30,
// max 90).
func deliverabilityDays(r *http.Request) int {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}
	return days
}

// handleDeliverabilityAccounts renders the "By sending account" fragment for the
// deliverability page. It is a separate route so a slow aggregate cannot time
// out the whole page: the page loads first and this fragment fills in after.
func (s *Server) handleDeliverabilityAccounts(w http.ResponseWriter, r *http.Request) {
	since := time.Now().AddDate(0, 0, -deliverabilityDays(r))

	accounts, err := s.store.DeliverabilityByAccount(r.Context(), since)
	if err != nil {
		s.renderPartial(w, "deliverability_accounts", map[string]any{
			"Accounts": []delivAccount{},
			"Error":    "The per-account breakdown failed to load.",
		})
		return
	}

	out := make([]delivAccount, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, delivAccount{Account: a.Account, Sent: a.Sent, Bounced: a.Bounced, Deferred: a.Deferred})
	}

	s.renderPartial(w, "deliverability_accounts", map[string]any{"Accounts": out})
}

// delivSummary is the shape the deliverability page renders.
type delivSummary struct {
	Sent         int64
	Bounced      int64
	Deferred     int64
	Total        int64
	BounceRate   float64
	DeferralRate float64
	ByDomain     []delivDomain
	ByAccount    []delivAccount
}

type delivDomain struct {
	Domain   string
	Sent     int64
	Bounced  int64
	Deferred int64
}

type delivAccount struct {
	Account  string
	Sent     int64
	Bounced  int64
	Deferred int64
}

func summarizeDeliverability(metrics []store.DeliverabilityMetric, accounts []store.DeliverabilityAccount) delivSummary {
	var out delivSummary
	totals := map[string]int64{}
	byDomain := map[string]map[string]int64{}

	for _, m := range metrics {
		totals[m.Status] += m.Count
		if byDomain[m.Domain] == nil {
			byDomain[m.Domain] = map[string]int64{}
		}
		byDomain[m.Domain][m.Status] += m.Count
	}

	out.Sent = totals["sent"]
	out.Bounced = totals["bounced"]
	out.Deferred = totals["deferred"]
	out.Total = out.Sent + out.Bounced + out.Deferred

	if out.Sent+out.Bounced > 0 {
		out.BounceRate = float64(out.Bounced) / float64(out.Sent+out.Bounced) * 100
	}
	if out.Sent+out.Deferred > 0 {
		out.DeferralRate = float64(out.Deferred) / float64(out.Sent+out.Deferred) * 100
	}

	for d, m := range byDomain {
		out.ByDomain = append(out.ByDomain, delivDomain{
			Domain:   d,
			Sent:     m["sent"],
			Bounced:  m["bounced"],
			Deferred: m["deferred"],
		})
	}
	sort.Slice(out.ByDomain, func(i, j int) bool {
		return out.ByDomain[i].Sent > out.ByDomain[j].Sent
	})

	for _, a := range accounts {
		out.ByAccount = append(out.ByAccount, delivAccount{
			Account:  a.Account,
			Sent:     a.Sent,
			Bounced:  a.Bounced,
			Deferred: a.Deferred,
		})
	}

	return out
}

// ---- Blocklists ------------------------------------------------------------

func (s *Server) handleBlocklistsPage(w http.ResponseWriter, r *http.Request) {
	status, err := s.store.LatestBlocklistStatus(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load blocklist status")
		return
	}
	s.render(w, http.StatusOK, "blocklists.html", s.newPageData(w, r, "Blocklists", "blocklists", map[string]any{
		"Checks": status,
	}))
}

// ---- Outbound IPs ----------------------------------------------------------

func (s *Server) handleOutboundIPsPage(w http.ResponseWriter, r *http.Request) {
	ips, err := s.store.ListOutboundIPs(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load outbound IPs")
		return
	}
	s.render(w, http.StatusOK, "outbound_ips.html", s.newPageData(w, r, "Outbound IPs", "outbound-ips", map[string]any{
		"IPs":       ips,
		"Available": discoverServerIPs(ips),
	}))
}

func (s *Server) handleOutboundIPCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}
	ip := strings.TrimSpace(r.FormValue("ip"))
	mode := r.FormValue("mode")
	if mode == "" {
		mode = models.IPModeDisabled
	}
	priority, _ := strconv.Atoi(r.FormValue("priority"))

	if _, err := s.store.InsertOutboundIP(r.Context(), models.OutboundIP{
		IP:       ip,
		Mode:     mode,
		Priority: priority,
		Active:   true,
	}); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	s.requestSync("outbound-ip.create")
	w.Header().Set("HX-Redirect", "/system/outbound-ips?flash="+encodeFlash("Outbound IP added"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleOutboundIPUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid IP ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}
	mode := r.FormValue("mode")
	priority, _ := strconv.Atoi(r.FormValue("priority"))
	active := r.FormValue("active") == "on" || r.FormValue("active") == "1"

	if err := s.store.UpdateOutboundIP(r.Context(), models.OutboundIP{
		ID:       id,
		Mode:     mode,
		Priority: priority,
		Active:   active,
	}); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	s.requestSync("outbound-ip.update")
	w.Header().Set("HX-Redirect", "/system/outbound-ips?flash="+encodeFlash("Outbound IP updated"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleOutboundIPDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid IP ID")
		return
	}
	if err := s.store.DeleteOutboundIP(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	s.requestSync("outbound-ip.delete")
	w.Header().Set("HX-Redirect", "/system/outbound-ips?flash="+encodeFlash("Outbound IP removed"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleOutboundRuleCreate(w http.ResponseWriter, r *http.Request) {
	ipID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid IP ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}
	if _, err := s.store.InsertOutboundRule(r.Context(), models.OutboundRule{
		IPID:       ipID,
		MatchType:  r.FormValue("match_type"),
		MatchValue: strings.TrimSpace(r.FormValue("match_value")),
	}); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	s.requestSync("outbound-rule.create")
	w.Header().Set("HX-Redirect", "/system/outbound-ips?flash="+encodeFlash("Routing rule added"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleOutboundRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid rule ID")
		return
	}
	if err := s.store.DeleteOutboundRule(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	s.requestSync("outbound-rule.delete")
	w.Header().Set("HX-Redirect", "/system/outbound-ips?flash="+encodeFlash("Routing rule removed"))
	w.WriteHeader(http.StatusOK)
}

// discoverServerIPs lists the host's non-loopback IPv4 addresses that are not
// already in the registry, for the "add" dropdown on the outbound IPs page.
func discoverServerIPs(registered []models.OutboundIP) []string {
	known := map[string]bool{}
	for _, ip := range registered {
		known[ip.IP] = true
	}

	var out []string
	for _, ip := range dns.LocalIPv4s() {
		if !known[ip] {
			out = append(out, ip)
		}
	}
	return out
}

// ---- API keys & webhooks ---------------------------------------------------

func (s *Server) handleAPISettingsPage(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAPIKeys(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load API keys")
		return
	}
	hooks, err := s.store.ListWebhooks(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load webhooks")
		return
	}
	s.render(w, http.StatusOK, "api_settings.html", s.newPageData(w, r, "API & Webhooks", "api", map[string]any{
		"Keys":                 keys,
		"Webhooks":             hooks,
		"TransactionalEnabled": s.transactionalEnabled(),
	}))
}

func (s *Server) handleAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.renderFormError(w, "Name is required")
		return
	}

	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	key := "mx_" + hex.EncodeToString(raw)

	_, err := s.store.InsertAPIKey(r.Context(), models.APIKey{
		Name:    name,
		Prefix:  key[:10],
		KeyHash: hashAPIKey(key),
		Scopes:  "read",
		Active:  true,
	})
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	// Show the plaintext exactly once.
	s.renderPartial(w, "api_key_reveal", map[string]any{"Key": key, "Name": name})
}

func (s *Server) handleAPIKeyDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid API key ID")
		return
	}
	if err := s.store.DeleteAPIKey(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/settings/api?flash="+encodeFlash("API key deleted"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleWebhookCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}
	url := strings.TrimSpace(r.FormValue("url"))
	if url == "" {
		s.renderFormError(w, "URL is required")
		return
	}
	events := strings.FieldsFunc(r.FormValue("events"), func(c rune) bool { return c == ',' || c == ' ' })
	secret := r.FormValue("secret")

	if _, err := s.store.InsertWebhook(r.Context(), models.Webhook{
		URL:    url,
		Events: events,
		Secret: secret,
		Active: true,
	}); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/settings/api?flash="+encodeFlash("Webhook added"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleWebhookDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid webhook ID")
		return
	}
	if err := s.store.DeleteWebhook(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/settings/api?flash="+encodeFlash("Webhook deleted"))
	w.WriteHeader(http.StatusOK)
}

// requestSync queues a reconciler run after a store mutation. It is nil-safe so
// handlers stay testable without a live syncer.
func (s *Server) requestSync(reason string) {
	if s.syncer != nil {
		s.syncer.Request(reason)
	}
}
