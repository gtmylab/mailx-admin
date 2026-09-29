package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/dns"
	"github.com/gtmylab/mailx-admin/internal/models"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleDomainDNS renders the DNS tab for a domain: every record it needs, with
// the result of the last check next to it.
func (s *Server) handleDomainDNS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	domain, err := s.getDomainByID(ctx, id)
	if err != nil {
		s.renderError(w, 404, "Domain not found")
		return
	}

	page := s.buildDNSPage(domain, s.serverIP(ctx), s.cfg.Server.Hostname, s.loadCachedDNSChecks(ctx, id))

	s.render(w, 200, "domain_dns.html", s.newPageData(w, r,
		"DNS · "+domain.Name, "domains", page))
}

// handleDomainDNSCheck runs a fresh check and returns the table with the results
// filled in. `?only=<purpose>` checks a single record, for the per-row buttons.
func (s *Server) handleDomainDNSCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	domain, err := s.getDomainByID(ctx, id)
	if err != nil {
		s.renderError(w, 404, "Domain not found")
		return
	}

	plan := dns.BuildPlan(*domain, s.serverIP(ctx), s.cfg.Server.Hostname)
	expected := plan.Checkable()
	if only := r.URL.Query().Get("only"); only != "" {
		filtered := make([]dns.Expected, 0, 1)
		for _, e := range expected {
			if e.Purpose == only {
				filtered = append(filtered, e)
			}
		}
		expected = filtered
	}

	checker := dns.NewChecker(s.cfg.DNS.Resolver)
	results := checker.Check(ctx, expected)
	dns.SortResults(results)

	// Persist for the page's next render, merging with the other records' cached
	// rows so a per-row check does not wipe the rest.
	s.saveDNSChecks(ctx, id, mergeChecks(s.loadCachedDNSChecks(ctx, id), results, expected))

	page := s.buildDNSPage(domain, s.serverIP(ctx), s.cfg.Server.Hostname,
		mergeChecks(s.loadCachedDNSChecks(ctx, id), results, expected))

	s.renderPartial(w, "dns_check_results", page)
}

// mergeChecks overlays freshly checked results over the cached ones: everything
// that was just checked wins, everything else keeps its previous status.
func mergeChecks(cached, fresh []dns.CheckResult, checked []dns.Expected) []dns.CheckResult {
	replaced := map[string]bool{}
	for _, e := range checked {
		replaced[checkKey(e)] = true
	}

	out := make([]dns.CheckResult, 0, len(cached)+len(fresh))
	for _, c := range cached {
		if !replaced[checkKey(c.Expected)] {
			out = append(out, c)
		}
	}
	return append(out, fresh...)
}

// handleDomainDNSCopy exports the same records the page shows, as a zone-file
// shaped text block. It used to be built separately from the page, which is why
// the two could disagree.
func (s *Server) handleDomainDNSCopy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	domain, err := s.getDomainByID(ctx, id)
	if err != nil {
		s.renderError(w, 404, "Domain not found")
		return
	}

	plan := dns.BuildPlan(*domain, s.serverIP(ctx), s.cfg.Server.Hostname)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		`attachment; filename="%s-dns-records.txt"`, domain.Name))

	fmt.Fprintf(w, "# DNS records for %s\n", domain.Name)
	fmt.Fprintf(w, "# Generated %s by MailX Admin\n", time.Now().Format(time.RFC3339))
	if plan.ServerIP != "" {
		fmt.Fprintf(w, "# This server's public IP: %s\n", plan.ServerIP)
	}
	for _, warn := range plan.Warnings {
		fmt.Fprintf(w, "# WARNING: %s\n", warn)
	}
	fmt.Fprintf(w, "\n# %-8s %-38s %s\n", "TYPE", "NAME", "VALUE")
	for _, rec := range plan.Records {
		if rec.Later {
			continue
		}
		fmt.Fprintf(w, "%s\n", rec.Describe())
		if rec.Note != "" {
			fmt.Fprintf(w, "#    %s\n", rec.Note)
		}
	}

	var later []dns.Record
	for _, rec := range plan.Records {
		if rec.Later {
			later = append(later, rec)
		}
	}
	if len(later) > 0 {
		fmt.Fprintf(w, "\n# Recommended later (not required for mail to flow):\n")
		for _, rec := range later {
			fmt.Fprintf(w, "%s\n", rec.Describe())
		}
	}
}

// handleServerIPSave stores the operator's answer for "what is this server's
// public IP?", which is what the plan needs when auto-detection fails (a NATed
// network, no outbound HTTPS).
func (s *Server) handleServerIPSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	ip := strings.TrimSpace(r.FormValue("server_ip"))
	if ip != "" && net.ParseIP(ip) == nil {
		s.renderFormError(w, "That is not a valid IP address.")
		return
	}

	ctx := r.Context()
	if ip == "" {
		_, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = 'server_ip'`)
		if err != nil {
			s.renderFormError(w, "Could not clear the address: "+err.Error())
			return
		}
	} else {
		if _, err := s.db.ExecContext(ctx, `
            INSERT INTO settings (key, value) VALUES ('server_ip', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        `, ip); err != nil {
			s.renderFormError(w, "Could not save the address: "+err.Error())
			return
		}
	}

	_ = s.auditor.Log(ctx, audit.Entry{
		Actor:    s.actorName(r),
		Action:   "dns.server_ip",
		Result:   "ok",
		Detail:   map[string]any{"server_ip": ip},
		RemoteIP: clientIP(r),
	})

	target := "/"
	if id := r.FormValue("domain_id"); id != "" {
		target = "/domains/" + id + "/dns"
	}
	w.Header().Set("HX-Redirect", target+"?flash="+encodeFlash("Mail server address saved"))
	w.WriteHeader(http.StatusOK)
}

// ---- helpers ----

func (s *Server) getDomainByID(ctx context.Context, id int64) (*models.Domain, error) {
	var d models.Domain
	var isPrimary, active int
	var dkimCreated sql.NullTime
	var dkimPriv, dkimPub sql.NullString

	err := s.db.QueryRowContext(ctx, `
        SELECT id, name, is_primary, dkim_selector,
               dkim_private_key_path, dkim_public_record,
               dkim_created_at, active, created_at, updated_at
        FROM domains WHERE id = ?
    `, id).Scan(
		&d.ID, &d.Name, &isPrimary, &d.DKIMSelector,
		&dkimPriv, &dkimPub, &dkimCreated, &active, &d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	d.IsPrimary = isPrimary == 1
	d.Active = active == 1
	d.DKIMPrivateKeyPath = dkimPriv.String
	d.DKIMPublicRecord = dkimPub.String
	if dkimCreated.Valid {
		d.DKIMCreatedAt = &dkimCreated.Time
	}
	return &d, nil
}

// serverIP answers "what is this server's public IP?" — the DNS plan cannot do
// anything useful without an answer, and the previous implementation simply
// returned "" when its HTTPS probe failed, which produced records like
// "A  mail.example.com  " and "v=spf1 mx a ip4: ~all".
//
// Order:
//  1. the operator's explicit value (settings.server_ip) — the only source that
//     works behind NAT or without outbound HTTPS,
//  2. the detected public address, remembered in settings afterwards,
//  3. the address this server's own host name resolves to (on most installs the
//     mail host name is in public DNS),
//  4. the first global unicast address on a non-loopback interface.
func (s *Server) serverIP(ctx context.Context) string {
	var stored string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'server_ip'`).Scan(&stored)
	if ip := net.ParseIP(strings.TrimSpace(stored)); ip != nil {
		// An explicit value wins even when it is not a public address: some
		// installations deliver mail on a private network on purpose.
		return ip.String()
	}

	if detected := detectPublicIP(ctx); detected != "" {
		_, _ = s.db.ExecContext(ctx, `
            INSERT INTO settings (key, value) VALUES ('server_ip', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
        `, detected)
		return detected
	}

	if ip := hostnameAddress(ctx, s.cfg.Server.Hostname); ip != "" {
		return ip
	}
	return localAddress()
}

// hostnameAddress resolves the server's own name: on most installs the mail host
// name is the one published in DNS, so its A record is the answer.
func hostnameAddress(ctx context.Context, hostname string) string {
	if hostname == "" {
		return ""
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, hostname)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// localAddress is the last resort: the first global unicast address of a
// non-loopback interface, which on a single-NIC VPS is the public address.
func localAddress() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			return v4.String()
		}
	}
	return ""
}

func detectPublicIP(ctx context.Context) string {
	// Try a few well-known endpoints
	for _, url := range []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	} {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body := make([]byte, 64)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		if n > 0 {
			ip := strings.TrimSpace(string(body[:n]))
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	return ""
}

func (s *Server) saveDNSChecks(ctx context.Context, domainID int64, results []dns.CheckResult) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()

	// Clear old, write fresh
	_, _ = tx.ExecContext(ctx, `DELETE FROM dns_checks WHERE domain_id = ?`, domainID)

	for _, r := range results {
		var observed string
		if r.Observed != nil {
			b, _ := json.Marshal(r.Observed.Values)
			observed = string(b)
		}
		_, _ = tx.ExecContext(ctx, `
            INSERT INTO dns_checks
              (domain_id, record_type, record_name, expected_value, observed_value, status, message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, domainID, string(r.Expected.Type), r.Expected.Name, r.Expected.Value,
			observed, r.Status, r.Message)
	}
	tx.Commit()
}

func (s *Server) loadCachedDNSChecks(ctx context.Context, domainID int64) []dns.CheckResult {
	rows, err := s.db.QueryContext(ctx, `
        SELECT record_type, record_name, expected_value, observed_value, status, message
        FROM dns_checks WHERE domain_id = ? ORDER BY id
    `, domainID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []dns.CheckResult
	for rows.Next() {
		var rt, name, expected, observed, status, message string
		if err := rows.Scan(&rt, &name, &expected, &observed, &status, &message); err != nil {
			continue
		}
		res := dns.CheckResult{
			Expected: dns.Expected{
				Type:  dns.RecordType(rt),
				Name:  name,
				Value: expected,
			},
			Status:  status,
			Message: message,
		}
		if observed != "" {
			var values []string
			if err := json.Unmarshal([]byte(observed), &values); err == nil {
				res.Observed = &dns.Observed{Values: values}
			}
		}
		out = append(out, res)
	}
	return out
}
