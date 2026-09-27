package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/dns"
	"github.com/gtmylab/mailx-admin/internal/models"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleDomainDNS renders the DNS tab for a domain.
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

	// Load last cached check
	cached := s.loadCachedDNSChecks(ctx, id)

	s.render(w, 200, "domain_dns.html", s.newPageData(w, r,
		"DNS · "+domain.Name, "domains",
		map[string]any{
			"Domain":   domain,
			"Checks":   cached,
			"ServerIP": s.serverIP(ctx),
		},
	))
}

// handleDomainDNSCheck runs a fresh check and returns the results partial.
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

	checker := dns.NewChecker(s.cfg.DNS.Resolver)
	expected := dns.BuildExpected(*domain, s.serverIP(ctx), s.cfg.Server.Hostname)
	results := checker.Check(ctx, expected)
	dns.SortResults(results)

	// Persist for caching
	s.saveDNSChecks(ctx, id, results)

	s.renderPartial(w, "dns_check_results", map[string]any{
		"Checks": results,
		"Domain": domain,
	})
}

// handleDomainDNSCopy returns a plain-text block of DNS records for the admin to paste.
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

	expected := dns.BuildExpected(*domain, s.serverIP(ctx), s.cfg.Server.Hostname)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		`attachment; filename="%s-dns-records.txt"`, domain.Name))

	fmt.Fprintf(w, "# DNS records for %s\n", domain.Name)
	fmt.Fprintf(w, "# Generated %s\n\n", time.Now().Format(time.RFC3339))
	for _, e := range expected {
		switch e.Type {
		case dns.TypeMX:
			fmt.Fprintf(w, "%s\t%d\tIN\t%s\t%s.\n", e.Name, e.Priority, e.Type, e.Value)
		case dns.TypeTXT:
			fmt.Fprintf(w, "%s\t3600\tIN\t%s\t\"%s\"\n", e.Name, e.Type, e.Value)
		default:
			fmt.Fprintf(w, "%s\t3600\tIN\t%s\t%s\n", e.Name, e.Type, e.Value)
		}
	}
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

// serverIP returns the public IP of this server, cached in settings.
func (s *Server) serverIP(ctx context.Context) string {
	var ip string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'server_ip'`).Scan(&ip)
	if ip != "" {
		return ip
	}

	// Look it up once and cache forever
	if detected := detectPublicIP(ctx); detected != "" {
		_, _ = s.db.ExecContext(ctx,
			`INSERT INTO settings (key, value) VALUES ('server_ip', ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value`, detected)
		return detected
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
