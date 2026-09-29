package server

import (
	"fmt"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/dns"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// dnsRow is one line of the DNS page: a record to create, plus what public DNS
// says about it right now. The page renders the expected records and their
// status in the same table — v1.0.4 showed the cached check results only, so a
// domain that had never been checked (or whose cached rows were from an older
// layout) showed nothing to create at all.
type dnsRow struct {
	Purpose  string
	Type     string
	Name     string
	Value    string
	Priority int
	Note     string
	Required bool
	Manual   bool
	Status   string // ok | mismatch | missing | error | unchecked | manual
	Message  string
	Observed []string
}

// dnsPage is the data both the DNS page and the check fragment render from.
type dnsPage struct {
	Domain   *models.Domain
	ServerIP string
	MailHost string
	Hostname string
	Rows     []dnsRow
	Later    []dnsRow
	Warnings []string

	Verdict  string // ok | warn | err | info
	Summary  string
	Checked  bool
	CheckAge string
}

// buildDNSPage merges the record plan with the (possibly empty) check results.
func (s *Server) buildDNSPage(domain *models.Domain, serverIP, hostname string, checks []dns.CheckResult) *dnsPage {
	plan := dns.BuildPlan(*domain, serverIP, hostname)

	page := &dnsPage{
		Domain:   domain,
		ServerIP: plan.ServerIP,
		MailHost: plan.MailHost(),
		Hostname: hostname,
		Warnings: plan.Warnings,
	}

	byKey := make(map[string]dns.CheckResult, len(checks))
	for _, c := range checks {
		byKey[checkKey(c.Expected)] = c
	}

	var missingRequired, badRequired, uncheckedRequired []string
	for _, r := range plan.Records {
		row := dnsRow{
			Purpose:  r.Purpose,
			Type:     string(r.Type),
			Name:     r.Name,
			Value:    r.Value,
			Priority: r.Priority,
			Note:     r.Note,
			Required: r.Required,
			Manual:   r.Manual,
		}

		switch {
		case !r.Checkable && r.Manual:
			row.Status = "manual"
			row.Message = "Only your hosting provider can set this record."
		case !r.Checkable:
			row.Status = "unchecked"
		default:
			if res, ok := byKey[checkKey(r.Expected)]; ok {
				page.Checked = true
				row.Status = res.Status
				row.Message = res.Message
				if res.Observed != nil {
					row.Observed = res.Observed.Values
				}
			} else {
				row.Status = "unchecked"
				if r.Required {
					uncheckedRequired = append(uncheckedRequired, r.Name)
				}
			}
		}

		if r.Required {
			switch row.Status {
			case "mismatch", "missing", "error":
				badRequired = append(badRequired, r.Purpose)
			}
			if !r.Checkable {
				missingRequired = append(missingRequired, r.Purpose)
			}
		}

		if r.Later {
			page.Later = append(page.Later, row)
			continue
		}
		page.Rows = append(page.Rows, row)
	}

	page.Verdict, page.Summary = verdict(page, badRequired, uncheckedRequired, missingRequired)
	return page
}

// verdict turns the row statuses into one sentence an operator can act on.
func verdict(page *dnsPage, bad, unchecked, manual []string) (string, string) {
	switch {
	case len(bad) > 0:
		return "err", fmt.Sprintf(
			"%s missing or wrong. Mail for %s is not reliable until %s fixed.",
			joinList(bad), page.Domain.Name, plural(len(bad), "it is", "they are"))
	case len(manual) > 0:
		return "warn", fmt.Sprintf(
			"The records the panel can verify are in place. %s still has to be set by your hosting provider (see the note in the table).",
			joinList(manual))
	case !page.Checked:
		return "info", "Nothing has been verified yet. Add the records below, then press “Verify DNS”."
	case len(unchecked) > 0:
		return "warn", "Some records have not been verified yet: " + joinList(unchecked) + "."
	}
	return "ok", "Every record the panel checked matches, including the reverse DNS entry."
}

func checkKey(e dns.Expected) string {
	return fmt.Sprintf("%s|%s|%s", e.Type, e.Name, e.Value)
}

func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
