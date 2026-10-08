package dns

import (
	"fmt"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// unknownIP is what the panel puts in an A or SPF record when it cannot work out
// the server's public IP. It is deliberately not an empty string: printing
// "A  mail.example.com  " is how the previous release produced records that
// looked complete and were not.
const unknownIP = "<this server's public IP>"

// Record is one DNS record the panel wants the operator to create.
type Record struct {
	Type     RecordType `json:"type"`
	Name     string     `json:"name"` // FQDN, no trailing dot
	Value    string     `json:"value"`
	Priority int        `json:"priority,omitempty"` // MX only
	Purpose  string     `json:"purpose"`
	Note     string     `json:"note,omitempty"`

	// Required: mail does not work without it. Recommended records are amber.
	Required bool `json:"required"`

	// Checkable: the panel can query public DNS for it and say whether it
	// matches. PTR lives in a zone this server does not control, and the
	// "later" records are not part of the check yet.
	Checkable bool `json:"checkable"`

	// Manual: the record cannot be created at the DNS provider at all (PTR is
	// set by whoever owns the IP).
	Manual bool `json:"manual"`

	// Later: recommended hardening that is not needed for mail to flow
	// (MTA-STS, TLS reporting). Shown separately so the checklist stays short.
	Later bool `json:"later"`

	// Expected is what the checker compares against, when Checkable.
	Expected Expected `json:"-"`
}

// RecordPlan is everything the panel knows about one domain's DNS needs. It is
// the single source for the DNS page, the .txt export and the live check, so the
// three can never disagree about which records are wanted — v1.0.4 had them only
// in the export, which is why the page showed no expected records at all.
type RecordPlan struct {
	Domain   string   `json:"domain"`
	Hostname string   `json:"hostname"` // this server's mail host name
	ServerIP string   `json:"server_ip"`
	Records  []Record `json:"records"`

	// Warnings explain why a plan is incomplete (an unknown public IP, a domain
	// without a DKIM key). The page shows them above the table.
	Warnings []string `json:"warnings"`
}

// MailHost is the host name mail for this domain is delivered to: the server's
// own mail host (its hostname, or whatever /etc/mailname resolves to), never a
// synthetic "mail.<domain>" the operator may not have an A record for.
func (p *RecordPlan) MailHost() string {
	if p.Hostname != "" {
		return p.Hostname
	}
	return "mail." + p.Domain
}

// Checkable returns the records the checker can verify.
func (p *RecordPlan) Checkable() []Expected {
	out := make([]Expected, 0, len(p.Records))
	for _, r := range p.Records {
		if r.Checkable {
			out = append(out, r.Expected)
		}
	}
	return out
}

// BuildExpected returns the records the checker verifies, derived from the plan
// so a check can never ask for a different set than the page shows.
func BuildExpected(domain models.Domain, serverIP, hostname string) []Expected {
	return BuildPlan(domain, serverIP, hostname).Checkable()
}

// Describe renders the record the way a DNS provider form asks for it.
func (r Record) Describe() string {
	if r.Type == TypeMX {
		return fmt.Sprintf("%s  MX  %d  %s", r.Name, r.Priority, r.Value)
	}
	return fmt.Sprintf("%s  %s  %s", r.Name, r.Type, r.Value)
}

// BuildPlan assembles the full record set for one domain: what has to exist for
// mail to flow at all (required), what is strongly recommended, what only the
// hosting provider can set (PTR) and what can wait.
func BuildPlan(domain models.Domain, serverIP, hostname string) *RecordPlan {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain.Name)), ".")
	serverIP = strings.TrimSpace(serverIP)

	plan := &RecordPlan{Domain: name, Hostname: hostname, ServerIP: serverIP}

	ip := serverIP
	if ip == "" {
		ip = unknownIP
		plan.Warnings = append(plan.Warnings,
			"The server's public IP could not be determined, so the A records and the SPF ip4: mechanism show a placeholder. Set it on this page, then check again.")
	}

	mail := plan.MailHost()
	add := func(r Record) { plan.Records = append(plan.Records, r) }

	// ---- A records ------------------------------------------------------
	add(Record{
		Type: TypeA, Name: name, Value: ip, Purpose: "Domain apex",
		Note:     "Points the domain itself at this server.",
		Required: true, Checkable: serverIP != "",
		Expected: Expected{Type: TypeA, Name: name, Value: serverIP, Purpose: "Domain apex", Required: true},
	})
	add(Record{
		Type: TypeA, Name: mail, Value: ip, Purpose: "Mail host",
		Note:     "The name the MX record points at.",
		Required: true, Checkable: serverIP != "",
		Expected: Expected{Type: TypeA, Name: mail, Value: serverIP, Purpose: "Mail host", Required: true},
	})

	// ---- MX -------------------------------------------------------------
	add(Record{
		Type: TypeMX, Name: name, Value: mail, Priority: 10, Purpose: "Inbound mail",
		Note:     "Tells the world where to deliver mail for " + name + ".",
		Required: true, Checkable: true,
		Expected: Expected{Type: TypeMX, Name: name, Value: mail, Priority: 10, Purpose: "Inbound mail", Required: true},
	})

	// ---- SPF ------------------------------------------------------------
	spf := "v=spf1 mx a"
	if serverIP != "" {
		spf += " ip4:" + serverIP
	}
	spf += " ~all"
	add(Record{
		Type: TypeTXT, Name: name, Value: spf, Purpose: "SPF (authorised senders)",
		Note:     "Without it, providers treat mail from this server as spam.",
		Required: true, Checkable: true,
		Expected: Expected{Type: TypeTXT, Name: name, Value: spf, Purpose: "SPF", Required: true},
	})

	// ---- DKIM -----------------------------------------------------------
	selector := domain.DKIMSelector
	if selector == "" {
		selector = "default"
	}
	dkimName := selector + "._domainkey." + name
	if domain.DKIMPublicRecord != "" {
		add(Record{
			Type: TypeTXT, Name: dkimName, Value: domain.DKIMPublicRecord, Purpose: "DKIM (selector " + selector + ")",
			Note:     "Signs outgoing mail with the key the panel generated for this domain.",
			Required: true, Checkable: true,
			Expected: Expected{Type: TypeTXT, Name: dkimName, Value: domain.DKIMPublicRecord, Purpose: "DKIM", Required: true},
		})
	} else {
		plan.Warnings = append(plan.Warnings,
			"This domain has no DKIM key yet, so there is no DKIM record to publish. Generate one on the domain page, then come back.")
		add(Record{
			Type: TypeTXT, Name: dkimName, Value: "(no key generated yet)", Purpose: "DKIM",
			Note: "Generate a key on the domain page first.", Required: true,
		})
	}

	// ---- DMARC ----------------------------------------------------------
	dmarc := fmt.Sprintf("v=DMARC1; p=quarantine; pct=100; rua=mailto:admin@%s; ruf=mailto:admin@%s; sp=quarantine; aspf=r; adkim=r", name, name)
	add(Record{
		Type: TypeTXT, Name: "_dmarc." + name,
		Value:    dmarc,
		Purpose:  "DMARC (policy + reports)",
		Note:     "Quarantines mail that fails DMARC and sends aggregate + forensic reports to admin@" + name + ".",
		Required: false, Checkable: true,
		Expected: Expected{Type: TypeTXT, Name: "_dmarc." + name, Value: dmarc, Purpose: "DMARC", Required: false},
	})

	// ---- PTR ------------------------------------------------------------
	if rev := reverseName(serverIP); rev != "" {
		add(Record{
			Type: TypePTR, Name: rev, Value: mail,
			Purpose: "PTR / reverse DNS (" + serverIP + ")",
			Note: "Only your hosting provider can set this: they own the reverse zone. Gmail and Outlook " +
				"reject or penalise mail from an IP whose PTR does not name the mail host.",
			Required: true, Checkable: true, Manual: true,
			Expected: Expected{Type: TypePTR, Name: rev, Value: mail, Purpose: "PTR", Required: true},
		})
	}

	// ---- Panel / webmail host (optional) --------------------------------
	add(Record{
		Type: TypeA, Name: "admin." + name, Value: ip, Purpose: "Panel or webmail host (admin." + name + ")",
		Note:     "Only needed if you reach this panel (or Roundcube) on its own name.",
		Required: false, Checkable: serverIP != "",
		Expected: Expected{Type: TypeA, Name: "admin." + name, Value: serverIP, Purpose: "Panel or webmail host", Required: false},
	})

	// ---- Recommended later ----------------------------------------------
	add(Record{
		Type: TypeTXT, Name: "_mta-sts." + name, Value: "v=STSv1; id=" + time.Now().UTC().Format("20060102150405"),
		Purpose: "MTA-STS (add later)",
		Note:    "Needs an HTTPS policy file at https://mta-sts." + name + "/.well-known/mta-sts.txt before it does anything.",
		Later:   true,
	})
	add(Record{
		Type: TypeTXT, Name: "_smtp._tls." + name, Value: "v=TLSRPTv1; rua=mailto:postmaster@" + name,
		Purpose: "TLS reporting (add later)",
		Note:    "Asks sending servers to report TLS problems to you.",
		Later:   true,
	})

	return plan
}

// reverseName turns an IP into its reverse-DNS name without the trailing dot.
func reverseName(ip string) string {
	return strings.TrimSuffix(reverseAddr(ip), ".")
}
