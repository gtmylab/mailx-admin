package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Blocklist is a DNSBL zone the panel checks outbound IPs against.
type Blocklist struct {
	Name string
	Zone string
}

// DefaultBlocklists are the public DNSBLs checked hourly by the blocklist job.
var DefaultBlocklists = []Blocklist{
	{Name: "Spamhaus ZEN", Zone: "zen.spamhaus.org"},
	{Name: "Barracuda", Zone: "b.barracudacentral.org"},
	{Name: "SpamCop", Zone: "bl.spamcop.net"},
	{Name: "SORBS", Zone: "dnsbl.sorbs.net"},
	{Name: "UCEPROTECT L1", Zone: "dnsbl-1.uceprotect.net"},
	{Name: "UCEPROTECT L2", Zone: "dnsbl-2.uceprotect.net"},
	{Name: "UCEPROTECT L3", Zone: "dnsbl-3.uceprotect.net"},
	{Name: "CBL (Abusix)", Zone: "cbl.abuseat.org"},
	{Name: "PSBL", Zone: "psbl.surriel.com"},
	{Name: "SURBL multi", Zone: "multi.surbl.org"},
	{Name: "SpamRATS NoPTR", Zone: "noptr.spamrats.com"},
	{Name: "DroneBL", Zone: "dnsbl.dronebl.org"},
	{Name: "JustSpam", Zone: "dnsbl.justspam.org"},
	{Name: "GBUdb", Zone: "truncate.gbudb.net"},
}

// blocklistQueryName builds the DNS name to look up for an IP in a zone: the
// IPv4 octets reversed, then the zone appended (e.g. 1.2.3.4 →
// 4.3.2.1.zen.spamhaus.org). Pure so it is testable without a resolver.
func blocklistQueryName(ip, zone string) (string, error) {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return "", fmt.Errorf("cannot use %q for DNSBL: want an IPv4 address", ip)
	}
	return fmt.Sprintf("%d.%d.%d.%d.%s", v4[3], v4[2], v4[1], v4[0], zone), nil
}

// CheckBlocklist queries one DNSBL zone for ip and reports whether the IP is
// listed, with the list's own reason (the TXT record) when available.
func CheckBlocklist(ctx context.Context, resolver, zone, ip string) (listed bool, detail string, err error) {
	name, err := blocklistQueryName(ip, zone)
	if err != nil {
		return false, "", err
	}

	client := &dns.Client{}
	a := new(dns.Msg)
	a.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp, _, err := client.ExchangeContext(ctx, a, resolver)
	if err != nil {
		return false, "", err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false, "", fmt.Errorf("DNS response code: %s", dns.RcodeToString[resp.Rcode])
	}

	listed = false
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.A); ok {
			listed = true
			break
		}
	}
	if !listed {
		return false, "", nil
	}

	// Listed — pull the TXT record for the reason.
	txt := new(dns.Msg)
	txt.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	if tresp, _, err := client.ExchangeContext(ctx, txt, resolver); err == nil && tresp.Rcode == dns.RcodeSuccess {
		var parts []string
		for _, rr := range tresp.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				parts = append(parts, strings.Join(t.Txt, ""))
			}
		}
		detail = strings.Join(parts, " ")
	}
	return true, detail, nil
}
