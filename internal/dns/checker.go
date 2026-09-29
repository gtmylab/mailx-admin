package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeCNAME RecordType = "CNAME"
	TypePTR   RecordType = "PTR"
)

// Expected is a record we want to exist for a domain.
type Expected struct {
	Type     RecordType
	Name     string // FQDN, no trailing dot
	Value    string
	Priority int    // for MX
	Purpose  string // human label: "DKIM", "SPF", "DMARC", "MX"
	Required bool
}

// Observed is what we found in DNS.
type Observed struct {
	Type   RecordType
	Name   string
	Values []string
	TTL    uint32
}

// CheckResult compares expected vs observed.
type CheckResult struct {
	Expected Expected
	Observed *Observed
	Status   string // ok, missing, mismatch, error
	Message  string
}

// Checker performs live DNS lookups.
type Checker struct {
	resolver string // e.g. "1.1.1.1:53", empty = system default
	timeout  time.Duration
}

func NewChecker(resolver string) *Checker {
	if resolver == "" {
		resolver = "1.1.1.1:53"
	}
	return &Checker{
		resolver: resolver,
		timeout:  5 * time.Second,
	}
}

// Check queries DNS for each expected record and returns results.
// Runs lookups in parallel with a bounded concurrency.
func (c *Checker) Check(ctx context.Context, expected []Expected) []CheckResult {
	results := make([]CheckResult, len(expected))

	// Simple bounded concurrency: 5 at a time
	sem := make(chan struct{}, 5)
	done := make(chan int, len(expected))

	for i, exp := range expected {
		i, exp := i, exp
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = c.checkOne(ctx, exp)
			done <- i
		}()
	}

	for range expected {
		<-done
	}
	return results
}

func (c *Checker) checkOne(ctx context.Context, exp Expected) CheckResult {
	res := CheckResult{Expected: exp}

	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var (
		obs *Observed
		err error
	)

	switch exp.Type {
	case TypeA, TypeAAAA, TypeCNAME:
		obs, err = c.lookupSingle(queryCtx, exp.Name, exp.Type)
	case TypeMX:
		obs, err = c.lookupMX(queryCtx, exp.Name)
	case TypeTXT:
		obs, err = c.lookupTXT(queryCtx, exp.Name)
	case TypePTR:
		obs, err = c.lookupPTR(queryCtx, exp.Name)
	}

	if err != nil {
		res.Status = "error"
		res.Message = err.Error()
		return res
	}

	res.Observed = obs

	if obs == nil || len(obs.Values) == 0 {
		if exp.Required {
			res.Status = "missing"
			res.Message = "no record found"
		} else {
			res.Status = "ok"
			res.Message = "optional record not present (ok)"
		}
		return res
	}

	// Compare values
	if ok, detail := matchRecord(exp, obs); ok {
		res.Status = "ok"
		res.Message = "matches"
		return res
	} else {
		res.Status = "mismatch"
		res.Message = detail
		return res
	}
}

func (c *Checker) lookupSingle(ctx context.Context, name string, t RecordType) (*Observed, error) {
	// Prefer the custom resolver
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: c.timeout}
			return d.DialContext(ctx, "udp", c.resolver)
		},
	}

	var ips []string
	var err error
	switch t {
	case TypeA:
		ips, err = r.LookupHost(ctx, name)
	case TypeAAAA:
		ips, err = r.LookupHost(ctx, name)
	case TypeCNAME:
		cname, e := r.LookupCNAME(ctx, name)
		if e != nil {
			return nil, e
		}
		ips = []string{cname}
	}

	if err != nil {
		if isNXDomain(err) {
			return nil, nil
		}
		return nil, err
	}
	return &Observed{Type: t, Name: name, Values: ips}, nil
}

func (c *Checker) lookupMX(ctx context.Context, name string) (*Observed, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeMX)

	client := &dns.Client{Timeout: c.timeout}
	resp, _, err := client.ExchangeContext(ctx, m, c.resolver)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response code: %s", dns.RcodeToString[resp.Rcode])
	}

	var values []string
	var minTTL uint32
	for _, rr := range resp.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			values = append(values, fmt.Sprintf("%d %s", mx.Preference, strings.TrimSuffix(mx.Mx, ".")))
			if minTTL == 0 || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}
	return &Observed{Type: TypeMX, Name: name, Values: values, TTL: minTTL}, nil
}

func (c *Checker) lookupTXT(ctx context.Context, name string) (*Observed, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)

	client := &dns.Client{Timeout: c.timeout}
	resp, _, err := client.ExchangeContext(ctx, m, c.resolver)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response code: %s", dns.RcodeToString[resp.Rcode])
	}

	var values []string
	var minTTL uint32
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			values = append(values, strings.Join(txt.Txt, ""))
			if minTTL == 0 || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}
	return &Observed{Type: TypeTXT, Name: name, Values: values, TTL: minTTL}, nil
}

// lookupPTR resolves a reverse zone. expected.Name is the reverse name
// (10.113.0.203.in-addr.arpa); an IP is accepted too, so a caller cannot get the
// spelling wrong.
func (c *Checker) lookupPTR(ctx context.Context, name string) (*Observed, error) {
	if ip := net.ParseIP(name); ip != nil {
		name = reverseAddr(ip.String())
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypePTR)

	client := &dns.Client{Timeout: c.timeout}
	resp, _, err := client.ExchangeContext(ctx, m, c.resolver)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response code: %s", dns.RcodeToString[resp.Rcode])
	}

	var values []string
	var minTTL uint32
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			values = append(values, strings.TrimSuffix(ptr.Ptr, "."))
			if minTTL == 0 || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}
	return &Observed{Type: TypePTR, Name: strings.TrimSuffix(name, "."), Values: values, TTL: minTTL}, nil
}

func normalizeTXT(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	// Collapse multiple spaces into one
	return strings.Join(strings.Fields(s), " ")
}

func isNXDomain(err error) bool {
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}
	return false
}

// SortResults orders results for display: errors, mismatches, missing, ok.
func SortResults(results []CheckResult) {
	order := map[string]int{"error": 0, "mismatch": 1, "missing": 2, "ok": 3}
	sort.SliceStable(results, func(i, j int) bool {
		return order[results[i].Status] < order[results[j].Status]
	})
}
