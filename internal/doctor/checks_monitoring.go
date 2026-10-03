package doctor

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// blocklistCheck reports whether any outbound IP is currently listed on a DNSBL.
// A listing is a Warn, not a Fail: the server still delivers, but its reputation
// is at risk.
func blocklistCheck(ctx context.Context, opts Options) Check {
	if opts.Store == nil {
		return Check{}
	}
	statuses, err := opts.Store.LatestBlocklistStatus(ctx)
	if err != nil {
		return Check{Name: "blocklists", Status: Warn, Detail: "could not read blocklist status: " + err.Error()}
	}
	return blocklistCheckFrom(statuses)
}

// blocklistCheckFrom is the pure decision behind blocklistCheck, so it can be
// tested without a database.
func blocklistCheckFrom(statuses []models.BlocklistCheck) Check {
	listed := map[string][]string{} // ip -> list names
	for _, s := range statuses {
		if s.Status == "listed" {
			listed[s.IP] = append(listed[s.IP], s.List)
		}
	}
	if len(listed) == 0 {
		return Check{Name: "blocklists", Status: OK, Detail: fmt.Sprintf("%d blocklist check(s), no listings", len(statuses))}
	}

	ips := make([]string, 0, len(listed))
	for ip := range listed {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip+" ("+strings.Join(listed[ip], ", ")+")")
	}
	return Check{
		Name:   "blocklists",
		Status: Warn,
		Detail: "listed: " + strings.Join(parts, "; "),
		Hint:   "an outbound IP is on a DNS blocklist; delist it or route mail via a clean address",
	}
}

// ptrCheck reports active outbound IPs without a verified PTR record. A missing
// record is a Warn (many receivers reject mail from addresses without one); an
// IP the daily job has not checked yet is only Info.
func ptrCheck(ctx context.Context, opts Options) Check {
	if opts.Store == nil {
		return Check{}
	}
	ips, err := opts.Store.ListOutboundIPs(ctx)
	if err != nil {
		return Check{Name: "outbound IP PTR", Status: Warn, Detail: "could not read outbound IPs: " + err.Error()}
	}
	return ptrCheckFrom(ips)
}

// ptrCheckFrom is the pure decision behind ptrCheck.
func ptrCheckFrom(ips []models.OutboundIP) Check {
	var missing, unchecked []string
	for _, ip := range ips {
		if !ip.Active {
			continue
		}
		if ip.PTROK == nil {
			unchecked = append(unchecked, ip.IP)
		} else if !*ip.PTROK {
			missing = append(missing, ip.IP)
		}
	}
	sort.Strings(missing)
	sort.Strings(unchecked)

	switch {
	case len(missing) > 0:
		return Check{
			Name:   "outbound IP PTR",
			Status: Warn,
			Detail: "missing PTR: " + strings.Join(missing, ", "),
			Hint:   "many receivers reject mail from addresses without a reverse record",
		}
	case len(unchecked) > 0:
		return Check{
			Name:   "outbound IP PTR",
			Status: Info,
			Detail: "PTR not yet checked for: " + strings.Join(unchecked, ", "),
			Hint:   "the daily PTR job has not run yet",
		}
	default:
		return Check{Name: "outbound IP PTR", Status: OK, Detail: "every active outbound IP has a PTR record"}
	}
}
