package dns

import (
	"context"
	"net"
	"sort"
	"time"
)

// LocalIPv4s returns the host's non-loopback IPv4 addresses, de-duplicated and
// sorted. It is the shared discovery step for the outbound-IPs page and the
// daily IP-discovery job: both need "which addresses does this host actually
// have" answered in one place so the two can never disagree.
func LocalIPv4s() []string {
	seen := map[string]bool{}
	var out []string

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if ip == nil {
				continue
			}
			v4 := ip.To4()
			if v4 == nil || v4.IsLoopback() {
				continue
			}
			if s := v4.String(); !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// LookupPTR resolves ip's reverse DNS and returns the PTR names with the
// trailing dot trimmed. A nil slice with a nil error means the reverse name has
// no PTR record; any other error means the lookup itself failed.
func LookupPTR(ctx context.Context, resolver, ip string) ([]string, error) {
	c := &Checker{resolver: resolver, timeout: 5 * time.Second}
	obs, err := c.lookupPTR(ctx, ip)
	if err != nil {
		return nil, err
	}
	if obs == nil {
		return nil, nil
	}
	return obs.Values, nil
}
