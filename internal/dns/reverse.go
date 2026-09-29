package dns

import "github.com/miekg/dns"

// reverseAddr turns an IP into its reverse-DNS name (with the trailing dot), in
// one place so the plan, the checker and the .txt export cannot disagree about
// how the reverse zone is spelled.
func reverseAddr(ip string) string {
	name, err := dns.ReverseAddr(ip)
	if err != nil {
		return ""
	}
	return name
}
