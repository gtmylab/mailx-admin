package dns

import (
	"fmt"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// BuildExpected returns all DNS records a domain needs, based on its config.
func BuildExpected(domain models.Domain, serverIP string, hostname string) []Expected {
	selector := domain.DKIMSelector
	if selector == "" {
		selector = "default"
	}

	records := []Expected{
		{
			Type:     TypeA,
			Name:     domain.Name,
			Value:    serverIP,
			Purpose:  "A record",
			Required: true,
		},
		{
			Type:     TypeA,
			Name:     "mail." + domain.Name,
			Value:    serverIP,
			Purpose:  "A record (mail)",
			Required: true,
		},
		{
			Type:     TypeMX,
			Name:     domain.Name,
			Value:    "mail." + domain.Name,
			Priority: 10,
			Purpose:  "MX",
			Required: true,
		},
		{
			Type:     TypeTXT,
			Name:     domain.Name,
			Value:    fmt.Sprintf("v=spf1 mx a ip4:%s ~all", serverIP),
			Purpose:  "SPF",
			Required: true,
		},
		{
			Type:     TypeTXT,
			Name:     "_dmarc." + domain.Name,
			Value:    fmt.Sprintf("v=DMARC1; p=none; rua=mailto:admin@%s", domain.Name),
			Purpose:  "DMARC",
			Required: false, // recommended, not required
		},
	}

	if domain.DKIMPublicRecord != "" {
		records = append(records, Expected{
			Type:     TypeTXT,
			Name:     fmt.Sprintf("%s._domainkey.%s", selector, domain.Name),
			Value:    domain.DKIMPublicRecord,
			Purpose:  "DKIM",
			Required: true,
		})
	}

	return records
}
