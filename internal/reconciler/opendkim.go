package reconciler

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// RenderKeyTable produces /etc/opendkim/KeyTable.
//
// Format: <selector>._domainkey.<domain> <domain>:<selector>:<keyfile>
func RenderKeyTable(snap *models.Snapshot, opendkimDir string) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")

	lines := make([]string, 0, len(snap.Domains))
	for _, d := range snap.Domains {
		if d.DKIMPrivateKeyPath == "" {
			continue
		}
		line := fmt.Sprintf("%s._domainkey.%s %s:%s:%s",
			d.DKIMSelector, d.Name, d.Name, d.DKIMSelector, d.DKIMPrivateKeyPath)
		lines = append(lines, line)
	}
	sort.Strings(lines)

	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.Bytes()
}

// RenderSigningTable produces /etc/opendkim/SigningTable.
//
// Format: *@<domain> <selector>._domainkey.<domain>
func RenderSigningTable(snap *models.Snapshot) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")

	lines := make([]string, 0, len(snap.Domains))
	for _, d := range snap.Domains {
		if d.DKIMPrivateKeyPath == "" {
			continue
		}
		line := fmt.Sprintf("*@%s %s._domainkey.%s", d.Name, d.DKIMSelector, d.Name)
		lines = append(lines, line)
	}
	sort.Strings(lines)

	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.Bytes()
}

// RenderTrustedHosts produces /etc/opendkim/TrustedHosts.
func RenderTrustedHosts(snap *models.Snapshot, hostname string) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")

	lines := []string{"127.0.0.1", "::1", "localhost", hostname}
	for _, d := range snap.Domains {
		lines = append(lines, d.Name, "mail."+d.Name)
	}
	sort.Strings(lines)

	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.Bytes()
}
