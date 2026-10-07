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
		// Trust the real hostname above; never invent a "mail.<domain>" host the
		// operator may not have an A record for.
		lines = append(lines, d.Name)
	}
	sort.Strings(lines)

	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.Bytes()
}

// RenderOpenDKIMConf produces /etc/opendkim.conf in multi-domain mode: keys and
// signing policies come from KeyTable and SigningTable, not a single
// Domain/Selector/KeyFile triple, which is what lets the panel manage any number
// of domains. The daemon settings mirror Mailx-Installer's, so a server the
// installer set up keeps working unchanged.
func RenderOpenDKIMConf(opendkimDir string) []byte {
	// These are server paths written into the config file, so join with "/" —
	// never filepath.Join, which would use the panel's own OS separator.
	keyTable := opendkimDir + "/KeyTable"
	signingTable := opendkimDir + "/SigningTable"
	trustedHosts := opendkimDir + "/TrustedHosts"

	return []byte(fmt.Sprintf(`# Managed by mailx-admin — DO NOT EDIT

Syslog                  yes
SyslogSuccess           yes
LogWhy                  yes

Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no
OversignHeaders         From
SignatureAlgorithm      rsa-sha256
UMask                   007

UserID                  opendkim:opendkim

Socket                  local:/var/spool/postfix/opendkim/opendkim.sock

# Multi-domain: keys and signing policies come from the tables above, not from
# one hardcoded key, so every domain the panel manages is signed.
KeyTable                %s
SigningTable            refile:%s
InternalHosts           file:%s
ExternalIgnoreList      file:%s

AutoRestart             yes
AutoRestartRate         10/1M
DNSTimeout              5
`, keyTable, signingTable, trustedHosts, trustedHosts))
}
