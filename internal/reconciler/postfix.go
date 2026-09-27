package reconciler

import (
	"bytes"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/models"
	"os"
	"sort"
	"strings"
)

// RenderPostfixMainCF produces /etc/postfix/main.cf from the snapshot.
//
// This preserves the structure of the upstream _main.cf you download from
// GitHub, but injects domain/user-driven settings deterministically.
//
// NOTE: We do NOT try to reproduce the entire main.cf here — the installer
// downloads a template. The reconciler appends a clearly-delimited block
// of managed settings at the end, which Postfix's last-wins semantics honor.
func RenderPostfixMainCF(snap *models.Snapshot, hostname string) []byte {
	var b bytes.Buffer

	b.WriteString("# ============================================================================\n")
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT THIS BLOCK BY HAND\n")
	b.WriteString("# Any changes here will be overwritten on the next reconcile.\n")
	b.WriteString("# To add unmanaged settings, put them ABOVE this block.\n")
	b.WriteString("# ============================================================================\n")
	b.WriteString("# BEGIN mailx-admin managed block\n\n")

	primary := snap.PrimaryDomain()
	if primary == nil {
		fmt.Fprintf(&b, "# no primary domain configured\n")
	} else {
		fmt.Fprintf(&b, "myhostname = %s\n", hostname)
		fmt.Fprintf(&b, "mydomain = %s\n", primary.Name)
		fmt.Fprintf(&b, "myorigin = $mydomain\n")
		fmt.Fprintf(&b, "mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain\n")
	}

	// Virtual domains — one per line, "domain  OK"
	domains := make([]string, 0, len(snap.Domains))
	for _, d := range snap.Domains {
		domains = append(domains, d.Name)
	}
	sort.Strings(domains)
	fmt.Fprintf(&b, "\nvirtual_mailbox_domains = %s\n", strings.Join(domains, ", "))

	b.WriteString("\n# Virtual maps\n")
	b.WriteString("virtual_alias_maps = hash:/etc/postfix/virtual\n")
	b.WriteString("virtual_mailbox_maps = hash:/etc/postfix/vmailbox\n")
	b.WriteString("virtual_mailbox_base = /var/mail/vhosts\n")
	b.WriteString("virtual_uid_maps = static:5000\n")
	b.WriteString("virtual_gid_maps = static:5000\n")

	b.WriteString("\n# DKIM milter\n")
	b.WriteString("milter_default_action = accept\n")
	b.WriteString("milter_protocol = 2\n")
	b.WriteString("smtpd_milters = unix:/var/spool/postfix/opendkim/opendkim.sock\n")
	b.WriteString("non_smtpd_milters = unix:/var/spool/postfix/opendkim/opendkim.sock\n")

	b.WriteString("\n# Header checks\n")
	b.WriteString("header_checks = regexp:/etc/postfix/header_checks\n")

	b.WriteString("\n# END mailx-admin managed block\n")
	return b.Bytes()
}

// RenderVirtualMap produces /etc/postfix/virtual — alias lookups.
//
// Format: <source> <destination1>,<destination2>
//
//	alice@example.com   alice@example.com         (self, for local delivery)
//	sales@example.com   alice@example.com,bob@... (distribution list)
//	@example.com        catchall@example.com      (catch-all)
func RenderVirtualMap(snap *models.Snapshot) []byte {
	var b bytes.Buffer

	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n")
	b.WriteString("# Format: source destination1,destination2\n\n")

	// Sort for deterministic output (git-friendly diffs)
	lines := make([]string, 0)

	// Users map to themselves (so Postfix knows they're valid recipients)
	for _, u := range snap.Users {
		lines = append(lines, fmt.Sprintf("%s\t%s", u.Email, u.Email))
	}

	// Aliases
	for _, a := range snap.Aliases {
		source := a.Source
		if !strings.Contains(source, "@") {
			// Local part only — expand with domain
			var domainName string
			for _, d := range snap.Domains {
				if d.ID == a.DomainID {
					domainName = d.Name
					break
				}
			}
			if strings.HasPrefix(source, "@") {
				// already has @domain
				source = source[1:] // strip leading @ handled below
			}
			if domainName != "" && !strings.Contains(source, "@") {
				source = source + "@" + domainName
			}
		}
		lines = append(lines, fmt.Sprintf("%s\t%s", source, a.Destination))
	}

	sort.Strings(lines)
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}

	return b.Bytes()
}

// RenderVmailboxMap produces /etc/postfix/vmailbox — virtual mailbox paths.
//
// Format: <email> <maildir_path>
func RenderVmailboxMap(snap *models.Snapshot) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")

	lines := make([]string, 0, len(snap.Users))
	for _, u := range snap.Users {
		// /var/mail/vhosts/<domain>/<user>/Maildir/
		path := fmt.Sprintf("/var/mail/vhosts/%s/%s/Maildir/", u.DomainName, u.Username)
		lines = append(lines, fmt.Sprintf("%s\t%s", u.Email, path))
	}
	sort.Strings(lines)

	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}

	return b.Bytes()
}

// RenderHeloAccess produces /etc/postfix/helo_access.
func RenderHeloAccess(snap *models.Snapshot, hostname string) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")

	lines := []string{fmt.Sprintf("%s OK", hostname)}
	for _, d := range snap.Domains {
		lines = append(lines, fmt.Sprintf(".%s OK", d.Name))
	}
	sort.Strings(lines)

	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.Bytes()
}

// RenderHeaderChecks produces /etc/postfix/header_checks.
func RenderHeaderChecks(hostname string) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")
	fmt.Fprintf(&b, "/^Received: from \\S+ \\(.*\\[.*\\]\\)/ REPLACE Received: from %s (localhost [127.0.0.1])\n", hostname)
	b.WriteString("/^X-Originating-IP:/ IGNORE\n")
	return b.Bytes()
}

func RenderMasterCF(renderFn func([]byte, []models.PortListener) []byte, listeners []models.PortListener, currentPath string) []byte {
	original, _ := os.ReadFile(currentPath)
	return renderFn(original, listeners)
}
