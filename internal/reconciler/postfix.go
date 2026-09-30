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
	b.WriteString("virtual_mailbox_base = " + models.VmailBase + "\n")
	// Per-recipient ownership instead of `static:5000`. Every mailbox is still
	// delivered by virtual(8); what changes per recipient is the maildir path
	// (vmailbox) and the uid/gid it is delivered as. A system mailbox belongs
	// to its real account and Postfix has to deliver into /home/<user>/Maildir
	// as that account, or the write fails with EACCES.
	//
	// The maps are rendered for every active mailbox, so a lookup can only miss
	// when the panel and the server disagree — and then the error names the
	// recipient instead of silently dropping the mail.
	b.WriteString("virtual_uid_maps = hash:/etc/postfix/vuidmaps\n")
	b.WriteString("virtual_gid_maps = hash:/etc/postfix/vgidmaps\n")

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

// RenderVmailboxMap produces /etc/postfix/vmailbox — where each mailbox's mail
// is delivered.
//
// Format: <email> <maildir_path>
//
// The path is absolute for both kinds of mailbox: virtual ones live under
// virtual_mailbox_base, system ones in /home/<user>/Maildir. Postfix's
// virtual(8) takes the path from this map and the ownership from
// virtual_uid_maps/virtual_gid_maps, so the two have to agree per recipient —
// see RenderVirtualUidMaps.
func RenderVmailboxMap(snap *models.Snapshot) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")

	lines := make([]string, 0, len(snap.Users))
	for _, u := range snap.Users {
		// Trailing slash: Postfix then treats the value as a maildir.
		path := u.MaildirPath() + "/"
		lines = append(lines, fmt.Sprintf("%s\t%s", u.Email, path))
	}
	sort.Strings(lines)

	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}

	return b.Bytes()
}

// RenderVirtualUidMaps produces /etc/postfix/vuidmaps: the uid virtual(8) must
// deliver each recipient as.
//
// Format: <email> <uid>
//
// A single `static:5000` was enough while every mailbox was virtual, and it is
// precisely what breaks a mailbox on a real account: uid 5000 cannot write into
// /home/test1/Maildir. See RenderVirtualGidMaps for the gid half.
func RenderVirtualUidMaps(snap *models.Snapshot) []byte {
	return renderOwnerMap(snap, func(u models.User) int { return u.DeliveryUID() })
}

// RenderVirtualGidMaps produces /etc/postfix/vgidmaps, the gid half of
// RenderVirtualUidMaps.
func RenderVirtualGidMaps(snap *models.Snapshot) []byte {
	return renderOwnerMap(snap, func(u models.User) int { return u.DeliveryGID() })
}

func renderOwnerMap(snap *models.Snapshot, pick func(models.User) int) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n")
	b.WriteString("# Recipient -> the uid/gid Postfix delivers as.\n")
	b.WriteString("# vmail mailboxes use 5000:5000, system ones the account's own.\n\n")

	lines := make([]string, 0, len(snap.Users))
	for _, u := range snap.Users {
		lines = append(lines, fmt.Sprintf("%s\t%d", u.Email, pick(u)))
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
