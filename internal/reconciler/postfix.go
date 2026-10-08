package reconciler

import (
	"bytes"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/models"
	"os"
	"sort"
	"strconv"
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

	b.WriteString("# BEGIN mailx-admin managed block\n")
	b.WriteString("# ============================================================================\n")
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT THIS BLOCK BY HAND\n")
	b.WriteString("# Any changes here will be overwritten on the next reconcile.\n")
	b.WriteString("# To add unmanaged settings, put them ABOVE this block.\n")
	b.WriteString("# ============================================================================\n\n")

	primary := snap.PrimaryDomain()
	if primary == nil {
		fmt.Fprintf(&b, "# no primary domain configured\n")
	} else {
		fmt.Fprintf(&b, "myhostname = %s\n", hostname)
		fmt.Fprintf(&b, "mydomain = %s\n", primary.Name)
		fmt.Fprintf(&b, "myorigin = $mydomain\n")
		// mydestination must not name any mail domain: Postfix would classify it
		// as local and refuse delivery to every virtual mailbox in it (a virtual
		// mailbox has no Unix account, so local(8) bounces it as "unknown user").
		// Keep only localhost; the mail domains belong to virtual_mailbox_domains.
		fmt.Fprintf(&b, "mydestination = localhost, localhost.$mydomain\n")
	}

	// Virtual domains — one per line, "domain  OK"
	domains := make([]string, 0, len(snap.Domains))
	for _, d := range snap.Domains {
		domains = append(domains, d.Name)
	}
	sort.Strings(domains)
	fmt.Fprintf(&b, "\nvirtual_mailbox_domains = %s\n", strings.Join(domains, ", "))

	// The installer's main.cf leaves virtual_alias_domains pointing at
	// /etc/postfix/virtual_domains, which would classify every domain as an
	// alias domain (no mailbox delivery). Override it to empty: aliases live in
	// virtual_alias_maps and are checked within virtual_mailbox_domains.
	b.WriteString("virtual_alias_domains =\n")

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

	// Outbound IP routing. sender_dependent_default_transport_maps picks the
	// per-IP transport (see RenderSenderTransport/RenderOutboundTransports);
	// default_transport is the highest-priority "always" IP, or the stock smtp
	// when no outbound IP is configured.
	b.WriteString("\nsender_dependent_default_transport_maps = hash:/etc/postfix/sender_transport\n")
	fmt.Fprintf(&b, "default_transport = %s\n", DefaultOutboundTransport(snap.OutboundIPs))

	b.WriteString("\n# DKIM milter\n")
	b.WriteString("milter_default_action = accept\n")
	b.WriteString("milter_protocol = 2\n")
	b.WriteString("smtpd_milters = unix:opendkim/opendkim.sock\n")
	b.WriteString("non_smtpd_milters = unix:opendkim/opendkim.sock\n")

	b.WriteString("\n# Header checks\n")
	b.WriteString("header_checks = regexp:/etc/postfix/header_checks\n")

	// Outbound smarthost. When configured, every outbound message goes through
	// the relay instead of direct delivery — the escape hatch for hosts whose
	// provider/ISP blocks outbound SMTP.
	if snap.Relay != nil && snap.Relay.Enabled {
		relayHost := snap.Relay.Host
		if snap.Relay.Port > 0 {
			relayHost = fmt.Sprintf("[%s]:%d", snap.Relay.Host, snap.Relay.Port)
		}
		b.WriteString("\n# Outbound relay\n")
		fmt.Fprintf(&b, "relayhost = %s\n", relayHost)
		if snap.Relay.Username != "" {
			b.WriteString("smtp_sasl_auth_enable = yes\n")
			b.WriteString("smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd\n")
			b.WriteString("smtp_sasl_security_options = noanonymous\n")
		}
		switch snap.Relay.TLSMode {
		case "smtps":
			b.WriteString("smtp_use_tls = yes\n")
			b.WriteString("smtp_tls_wrappermode = yes\n")
		case "starttls":
			b.WriteString("smtp_tls_security_level = encrypt\n")
		}
	}

	b.WriteString("\n# Suppression checks\n")
	b.WriteString("smtpd_sender_restrictions = check_sender_access hash:/etc/postfix/suppressions_in\n")

	b.WriteString("\n# END mailx-admin managed block\n")
	return b.Bytes()
}

// RenderSaslPasswd produces /etc/postfix/sasl_passwd: the smarthost credentials
// Postfix reads via smtp_sasl_password_maps. The file is 0600 root:root because
// it holds the relay password in plaintext.
func RenderSaslPasswd(relay *models.RelayConfig) []byte {
	if relay == nil || !relay.Enabled || relay.Username == "" {
		return []byte("# Managed by mailx-admin — no relay credentials\n")
	}
	host := relay.Host
	if relay.Port > 0 {
		host = fmt.Sprintf("[%s]:%d", relay.Host, relay.Port)
	}
	return []byte(fmt.Sprintf("# Managed by mailx-admin — DO NOT EDIT\n%s %s:%s\n", host, relay.Username, relay.Password))
}

// mergeMainCF injects the freshly-rendered managed block into an existing
// main.cf. The installer downloads the rest of main.cf from a template, and the
// panel owns only the delimited block at the end; Postfix reads main.cf itself,
// so the block has to be merged into it rather than written to a sidecar file
// nothing includes. A previous managed block is replaced, so the file stays
// idempotent across reconciles.
func mergeMainCF(existing, managed []byte) []byte {
	const beginMarker = "# BEGIN mailx-admin managed block"
	const endMarker = "# END mailx-admin managed block"

	begin := []byte(beginMarker)
	end := []byte(endMarker)

	if i := bytes.Index(existing, begin); i >= 0 {
		if j := bytes.Index(existing[i:], end); j >= 0 {
			jEnd := i + j + len(end)
			if jEnd < len(existing) && existing[jEnd] == '\n' {
				jEnd++
			}
			existing = append(existing[:i:i], existing[jEnd:]...)
		}
	}

	existing = bytes.TrimRight(existing, "\n")
	out := make([]byte, 0, len(existing)+len(managed)+2)
	out = append(out, existing...)
	out = append(out, '\n', '\n')
	out = append(out, managed...)
	return out
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
		var domainName string
		for _, d := range snap.Domains {
			if d.ID == a.DomainID {
				domainName = d.Name
				break
			}
		}
		source := a.Source
		switch {
		case source == "@" || source == "":
			// Bare catch-all ("@") or a legacy empty seed row → "@domain".
			if domainName != "" {
				source = "@" + domainName
			}
		case strings.Contains(source, "@"):
			// Already fully qualified ("@example.com" catch-all).
		default:
			// Local part only — expand with the domain name.
			if domainName != "" {
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

func RenderMasterCF(renderFn func([]byte, []models.PortListener) []byte, listeners []models.PortListener, currentPath string, transports []byte) []byte {
	original, _ := os.ReadFile(currentPath)
	return append(renderFn(original, listeners), transports...)
}

// transportName is the master.cf transport a given outbound IP gets. It is
// keyed on the database id so renaming an IP never rewrites its transport.
func transportName(id int64) string { return "smtpip" + strconv.FormatInt(id, 10) }

// RenderSenderTransport produces /etc/postfix/sender_transport: which transport
// (and so which smtp_bind_address) a sender is routed through. It is read by
// sender_dependent_default_transport_maps.
func RenderSenderTransport(ips []models.OutboundIP) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")

	lines := make([]string, 0)
	for _, ip := range ips {
		if !ip.Active || ip.Mode != models.IPModeRules {
			continue
		}
		tr := transportName(ip.ID)
		for _, r := range ip.Rules {
			lines = append(lines, fmt.Sprintf("%s\t%s", senderPattern(r), tr))
		}
	}
	sort.Strings(lines)
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.Bytes()
}

// senderPattern maps an outbound rule to the sender_dependent_transport key:
// @domain for a domain rule, user@ for a bare user, and the full address for an
// email rule.
func senderPattern(r models.OutboundRule) string {
	switch r.MatchType {
	case models.RuleMatchDomain:
		return "@" + r.MatchValue
	case models.RuleMatchUser:
		return r.MatchValue + "@"
	default:
		return r.MatchValue
	}
}

// RenderOutboundTransports produces the master.cf stanzas that bind each
// outbound IP to its own transport (smtp_bind_address). The caller appends this
// to master.cf.
func RenderOutboundTransports(ips []models.OutboundIP) []byte {
	var b bytes.Buffer
	for _, ip := range ips {
		if !ip.Active || ip.Mode == models.IPModeDisabled {
			continue
		}
		fmt.Fprintf(&b, "%s unix - - n - - smtp\n", transportName(ip.ID))
		fmt.Fprintf(&b, "  -o smtp_bind_address=%s\n", ip.IP)
	}
	return b.Bytes()
}

// DefaultOutboundTransport is the transport used when no sender rule matches:
// the highest-priority "always" IP, or the stock "smtp" transport when none is
// configured.
func DefaultOutboundTransport(ips []models.OutboundIP) string {
	best := ""
	bestPriority := -1
	for _, ip := range ips {
		if !ip.Active || ip.Mode != models.IPModeAlways {
			continue
		}
		if ip.Priority > bestPriority {
			bestPriority = ip.Priority
			best = transportName(ip.ID)
		}
	}
	if best == "" {
		return "smtp"
	}
	return best
}

// RenderSuppressions produces /etc/postfix/suppressions: a recipient access map
// the submission service consults via check_recipient_access to refuse outbound
// mail to suppressed recipients/domains.
func RenderSuppressions(sups []models.Suppression) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")
	for _, s := range sups {
		if s.Direction == "in" {
			continue
		}
		fmt.Fprintf(&b, "%s\t550 5.7.1 recipient suppressed by policy\n", suppressionKey(s, false))
	}
	return b.Bytes()
}

// RenderSenderSuppressions produces /etc/postfix/suppressions_in: a sender
// access map consulted via smtpd_sender_restrictions to reject inbound mail from
// suppressed senders/domains.
func RenderSenderSuppressions(sups []models.Suppression) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n\n")
	for _, s := range sups {
		if s.Direction != "in" {
			continue
		}
		fmt.Fprintf(&b, "%s\t550 5.7.1 sender rejected by policy\n", suppressionKey(s, true))
	}
	return b.Bytes()
}

// suppressionKey returns the Postfix access-map key for a rule: the full address
// for an email match, "@domain" for an outbound domain match (all recipients in
// the domain), or the bare domain for an inbound domain match.
func suppressionKey(s models.Suppression, sender bool) string {
	if s.MatchType == "domain" {
		if sender {
			return s.Email
		}
		return "@" + s.Email
	}
	return s.Email
}
