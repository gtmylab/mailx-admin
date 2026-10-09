package ports

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/models"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	beginMarker = "# BEGIN mailx-admin managed listeners"
	endMarker   = "# END mailx-admin managed listeners"
)

// Listener is a parsed entry from master.cf.
type Listener struct {
	Port         int
	Type         string // inet, unix
	Private      string // y, n
	Unprivileged string // y, n
	Chroot       string // y, n
	Wakeup       string
	MaxProc      string
	Command      string
	Options      []string // -o key=value lines
	Managed      bool     // true if inside our managed block
	LineIndex    int      // position in the file (for reference)
}

// Parse reads master.cf and returns all listeners plus the raw text.
func Parse(path string) ([]Listener, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}

	var listeners []Listener
	var inManaged bool

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var current *Listener
	lineIdx := 0

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Block markers
		if strings.HasPrefix(trimmed, beginMarker) {
			inManaged = true
			lineIdx++
			continue
		}
		if strings.HasPrefix(trimmed, endMarker) {
			inManaged = false
			lineIdx++
			continue
		}

		// Comment or blank
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lineIdx++
			continue
		}

		// Continuation line (indented, "-o ...")
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if current != nil && strings.HasPrefix(trimmed, "-o ") {
				current.Options = append(current.Options, trimmed)
			}
			lineIdx++
			continue
		}

		// New listener line
		if current != nil {
			listeners = append(listeners, *current)
		}

		fields := strings.Fields(line)
		if len(fields) < 8 {
			lineIdx++
			continue
		}

		port, err := strconv.Atoi(fields[0])
		if err != nil {
			// Not a port — could be "smtp", "submission" etc.
			// Look up in /etc/services, or just skip. For now, skip non-numeric.
			lineIdx++
			continue
		}

		current = &Listener{
			Port:         port,
			Type:         fields[1],
			Private:      fields[2],
			Unprivileged: fields[3],
			Chroot:       fields[4],
			Wakeup:       fields[5],
			MaxProc:      fields[6],
			Command:      fields[7],
			Managed:      inManaged,
			LineIndex:    lineIdx,
		}
		lineIdx++
	}
	if current != nil {
		listeners = append(listeners, *current)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return listeners, data, nil
}

// Render produces the master.cf with the managed block replaced.
// Non-managed content (including the standard 25/465/587 entries) is preserved verbatim.
func Render(original []byte, customListeners []models.PortListener) []byte {
	// Strip existing managed block
	stripped := stripManagedBlock(original)

	// Build new managed block
	var block bytes.Buffer
	block.WriteString("\n" + beginMarker + "\n")
	block.WriteString("# These listeners are managed by MailX Admin.\n")
	block.WriteString("# Any changes here will be overwritten on the next reconcile.\n\n")

	// Sort by port for deterministic output
	sorted := make([]models.PortListener, len(customListeners))
	copy(sorted, customListeners)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Port < sorted[j].Port })

	for _, l := range sorted {
		if !l.Enabled {
			continue
		}
		block.WriteString(renderListener(l))
	}

	block.WriteString(endMarker + "\n")

	// Append
	out := make([]byte, 0, len(stripped)+block.Len())
	out = append(out, stripped...)
	out = append(out, block.Bytes()...)
	return out
}

func stripManagedBlock(data []byte) []byte {
	var out bytes.Buffer
	var inManaged bool

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, beginMarker) {
			inManaged = true
			continue
		}
		if strings.HasPrefix(trimmed, endMarker) {
			inManaged = false
			continue
		}
		if inManaged {
			continue
		}

		out.WriteString(line)
		out.WriteString("\n")
	}

	// Trim trailing whitespace-only lines before appending
	return bytes.TrimRight(out.Bytes(), "\n")
}

func renderListener(l models.PortListener) string {
	var b strings.Builder

	if l.Description != "" {
		fmt.Fprintf(&b, "# %s\n", l.Description)
	}

	// Default: Postfix-style smtpd listener with TLS + SASL
	fmt.Fprintf(&b, "%d      inet  n       -       y       -       -       smtpd\n", l.Port)
	fmt.Fprintf(&b, "  -o syslog_name=postfix/%d\n", l.Port)

	switch l.TLSMode {
	case "encrypt":
		fmt.Fprintf(&b, "  -o smtpd_tls_security_level=encrypt\n")
	case "none":
		fmt.Fprintf(&b, "  -o smtpd_tls_security_level=none\n")
	default:
		fmt.Fprintf(&b, "  -o smtpd_tls_security_level=may\n")
	}

	if l.RequireSASL {
		b.WriteString("  -o smtpd_sasl_auth_enable=yes\n")
		b.WriteString("  -o smtpd_client_restrictions=permit_sasl_authenticated,reject\n")
		b.WriteString("  -o smtpd_sender_login_maps=hash:/etc/postfix/virtual\n")
		b.WriteString("  -o { smtpd_recipient_restrictions = check_recipient_access hash:/etc/postfix/suppressions,permit_sasl_authenticated,reject }\n")
	}

	b.WriteString("  -o milter_macro_daemon_name=ORIGINATING\n")

	return b.String()
}

// Validate checks a prospective listener before applying.
func Validate(l models.PortListener, existing []models.PortListener) error {
	if l.Port < 1 || l.Port > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", l.Port)
	}
	if l.Port < 1024 {
		// Root can bind low ports but it's a bad idea for user submission ports
		return fmt.Errorf("port %d is privileged; choose a port ≥ 1024", l.Port)
	}

	// Reserved ports we never touch
	reserved := map[int]string{
		25:    "SMTP",
		465:   "SMTPS",
		587:   "Submission",
		110:   "POP3",
		143:   "IMAP",
		993:   "IMAPS",
		995:   "POP3S",
		12340: "Dovecot quota-status",
		9090:  "MailX Admin",
		8080:  "Roundcube",
		8081:  "MailX web",
		8082:  "PHPMyAdmin",
	}
	if name, ok := reserved[l.Port]; ok {
		return fmt.Errorf("port %d is reserved for %s; choose a different port", l.Port, name)
	}

	for _, e := range existing {
		if e.Port == l.Port && e.ID != l.ID {
			return fmt.Errorf("port %d already configured", l.Port)
		}
	}

	return nil
}

// CheckPortAvailable tries to bind the port briefly to detect conflicts.
func CheckPortAvailable(port int) error {
	// We only check local binding, not "already in master.cf"
	// Use net.Listen with SO_REUSEADDR off (default) to detect conflicts
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		if strings.Contains(err.Error(), "address already in use") {
			return fmt.Errorf("port %d is in use by another process", port)
		}
		return err
	}
	ln.Close()
	return nil
}

// Dedupe collapses identical listeners — same port, type, chroot and command —
// into one entry, and reports how many duplicate lines were dropped. master.cf
// can accumulate repeats when the installer's "add SMTP port" step runs more
// than once; the panel shows each listener once instead of once per copy.
func Dedupe(listeners []Listener) (unique []Listener, dropped int) {
	seen := map[string]bool{}
	for _, l := range listeners {
		key := fmt.Sprintf("%d|%s|%s|%s", l.Port, l.Type, l.Chroot, l.Command)
		if seen[key] {
			dropped++
			continue
		}
		seen[key] = true
		unique = append(unique, l)
	}
	return unique, dropped
}

var portLineRe = regexp.MustCompile(`^(\d+)\s+inet\b`)
