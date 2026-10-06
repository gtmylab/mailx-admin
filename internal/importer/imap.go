package importer

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// IMAPConfig is a source IMAP server. It covers Google Workspace (app password),
// Microsoft 365 (app password) and any Mailcow/Mailu/iRedMail host.
type IMAPConfig struct {
	Host     string
	Port     int
	TLSMode  string // "", "starttls" or "tls"
	Username string
	Password string

	// Insecure skips TLS certificate verification. It is for one-off migrations
	// where the server presents a certificate that does not match its hostname;
	// the connection is still encrypted, but the identity is not checked.
	Insecure bool
}

// ImportIMAP connects to the server, lists every folder and fetches each
// message with its flags and internal date, writing them into w. report receives
// progress events (may be nil).
func ImportIMAP(ctx context.Context, cfg IMAPConfig, w *Writer, report func(Progress)) (*Result, error) {
	if cfg.Port == 0 {
		if cfg.TLSMode == "tls" {
			cfg.Port = 993
		} else {
			cfg.Port = 143
		}
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	emit := func(p Progress) {
		if report != nil {
			report(p)
		}
	}

	emit(Progress{Log: "Connecting to " + addr + " (" + tlsLabel(cfg.TLSMode) + ")..."})
	if cfg.Insecure {
		emit(Progress{Log: "TLS certificate verification disabled (insecure)."})
	}
	c, err := dialIMAP(cfg.TLSMode, addr, cfg.Insecure)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer c.Logout()
	emit(Progress{Log: "Connected."})

	emit(Progress{Log: "Authenticating as " + cfg.Username + "..."})
	if err := c.Login(cfg.Username, cfg.Password); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	emit(Progress{Log: "Authenticated."})

	res := &Result{Folders: map[string]int{}}

	emit(Progress{Log: "Listing folders..."})
	boxes := make(chan *imap.MailboxInfo, 32)
	listDone := make(chan error, 1)
	go func() { listDone <- c.List("", "*", boxes) }()

	var names []string
	for b := range boxes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		names = append(names, b.Name)
	}
	if err := <-listDone; err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	emit(Progress{Log: fmt.Sprintf("Found %d folders.", len(names))})

	// Best-effort grand total across every folder, via STATUS (no SELECT needed).
	total := 0
	for _, name := range names {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if st, err := c.Status(name, []imap.StatusItem{imap.StatusMessages}); err == nil {
			total += int(st.Messages)
		}
	}

	cumulative := 0
	for _, name := range names {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Some folders exist only as namespace nodes and cannot be selected.
		if _, err := c.Select(name, true); err != nil {
			continue
		}
		emit(Progress{Log: "Fetching " + name + "...", Folder: name, Messages: cumulative, Total: total})
		n, err := importFolder(ctx, c, name, w, cumulative, total, emit)
		if err != nil {
			return nil, err
		}
		cumulative += n
		res.Folders[name] += n
		emit(Progress{Log: fmt.Sprintf("Imported %d messages from %s.", n, name), Folder: name, Messages: cumulative, Total: total})
	}
	emit(Progress{Log: fmt.Sprintf("Import complete: %d messages.", cumulative), Messages: cumulative, Total: total})
	return res, nil
}

// tlsLabel names the encryption mode for log output.
func tlsLabel(mode string) string {
	switch mode {
	case "tls":
		return "SSL/TLS"
	case "starttls":
		return "STARTTLS"
	default:
		return "plain"
	}
}

// dialIMAP opens the connection with the requested encryption. When insecure is
// true, TLS certificate verification is skipped (the connection is still
// encrypted, but the certificate is not checked against the hostname).
func dialIMAP(mode, addr string, insecure bool) (*client.Client, error) {
	var tlsCfg *tls.Config
	if insecure {
		tlsCfg = &tls.Config{InsecureSkipVerify: true}
	}
	switch mode {
	case "tls":
		return client.DialTLS(addr, tlsCfg)
	case "starttls":
		c, err := client.Dial(addr)
		if err != nil {
			return nil, err
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	default:
		return client.Dial(addr)
	}
}

// importFolder fetches every message in the selected folder and writes it.
// base is the number of messages already imported from earlier folders, and
// total is the best-effort grand total across all folders.
func importFolder(ctx context.Context, c *client.Client, name string, w *Writer, base, total int, emit func(Progress)) (int, error) {
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem(), imap.FetchFlags, imap.FetchInternalDate}

	seqset := new(imap.SeqSet)
	seqset.AddRange(1, 0) // 1:* — every message

	messages := make(chan *imap.Message, 64)
	done := make(chan error, 1)
	go func() { done <- c.Fetch(seqset, items, messages) }()

	n := 0
	for msg := range messages {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		flags := Flags{
			Seen:     hasFlag(msg.Flags, imap.SeenFlag),
			Flagged:  hasFlag(msg.Flags, imap.FlaggedFlag),
			Answered: hasFlag(msg.Flags, imap.AnsweredFlag),
			Draft:    hasFlag(msg.Flags, imap.DraftFlag),
			Deleted:  hasFlag(msg.Flags, imap.DeletedFlag),
		}
		var date time.Time
		if !msg.InternalDate.IsZero() {
			date = msg.InternalDate
		}
		var body []byte
		if lit, ok := msg.Body[section]; ok {
			body, _ = io.ReadAll(lit)
		}
		if err := w.Put(name, body, flags, date); err != nil {
			return n, err
		}
		n++
		emit(Progress{Folder: name, Messages: base + n, Total: total})
	}
	return n, <-done
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, want) {
			return true
		}
	}
	return false
}
