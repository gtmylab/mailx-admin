package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type TLSMode string

const (
	TLSStartTLS TLSMode = "starttls"
	TLSImplicit TLSMode = "implicit"
	TLSNone     TLSMode = "none"
)

type SendOptions struct {
	Host       string
	Port       int
	TLSMode    TLSMode
	SkipVerify bool

	// Optional auth. If Username is empty, no AUTH is attempted.
	Username string
	Password string

	From    string
	To      string
	Subject string
	Body    string

	Timeout time.Duration
}

type Result struct {
	Success    bool
	Duration   time.Duration
	Transcript []TranscriptLine
	Error      string
	TLS        *TLSInfo
}

type TranscriptLine struct {
	Dir  string // "C" client, "S" server, "I" info
	Text string
	Ts   time.Time
}

type TLSInfo struct {
	Version     string
	CipherSuite string
	ServerName  string
	PeerCerts   int
	NotAfter    time.Time
}

// Send runs the SMTP conversation and captures a full transcript.
func Send(ctx context.Context, opts SendOptions) *Result {
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}

	res := &Result{Transcript: []TranscriptLine{}}
	start := time.Now()
	defer func() { res.Duration = time.Since(start) }()

	log := func(dir, text string) {
		res.Transcript = append(res.Transcript, TranscriptLine{
			Dir:  dir,
			Text: text,
			Ts:   time.Now(),
		})
	}

	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	log("I", fmt.Sprintf("Connecting to %s (TLS mode: %s)", addr, opts.TLSMode))

	dialer := &net.Dialer{Timeout: opts.Timeout}
	var conn net.Conn
	var err error

	if opts.TLSMode == TLSImplicit {
		tlsCfg := &tls.Config{
			ServerName:         opts.Host,
			InsecureSkipVerify: opts.SkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			res.Error = "TLS dial: " + err.Error()
			log("I", "FAILED: "+res.Error)
			return res
		}
		captureTLSInfo(conn, res, log)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			res.Error = "dial: " + err.Error()
			log("I", "FAILED: "+res.Error)
			return res
		}
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	}

	reader := bufio.NewReader(conn)

	// ---- Greeting ----
	greeting, err := reader.ReadString('\n')
	if err != nil {
		res.Error = "read greeting: " + err.Error()
		return res
	}
	log("S", strings.TrimRight(greeting, "\r\n"))

	if !isCode(greeting, 220) {
		res.Error = "unexpected greeting code"
		return res
	}

	// ---- EHLO ----
	if err := cmd(conn, reader, log, "EHLO mailx-admin.local", 250); err != nil {
		res.Error = err.Error()
		return res
	}

	// Note: we don't parse capabilities from EHLO for simplicity. If STARTTLS
	// is requested but not advertised, the STARTTLS command will fail and the
	// error message will be clear.

	// ---- STARTTLS ----
	if opts.TLSMode == TLSStartTLS {
		if err := cmd(conn, reader, log, "STARTTLS", 220); err != nil {
			res.Error = "STARTTLS: " + err.Error()
			return res
		}

		tlsCfg := &tls.Config{
			ServerName:         opts.Host,
			InsecureSkipVerify: opts.SkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			res.Error = "TLS handshake: " + err.Error()
			log("I", "TLS handshake FAILED: "+err.Error())
			return res
		}
		conn = tlsConn
		reader = bufio.NewReader(conn)
		captureTLSInfo(conn, res, log)

		// Re-EHLO after STARTTLS
		if err := cmd(conn, reader, log, "EHLO mailx-admin.local", 250); err != nil {
			res.Error = "EHLO after STARTTLS: " + err.Error()
			return res
		}
	}

	// ---- AUTH ----
	if opts.Username != "" {
		if err := doAuth(conn, reader, log, opts.Host, opts.Username, opts.Password); err != nil {
			res.Error = "AUTH: " + err.Error()
			return res
		}
	}

	// ---- MAIL FROM ----
	if err := cmd(conn, reader, log, "MAIL FROM:<"+opts.From+">", 250); err != nil {
		res.Error = "MAIL FROM: " + err.Error()
		return res
	}

	// ---- RCPT TO ----
	if err := cmd(conn, reader, log, "RCPT TO:<"+opts.To+">", 250); err != nil {
		res.Error = "RCPT TO: " + err.Error()
		return res
	}

	// ---- DATA ----
	if err := cmd(conn, reader, log, "DATA", 354); err != nil {
		res.Error = "DATA: " + err.Error()
		return res
	}

	// Build headers
	headers := []string{
		"From: " + opts.From,
		"To: " + opts.To,
		"Subject: " + opts.Subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: " + generateMessageID(opts.From),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	payload := strings.Join(headers, "\r\n") + "\r\n\r\n" + opts.Body + "\r\n"
	// Dot-stuffing: lines starting with "." must have an extra "."
	payload = strings.ReplaceAll(payload, "\r\n.", "\r\n..")

	fmt.Fprintf(conn, "%s.\r\n", payload)
	log("C", fmt.Sprintf("... payload (%d bytes) ...", len(payload)))
	log("C", ".")

	// ---- Response after DATA ----
	resp, err := reader.ReadString('\n')
	if err != nil {
		res.Error = "read after DATA: " + err.Error()
		return res
	}
	log("S", strings.TrimRight(resp, "\r\n"))

	if !isCode(resp, 250) {
		res.Error = fmt.Sprintf("server rejected message: %s", strings.TrimSpace(resp))
		return res
	}

	// ---- QUIT ----
	_ = cmd(conn, reader, log, "QUIT", 221)

	res.Success = true
	return res
}

// ---- helpers ----

func cmd(conn net.Conn, reader *bufio.Reader, log func(string, string), command string, wantCode int) error {
	fmt.Fprintf(conn, "%s\r\n", command)

	// Mask sensitive commands
	if strings.HasPrefix(strings.ToUpper(command), "AUTH") {
		log("C", "AUTH <redacted>")
	} else {
		log("C", command)
	}

	// Read one or more response lines (250-... continuation)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		log("S", strings.TrimRight(line, "\r\n"))

		// Multi-line response: "250-..." continues, "250 ..." ends
		if len(line) < 4 {
			return fmt.Errorf("malformed response: %q", line)
		}
		if line[3] == '-' {
			continue // more lines coming
		}
		// Final line — check code
		gotCode := 0
		fmt.Sscanf(line[:3], "%d", &gotCode)
		if gotCode != wantCode {
			return fmt.Errorf("expected %d, got %d (%s)", wantCode, gotCode, strings.TrimSpace(line))
		}
		return nil
	}
}

func doAuth(conn net.Conn, reader *bufio.Reader, log func(string, string), host, user, pass string) error {
	// AUTH PLAIN: base64("\0" + user + "\0" + pass)
	plain := "\x00" + user + "\x00" + pass
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))

	log("C", "AUTH PLAIN <redacted>")
	fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", encoded)

	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	log("S", strings.TrimRight(line, "\r\n"))

	if isCode(line, 235) {
		return nil
	}
	if isCode(line, 334) {
		// Server wants the payload separately
		log("C", "<redacted>")
		fmt.Fprintf(conn, "%s\r\n", encoded)
		line, err = reader.ReadString('\n')
		if err != nil {
			return err
		}
		log("S", strings.TrimRight(line, "\r\n"))
		if isCode(line, 235) {
			return nil
		}
	}
	return fmt.Errorf("auth rejected: %s", strings.TrimSpace(line))
}

func isCode(line string, code int) bool {
	if len(line) < 3 {
		return false
	}
	var got int
	fmt.Sscanf(line[:3], "%d", &got)
	return got == code
}

func base64Encode(b []byte) string {
	const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		for j := 0; j < 3 && i+j < len(b); j++ {
			n |= uint32(b[i+j]) << (16 - 8*j)
		}
		out.WriteByte(std[(n>>18)&0x3f])
		out.WriteByte(std[(n>>12)&0x3f])
		if i+1 < len(b) {
			out.WriteByte(std[(n>>6)&0x3f])
		} else {
			out.WriteByte('=')
		}
		if i+2 < len(b) {
			out.WriteByte(std[n&0x3f])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

func decodeBase64(s string) string {
	const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	var buf uint32
	var bits int
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			break
		}
		idx := strings.IndexByte(std, s[i])
		if idx < 0 {
			continue
		}
		buf = (buf << 6) | uint32(idx)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return string(out)
}

func captureTLSInfo(conn net.Conn, res *Result, log func(string, string)) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	state := tlsConn.ConnectionState()
	info := &TLSInfo{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ServerName:  state.ServerName,
		PeerCerts:   len(state.PeerCertificates),
	}
	if len(state.PeerCertificates) > 0 {
		info.NotAfter = state.PeerCertificates[0].NotAfter
	}
	res.TLS = info

	log("I", fmt.Sprintf("TLS: %s / %s / %d cert(s)",
		info.Version, info.CipherSuite, info.PeerCerts))
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		log("I", fmt.Sprintf("Cert subject: %s", leaf.Subject))
		log("I", fmt.Sprintf("Cert expires: %s", leaf.NotAfter.Format(time.RFC3339)))
		daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
		log("I", fmt.Sprintf("Cert days left: %d", daysLeft))
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("unknown (0x%04x)", v)
}

func generateMessageID(from string) string {
	host := "mailx-admin.local"
	if i := strings.Index(from, "@"); i >= 0 {
		host = from[i+1:]
	}
	return fmt.Sprintf("<%d.%d@%s>", time.Now().UnixNano(), time.Now().Unix(), host)
}

var ErrNoAuth = errors.New("no auth mechanism available")
