// Package postfwd speaks the part of postfwd's policy protocol the panel needs
// to prove that a domain's outgoing rate limit is enforced.
//
// The rules live in internal/reconciler/postfwd.go; this package holds the
// constants both sides have to agree on -- where postfwd listens, which senders
// and clients the marker rules the renderer emits can be recognised by -- and a
// small client for the wire protocol, so the doctor can ask the running daemon
// what it would do with a given message instead of guessing from a config file.
//
// That question is the whole point. A rendered rule that postfwd never matches
// looks exactly like a rule that works: the file is on disk, the daemon is
// running, Postfix asks, and mail flows (postfwd answers DUNNO). The only way to
// tell the difference is to send a request and read the answer.
package postfwd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// PolicyAddr is where postfwd listens (see the unit the installer writes) and
	// where main.cf sends Postfix (RenderPostfixMainCF). Loopback only: a policy
	// decision is worth an extra round trip on this host and nothing else.
	PolicyAddr = "127.0.0.1:10040"

	// CanarySender is the envelope sender of the marker rule the renderer puts at
	// the top of /etc/postfwd.cf. It answers CanaryReply unconditionally, so a
	// probe with it proves three things at once: postfwd is listening, it loaded
	// the file the panel wrote, and its parser understood it. The domain is
	// reserved by RFC 2606, so no real message can ever carry it.
	CanarySender = "rate-limit-canary@mailx-canary.invalid"
	CanaryReply  = "554 5.7.1 mailx-admin rate-limit canary"

	// ProbeLocalPart is the local part of the per-domain probe rules. Each limited
	// domain gets one probe rule per submission path (loopback and authenticated),
	// ahead of its rate rules, answering ProbeReply. A probe therefore never
	// reaches a rate() rule and never consumes an allowance -- checking a limit
	// must not spend it.
	ProbeLocalPart = "mailx-rate-limit-probe"
	ProbeReply     = "554 5.7.1 mailx-admin rate-limit probe"

	// askTimeout bounds one policy request. postfwd answers in microseconds when
	// it is healthy; this only has to be shorter than the operator's patience.
	askTimeout = 5 * time.Second

	// maxAnswer caps what one answer may occupy. An answer is a handful of
	// key=value lines; the cap is there so a misconfigured listener cannot make
	// the panel read forever.
	maxAnswer = 16 << 10
)

// LoopbackClients are the client addresses a submission from this host can carry
// once Postfix has normalised it: the IPv4 loopback, the IPv6 one, and the
// v4-mapped form Postfix reports on a dual-stack listener.
//
// The renderer needs all three because Roundcube (and anything else on this box)
// hands mail to 127.0.0.1:25 or ::1:25; the doctor needs the same list to probe
// the same path. The two used to be one entry, which is exactly the sort of
// mismatch a limit silently dies of.
var LoopbackClients = []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"}

// RemoteClientPattern matches every client address that is *not* this host.
//
// It exists so the two rules a window is split into -- "submitted from this
// host" and "submitted with SASL" -- never both match the same message. They
// share one rate() counter (one message must cost one unit), so they have to be
// mutually exclusive or the counter would run at double speed.
//
// Perl lookahead is used because postfwd has no "not in list" operator. Go's
// regexp cannot compile this; nothing in the panel evaluates it, postfwd does.
const RemoteClientPattern = `^(?!127\.0\.0\.1$|::1$|::ffff:127\.0\.0\.1$).+`

// ProbeSender is the envelope sender of a domain's probe rules.
func ProbeSender(domain string) string {
	return ProbeLocalPart + "@" + domain
}

// Request is one policy request: the attributes of a message Postfix would send
// to postfwd at the end of its data phase.
type Request struct {
	Sender        string
	Recipient     string
	ClientAddress string
	ClientName    string
	HELOName      string
	SASLUsername  string
	SASLMethod    string
	QueueID       string
	Size          int
}

// Encode renders the request in postfwd's protocol: one key=value per line,
// terminated by an empty line.
//
// The attribute names are Postfix's own (and postfwd's items of the same name),
// which is what makes a probe representative: postfwd evaluates the request with
// the very expressions the rules use.
func (r Request) Encode() string {
	var b strings.Builder
	b.WriteString("request=smtpd_access_policy\n")
	b.WriteString("protocol_state=END-OF-MESSAGE\n")
	b.WriteString("protocol_name=ESMTP\n")

	writeAttr(&b, "client_address", r.ClientAddress)
	name := r.ClientName
	if name == "" && r.ClientAddress != "" {
		// Postfix sends "unknown" when it has no PTR record, and a rule may test
		// it; saying nothing would make the probe less realistic than the traffic
		// it stands for.
		name = "unknown"
	}
	writeAttr(&b, "client_name", name)
	writeAttr(&b, "reverse_client_name", name)
	helo := r.HELOName
	if helo == "" && r.ClientAddress != "" {
		helo = "unknown"
	}
	writeAttr(&b, "helo_name", helo)
	writeAttr(&b, "sender", r.Sender)
	writeAttr(&b, "recipient", r.Recipient)
	if r.Recipient != "" {
		b.WriteString("recipient_count=1\n")
	}
	writeAttr(&b, "sasl_method", r.SASLMethod)
	writeAttr(&b, "sasl_username", r.SASLUsername)
	writeAttr(&b, "queue_id", r.QueueID)
	if r.Size > 0 {
		fmt.Fprintf(&b, "size=%d\n", r.Size)
	}
	b.WriteString("instance=1\n")
	b.WriteString("\n")
	return b.String()
}

func writeAttr(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(value)
	b.WriteByte('\n')
}

// Response is postfwd's answer.
type Response struct {
	// Action is the value of the answer's action attribute: an SMTP reply such as
	// "554 5.7.1 ..." or the word "dunno".
	Action string

	// Attrs is every attribute of the answer, including action.
	Attrs map[string]string
}

// Code returns the numeric SMTP status of the answer, or 0 for dunno (and for
// anything that is not a numeric reply).
func (r *Response) Code() int {
	if r == nil || len(r.Action) < 3 {
		return 0
	}
	code, err := strconv.Atoi(r.Action[:3])
	if err != nil {
		return 0
	}
	return code
}

// Denied reports whether postfwd refused the message, temporarily (4xx) or
// permanently (5xx).
func (r *Response) Denied() bool {
	return r.Code() >= 400
}

// Ask sends one request to the postfwd at addr and returns its answer.
//
// The caller's context bounds the exchange; a healthy postfwd answers a policy
// request in microseconds.
func Ask(ctx context.Context, addr string, req Request) (*Response, error) {
	if addr == "" {
		addr = PolicyAddr
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("postfwd on %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(askTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("postfwd on %s: %w", addr, err)
	}

	if _, err := io.WriteString(conn, req.Encode()); err != nil {
		return nil, fmt.Errorf("postfwd on %s: %w", addr, err)
	}
	return ParseAnswer(conn)
}

// ParseAnswer reads one answer: key=value lines, ended by an empty line or by
// the daemon closing the connection.
//
// An answer without an action is an error rather than an empty Response: postfwd
// always states what Postfix should do, so a silent one is a broken one, and the
// caller's next step (tell the operator) is the same either way.
func ParseAnswer(r io.Reader) (*Response, error) {
	resp := &Response{Attrs: make(map[string]string, 4)}
	br := bufio.NewReader(io.LimitReader(r, maxAnswer))

	for {
		line, err := br.ReadString('\n')
		text := strings.TrimRight(line, "\r\n")
		if text == "" {
			// The blank line that ends the answer, or the end of the stream.
			if err == nil || errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read postfwd answer: %w", err)
		}
		if key, value, ok := strings.Cut(text, "="); ok {
			key = strings.TrimSpace(key)
			resp.Attrs[key] = value
			if key == "action" {
				resp.Action = strings.TrimSpace(value)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read postfwd answer: %w", err)
		}
	}

	if resp.Action == "" {
		return nil, errors.New("postfwd answered without an action")
	}
	return resp, nil
}
