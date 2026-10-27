package postfwd

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestRequestEncodeHasTheAttributesPostfixSends: postfwd evaluates the request
// with the same item names the rules use, so a probe only stands for a real
// message if it carries Postfix's attributes and names.
func TestRequestEncodeHasTheAttributesPostfixSends(t *testing.T) {
	req := Request{
		Sender:        "alice@example.com",
		Recipient:     "bob@example.net",
		ClientAddress: "203.0.113.9",
		SASLUsername:  "alice",
		SASLMethod:    "plain",
		QueueID:       "ABC123",
		Size:          1234,
	}
	out := req.Encode()

	for _, want := range []string{
		"request=smtpd_access_policy\n",
		"protocol_state=END-OF-MESSAGE\n",
		"client_address=203.0.113.9\n",
		// Postfix fills these in even when it has no name for the client; a rule
		// may test them, so the probe must not leave them out.
		"client_name=unknown\n",
		"helo_name=unknown\n",
		"sender=alice@example.com\n",
		"recipient=bob@example.net\n",
		"recipient_count=1\n",
		"sasl_username=alice\n",
		"sasl_method=plain\n",
		"size=1234\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the request is missing %q:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Errorf("the request is not terminated by a blank line:\n%q", out)
	}

	// A message submitted from this host has no SASL at all: the attribute has to
	// be absent, not empty, because that is what postfwd matches `=~.+` against.
	local := Request{Sender: "alice@example.com", ClientAddress: "127.0.0.1"}
	if strings.Contains(local.Encode(), "sasl_username") {
		t.Errorf("an unauthenticated submission claims a SASL username:\n%s", local.Encode())
	}
}

// TestParseAnswerReadsARejection: the answer is what the doctor compares, so the
// status code has to survive parsing.
func TestParseAnswerReadsARejection(t *testing.T) {
	resp, err := ParseAnswer(strings.NewReader("action=554 5.7.1 Rate limit exceeded\n\n"))
	if err != nil {
		t.Fatalf("a valid answer was rejected: %v", err)
	}
	if resp.Action != "554 5.7.1 Rate limit exceeded" {
		t.Errorf("action = %q", resp.Action)
	}
	if resp.Code() != 554 {
		t.Errorf("code = %d, want 554", resp.Code())
	}
	if !resp.Denied() {
		t.Error("a 554 answer is not reported as a refusal")
	}
}

// TestParseAnswerReadsDunno: DUNNO has no status code and is not a refusal, and
// that difference is the whole point of the check.
func TestParseAnswerReadsDunno(t *testing.T) {
	resp, err := ParseAnswer(strings.NewReader("action=dunno\n"))
	if err != nil {
		t.Fatalf("a dunno answer was rejected: %v", err)
	}
	if resp.Code() != 0 || resp.Denied() {
		t.Errorf("dunno parsed as code %d, denied %v", resp.Code(), resp.Denied())
	}
}

// TestParseAnswerKeepsTheOtherAttributes: postfwd may add a reason or a rule id,
// and a check message that can quote it is easier to act on.
func TestParseAnswerKeepsTheOtherAttributes(t *testing.T) {
	resp, err := ParseAnswer(strings.NewReader("id=RL_0001\naction=450 4.7.1 slow down\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Attrs["id"] != "RL_0001" {
		t.Errorf("attrs = %v, want the rule id", resp.Attrs)
	}
}

// TestParseAnswerRejectsSilence: an empty answer is a broken daemon, not a
// permissive one -- reporting it as DUNNO would hide exactly the failure this
// package exists to expose.
func TestParseAnswerRejectsSilence(t *testing.T) {
	if _, err := ParseAnswer(strings.NewReader("")); err == nil {
		t.Error("an answer without an action was accepted")
	}
}

// TestProbeSenderStaysInsideTheDomain: the probe sender has to look like mail
// from the domain, or sender_domain== in the rule would not match it.
func TestProbeSenderStaysInsideTheDomain(t *testing.T) {
	if got, want := ProbeSender("example.com"), "mailx-rate-limit-probe@example.com"; got != want {
		t.Errorf("ProbeSender = %q, want %q", got, want)
	}
	if !strings.HasSuffix(ProbeSender("example.com"), "@example.com") {
		t.Error("the probe sender is not in the domain it probes")
	}
}

// TestAskTalksToTheDaemon exercises the round trip against a listener that
// answers like postfwd, so the protocol (one request, one answer, blank line) is
// covered without a mail server.
func TestAskTalksToTheDaemon(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	gotRequest := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the request up to its blank line, then answer.
		var b strings.Builder
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			b.WriteString(line)
			if line == "\n" || err != nil {
				break
			}
		}
		gotRequest <- b.String()
		_, _ = io.WriteString(conn, "action=554 5.7.1 mailx-admin rate-limit canary\n\n")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := Ask(ctx, ln.Addr().String(), Request{
		Sender:        CanarySender,
		Recipient:     "postmaster@example.net",
		ClientAddress: "203.0.113.9",
	})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if resp.Action != CanaryReply {
		t.Errorf("action = %q, want %q", resp.Action, CanaryReply)
	}

	select {
	case request := <-gotRequest:
		if !strings.Contains(request, "sender="+CanarySender) {
			t.Errorf("the request did not carry the sender:\n%s", request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the daemon never received a request")
	}
}
