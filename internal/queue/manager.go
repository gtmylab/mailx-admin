package queue

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Message struct {
	QueueID    string
	Size       int64
	Arrival    time.Time
	Active     bool
	Sender     string
	Recipients []Recipient
	Reason     string
}

type Recipient struct {
	Address string
	Delay   string
	Status  string
	Reason  string
}

// List runs `mailq` (or `postqueue -p`) and parses the output.
func List(ctx context.Context) ([]Message, error) {
	cmd := exec.CommandContext(ctx, "postqueue", "-p")
	out, err := cmd.Output()
	if err != nil {
		// postqueue -p returns non-zero if queue is empty sometimes;
		// check the output for "Mail queue is empty"
		if bytes.Contains(out, []byte("Mail queue is empty")) {
			return nil, nil
		}
		return nil, fmt.Errorf("postqueue: %w", err)
	}

	return parseMailq(out)
}

var (
	queueIDRe = regexp.MustCompile(`^([0-9A-Fa-f]+)\s+\*?\s*(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(.+)$`)
	senderRe  = regexp.MustCompile(`^\s*\((.+)\)$`)
	recipRe   = regexp.MustCompile(`^\s+(.+?)\s+(\S+)\s+(.+)$`)
	delayRe   = regexp.MustCompile(`^\s+\((.+)\)$`)
)

func parseMailq(data []byte) ([]Message, error) {
	var messages []Message
	var current *Message

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Header line: "QUEUEID [*] SIZE DATE SENDER"
		// e.g. "8F3A1B2C3D*  4532 Mon Sep 24 12:34:56  sender@example.com"
		if m := queueIDRe.FindStringSubmatch(line); m != nil {
			if current != nil {
				messages = append(messages, *current)
			}
			size, _ := strconv.ParseInt(m[2], 10, 64)
			ts, _ := time.Parse("Mon Jan 2 15:04:05", m[3])
			current = &Message{
				QueueID: m[1],
				Size:    size,
				Arrival: ts,
				Active:  strings.Contains(line, "*"),
				Sender:  strings.TrimSpace(m[4]),
			}
			continue
		}

		if current == nil {
			continue
		}

		// Sender continuation (with parentheses)
		if m := senderRe.FindStringSubmatch(line); m != nil {
			current.Sender = strings.TrimSpace(m[1])
			continue
		}

		// Recipient line
		if m := recipRe.FindStringSubmatch(line); m != nil {
			current.Recipients = append(current.Recipients, Recipient{
				Address: strings.TrimSpace(m[1]),
				Delay:   m[2],
				Status:  strings.TrimSpace(m[3]),
			})
			continue
		}

		// Recipient reason (parenthesized continuation)
		if m := delayRe.FindStringSubmatch(line); m != nil && len(current.Recipients) > 0 {
			last := &current.Recipients[len(current.Recipients)-1]
			last.Reason = strings.TrimSpace(m[1])
			continue
		}
	}
	if current != nil {
		messages = append(messages, *current)
	}

	return messages, nil
}

// Flush attempts to retry delivery of a specific message.
func Flush(ctx context.Context, queueID string) error {
	if !isValidQueueID(queueID) {
		return fmt.Errorf("invalid queue ID: %s", queueID)
	}
	cmd := exec.CommandContext(ctx, "postqueue", "-i", queueID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("postqueue -i: %w: %s", err, out)
	}
	return nil
}

// Delete removes a message from the queue.
func Delete(ctx context.Context, queueID string) error {
	if !isValidQueueID(queueID) {
		return fmt.Errorf("invalid queue ID: %s", queueID)
	}
	cmd := exec.CommandContext(ctx, "postsuper", "-d", queueID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("postsuper -d: %w: %s", err, out)
	}
	return nil
}

// Hold puts a message on hold.
func Hold(ctx context.Context, queueID string) error {
	if !isValidQueueID(queueID) {
		return fmt.Errorf("invalid queue ID: %s", queueID)
	}
	cmd := exec.CommandContext(ctx, "postsuper", "-h", queueID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("postsuper -h: %w: %s", err, out)
	}
	return nil
}

// Release removes a hold.
func Release(ctx context.Context, queueID string) error {
	if !isValidQueueID(queueID) {
		return fmt.Errorf("invalid queue ID: %s", queueID)
	}
	cmd := exec.CommandContext(ctx, "postsuper", "-H", queueID)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("postsuper -H: %w: %s", err, out)
	}
	return nil
}

// FlushAll retries all messages in the queue.
func FlushAll(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "postqueue", "-f")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("postqueue -f: %w: %s", err, out)
	}
	return nil
}

func isValidQueueID(id string) bool {
	if len(id) < 10 || len(id) > 20 {
		return false
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
