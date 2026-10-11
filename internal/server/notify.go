package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// notifyHTTPClient is shared by the chat/webhook providers. A short timeout
// keeps a slow webhook from blocking an event source for long.
var notifyHTTPClient = &http.Client{Timeout: 10 * time.Second}

// dispatchNotifications fans an event out to every enabled notification handle
// whose event list includes it. Delivery is best-effort: a failing handle is
// logged and skipped, never fatal to the caller.
func (s *Server) dispatchNotifications(ctx context.Context, event string, fields map[string]string) {
	notes, err := s.store.ListActiveAdminNotifications(ctx)
	if err != nil {
		s.logger.Warn("list active notifications", "err", err)
		return
	}
	for _, n := range notes {
		if !notificationMatches(n.Events, event) {
			continue
		}
		if err := s.sendNotification(ctx, n, event, fields); err != nil {
			s.logger.Warn("send notification", "provider", n.Provider, "err", err)
		}
	}
}

// notificationMatches reports whether a JSON array of event names contains event.
func notificationMatches(eventsJSON, event string) bool {
	var events []string
	if err := json.Unmarshal([]byte(eventsJSON), &events); err != nil {
		return false
	}
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

// sendNotification delivers one event to one handle, choosing the transport by
// provider.
func (s *Server) sendNotification(ctx context.Context, n models.AdminNotification, event string, fields map[string]string) error {
	msg := formatNotification(event, fields)
	switch n.Provider {
	case "slack":
		return postJSON(n.Target, map[string]any{"text": msg})
	case "discord":
		return postJSON(n.Target, map[string]any{"content": msg})
	case "webhook":
		return postJSON(n.Target, map[string]any{"event": event, "data": fields})
	case "telegram":
		return sendTelegram(n.Target, msg)
	case "email":
		return s.sendMail(ctx, n.Target, "mailx: "+event, msg)
	default:
		return fmt.Errorf("unknown provider %q", n.Provider)
	}
}

// postJSON POSTs a JSON object to a webhook URL and treats any non-2xx reply as
// an error.
func postJSON(url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := notifyHTTPClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

// sendTelegram sends a message through the Bot API. The target encodes both the
// bot token and the chat id as "<bot_token>|<chat_id>".
func sendTelegram(target, text string) error {
	token, chatID, ok := strings.Cut(target, "|")
	if !ok || token == "" || chatID == "" {
		return fmt.Errorf("telegram target must be <bot_token>|<chat_id>")
	}
	body, _ := json.Marshal(map[string]any{
		"chat_id":                  chatID,
		"text":                     text,
		"disable_web_page_preview": true,
	})
	resp, err := notifyHTTPClient.Post("https://api.telegram.org/bot"+token+"/sendMessage", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned %d", resp.StatusCode)
	}
	return nil
}

// formatNotification renders a short, human-readable message for an event. Keys
// are sorted so output is deterministic.
func formatNotification(event string, fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	fmt.Fprintf(&b, "mailx: %s\n", event)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, fields[k])
	}
	return strings.TrimRight(b.String(), "\n")
}
