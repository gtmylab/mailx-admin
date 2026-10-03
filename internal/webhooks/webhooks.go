// Package webhooks delivers outbound event notifications to operator-registered
// endpoints. Every delivery is signed with HMAC-SHA256 of the webhook's secret
// (so the receiver can verify the sender) and recorded in webhook_deliveries (so
// the operator can audit what was sent and why it failed).
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// Store is the subset of *store.Store the dispatcher needs, kept as an interface
// so the dispatcher can be tested without a database.
type Store interface {
	ListWebhooks(ctx context.Context) ([]models.Webhook, error)
	InsertWebhookDelivery(ctx context.Context, d models.WebhookDelivery) error
}

// Delivery headers.
const (
	HeaderEvent     = "X-MailX-Event"
	HeaderSignature = "X-MailX-Signature"
)

// maxResponseBody bounds how much of a webhook response is copied into the
// delivery log, so a runaway endpoint cannot fill the database.
const maxResponseBody = 4 << 10

// Dispatcher delivers events to subscribed webhooks and records every attempt.
type Dispatcher struct {
	store  Store
	client *http.Client
	logger *slog.Logger
}

// New builds a Dispatcher with a 10s per-delivery HTTP budget.
func New(st Store, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Dispatcher{
		store:  st,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: logger,
	}
}

// Dispatch sends event to every active webhook subscribed to it. The payload is
// wrapped as {event, timestamp, data} and signed. Dispatch is best-effort and
// never returns an error: the delivery log is the record of what happened.
func (d *Dispatcher) Dispatch(ctx context.Context, event string, data any) {
	hooks, err := d.store.ListWebhooks(ctx)
	if err != nil {
		d.logger.Warn("webhook dispatch: list webhooks", "err", err)
		return
	}

	body, err := json.Marshal(map[string]any{
		"event":     event,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"data":      data,
	})
	if err != nil {
		d.logger.Warn("webhook dispatch: marshal payload", "event", event, "err", err)
		return
	}

	for _, h := range hooks {
		if !h.Active || !subscribed(h, event) {
			continue
		}
		d.deliver(ctx, h, event, body)
	}
}

func (d *Dispatcher) deliver(ctx context.Context, h models.Webhook, event string, body []byte) {
	delivery := models.WebhookDelivery{
		WebhookID: h.ID,
		Event:     event,
		Payload:   string(body),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		d.record(ctx, delivery, false, 0, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderEvent, event)
	if h.Secret != "" {
		req.Header.Set(HeaderSignature, "sha256="+sign(h.Secret, body))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		d.record(ctx, delivery, false, 0, err.Error())
		return
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, io.LimitReader(resp.Body, maxResponseBody))

	d.record(ctx, delivery, resp.StatusCode >= 200 && resp.StatusCode < 300, resp.StatusCode, buf.String())
}

func (d *Dispatcher) record(ctx context.Context, delivery models.WebhookDelivery, success bool, status int, response string) {
	delivery.Success = success
	delivery.StatusCode = status
	delivery.Response = response
	if err := d.store.InsertWebhookDelivery(ctx, delivery); err != nil {
		d.logger.Warn("webhook dispatch: log delivery", "webhook_id", delivery.WebhookID, "event", delivery.Event, "err", err)
	}
}

// sign returns the hex HMAC-SHA256 of body under secret.
func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// subscribed reports whether a webhook receives event. A webhook subscribed to
// "*" receives everything.
func subscribed(h models.Webhook, event string) bool {
	for _, e := range h.Events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}
