package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

type fakeStore struct {
	hooks      []models.Webhook
	deliveries []models.WebhookDelivery
}

func (f *fakeStore) ListWebhooks(ctx context.Context) ([]models.Webhook, error) {
	return f.hooks, nil
}

func (f *fakeStore) InsertWebhookDelivery(ctx context.Context, d models.WebhookDelivery) error {
	f.deliveries = append(f.deliveries, d)
	return nil
}

func TestSign(t *testing.T) {
	got := sign("s3cret", []byte("hello"))
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte("hello"))
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Errorf("sign = %q, want %q", got, want)
	}
}

func TestSubscribed(t *testing.T) {
	cases := []struct {
		events []string
		event  string
		want   bool
	}{
		{[]string{"a.b"}, "a.b", true},
		{[]string{"a.b"}, "c.d", false},
		{[]string{"*"}, "c.d", true},
		{[]string{}, "a.b", false},
		{[]string{"x.y", "a.b"}, "a.b", true},
	}
	for _, tc := range cases {
		if got := subscribed(models.Webhook{Events: tc.events}, tc.event); got != tc.want {
			t.Errorf("subscribed(%v, %q) = %v, want %v", tc.events, tc.event, got, tc.want)
		}
	}
}

func TestDispatchDeliversSignedAndLogs(t *testing.T) {
	var (
		gotBody  []byte
		gotSig   string
		gotEvent string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get(HeaderSignature)
		gotEvent = r.Header.Get(HeaderEvent)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	st := &fakeStore{hooks: []models.Webhook{{
		ID:     7,
		URL:    server.URL,
		Events: []string{"blocklist.listed"},
		Secret: "s3cret",
		Active: true,
	}}}
	New(st, nil).Dispatch(context.Background(), "blocklist.listed", map[string]any{"ip": "1.2.3.4"})

	if want := "sha256=" + sign("s3cret", gotBody); gotSig != want {
		t.Errorf("signature = %q, want %q", gotSig, want)
	}
	if gotEvent != "blocklist.listed" {
		t.Errorf("event header = %q, want %q", gotEvent, "blocklist.listed")
	}

	if len(st.deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(st.deliveries))
	}
	dl := st.deliveries[0]
	if dl.WebhookID != 7 || dl.Event != "blocklist.listed" {
		t.Errorf("delivery meta = %+v", dl)
	}
	if !dl.Success || dl.StatusCode != http.StatusOK {
		t.Errorf("delivery not recorded as success: success=%v status=%d", dl.Success, dl.StatusCode)
	}
	if dl.Response != "ok" {
		t.Errorf("delivery response = %q, want %q", dl.Response, "ok")
	}
}

func TestDispatchSkipsInactiveAndUnsubscribed(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	st := &fakeStore{hooks: []models.Webhook{
		{ID: 1, URL: server.URL, Events: []string{"other.event"}, Active: true},       // not subscribed
		{ID: 2, URL: server.URL, Events: []string{"blocklist.listed"}, Active: false}, // inactive
		{ID: 3, URL: server.URL, Events: []string{"*"}, Active: true},                 // wildcard
	}}
	New(st, nil).Dispatch(context.Background(), "blocklist.listed", map[string]any{"ip": "1.2.3.4"})

	if hits != 1 {
		t.Errorf("requests = %d, want 1 (only the wildcard webhook)", hits)
	}
	if len(st.deliveries) != 1 {
		t.Errorf("deliveries = %d, want 1", len(st.deliveries))
	}
}

func TestDispatchFailureIsLogged(t *testing.T) {
	// A webhook whose URL is refused records a failed delivery rather than
	// panicking or silently dropping the event.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close() // refuse further connections

	st := &fakeStore{hooks: []models.Webhook{{
		ID: 1, URL: url, Events: []string{"blocklist.listed"}, Active: true,
	}}}
	New(st, nil).Dispatch(context.Background(), "blocklist.listed", map[string]any{"ip": "1.2.3.4"})

	if len(st.deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(st.deliveries))
	}
	if st.deliveries[0].Success {
		t.Error("delivery to a closed port was recorded as successful")
	}
}
