package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func TestHashAPIKey(t *testing.T) {
	const raw = "mx_abc123"
	sum := sha256.Sum256([]byte(raw))
	if want := hex.EncodeToString(sum[:]); hashAPIKey(raw) != want {
		t.Errorf("hashAPIKey = %q, want %q", hashAPIKey(raw), want)
	}
	if got := hashAPIKey(raw); len(got) != 64 {
		t.Errorf("hashAPIKey length = %d, want 64 hex chars", len(got))
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name string
		auth string
		want string
	}{
		{"bearer", "Bearer mx_abc", "mx_abc"},
		{"lowercase scheme", "bearer mx_abc", "mx_abc"},
		{"extra spaces", "Bearer    mx_abc   ", "mx_abc"},
		{"missing", "", ""},
		{"wrong scheme", "Basic mx_abc", ""},
		{"no space", "Bearermx_abc", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if got := bearerToken(r); got != tc.want {
				t.Errorf("bearerToken = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAPIKeyHasScope(t *testing.T) {
	cases := []struct {
		scopes      string
		read, write bool
	}{
		{"read", true, false},
		{"write", true, true},
		{"admin", true, true},
		{"", false, false},
	}
	for _, tc := range cases {
		k := &models.APIKey{Scopes: tc.scopes}
		if got := apiKeyHasScope(k, "read"); got != tc.read {
			t.Errorf("scopes %q read = %v, want %v", tc.scopes, got, tc.read)
		}
		if got := apiKeyHasScope(k, "write"); got != tc.write {
			t.Errorf("scopes %q write = %v, want %v", tc.scopes, got, tc.write)
		}
	}
	if apiKeyHasScope(nil, "read") {
		t.Error("nil key should never have scope")
	}
}

func TestAPIStringListUnmarshal(t *testing.T) {
	var single apiStringList
	if err := json.Unmarshal([]byte(`"a@example.com"`), &single); err != nil {
		t.Fatalf("string form: %v", err)
	}
	if len(single) != 1 || single[0] != "a@example.com" {
		t.Errorf("string form = %v", single)
	}

	var multi apiStringList
	if err := json.Unmarshal([]byte(`["a@example.com","b@example.com"]`), &multi); err != nil {
		t.Fatalf("array form: %v", err)
	}
	if len(multi) != 2 || multi[0] != "a@example.com" || multi[1] != "b@example.com" {
		t.Errorf("array form = %v", multi)
	}
}

func TestBuildTransactionalMessage(t *testing.T) {
	msg, err := buildTransactionalMessage(
		"<msg-id@example.com>",
		"sender@example.com",
		[]string{"a@example.com", "b@example.com"},
		nil, nil, "",
		"Hello",
		"plain body",
		"<b>html</b>",
		nil, nil,
	)
	if err != nil {
		t.Fatalf("buildTransactionalMessage: %v", err)
	}
	s := string(msg)

	for _, want := range []string{
		"From: sender@example.com",
		"To: a@example.com, b@example.com",
		"Subject: Hello",
		"MIME-Version: 1.0",
		"multipart/alternative",
		"text/plain; charset=UTF-8",
		"text/html; charset=UTF-8",
		"plain body",
		"<b>html</b>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("message missing %q", want)
		}
	}
}

func TestBuildTransactionalMessageSanitizesHeaders(t *testing.T) {
	msg, err := buildTransactionalMessage(
		"<msg-id@example.com>",
		"from@example.com",
		[]string{"a@example.com"},
		nil, nil, "",
		"Hi\r\nBcc: evil@example.com",
		"body",
		"",
		nil, nil,
	)
	if err != nil {
		t.Fatalf("buildTransactionalMessage: %v", err)
	}
	s := string(msg)

	if strings.Contains(s, "\nBcc:") || strings.Contains(s, "\r\nBcc:") {
		t.Errorf("subject CRLF injected a Bcc header: %q", s)
	}
	if !strings.Contains(s, "Subject: Hi  Bcc: evil@example.com") {
		t.Errorf("subject was not flattened: %q", s)
	}
}

func TestHeaderSafe(t *testing.T) {
	if got := headerSafe(" a\r\nb "); got != "a  b" {
		t.Errorf("headerSafe = %q, want %q", got, "a  b")
	}
}
