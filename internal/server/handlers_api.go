package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// ---- JSON plumbing ---------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if v == nil {
		w.WriteHeader(status)
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

// ---- Bearer authentication -------------------------------------------------

type apiKeyCtxKey struct{}

func apiKeyFromContext(ctx context.Context) *models.APIKey {
	k, _ := ctx.Value(apiKeyCtxKey{}).(*models.APIKey)
	return k
}

// bearerToken extracts the token from an Authorization: Bearer header, if any.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// hashAPIKey returns the SHA-256 hex digest of a key. Only the digest is stored,
// so the lookup path and the key-creation path must agree on this spelling.
func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// apiKeyHasScope reports whether a key grants the requested scope. "admin" grants
// everything; "write" implies "read".
func apiKeyHasScope(k *models.APIKey, scope string) bool {
	if k == nil {
		return false
	}
	switch scope {
	case "read":
		return k.Scopes == "read" || k.Scopes == "write" || k.Scopes == "admin"
	case "write":
		return k.Scopes == "write" || k.Scopes == "admin"
	default:
		return k.Scopes == "admin"
	}
}

// requireAPIKey authenticates /api/v1 requests with a bearer key and stashes the
// resolved key in the request context. Missing, unknown, inactive and expired
// keys all answer 401 JSON.
func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := bearerToken(r)
		if key == "" {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}

		k, err := s.store.APIKeyByHash(r.Context(), hashAPIKey(key))
		if err != nil || k == nil {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "invalid API key")
			return
		}
		if !k.Active {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "API key is inactive")
			return
		}
		if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now()) {
			writeAPIError(w, http.StatusUnauthorized, "unauthorized", "API key has expired")
			return
		}

		s.store.TouchAPIKey(r.Context(), k.ID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiKeyCtxKey{}, k)))
	})
}

// apiAuthorize enforces a scope on the authenticated key and answers 403 when it
// is not granted. It reports whether the handler may proceed.
func (s *Server) apiAuthorize(w http.ResponseWriter, r *http.Request, scope string) bool {
	if !apiKeyHasScope(apiKeyFromContext(r.Context()), scope) {
		writeAPIError(w, http.StatusForbidden, "forbidden", "insufficient scope: requires "+scope)
		return false
	}
	return true
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	return dec.Decode(dst)
}

// ---- Suppressions ----------------------------------------------------------

func (s *Server) handleAPISuppressionsList(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "read") {
		return
	}
	sups, err := s.store.ListSuppressions(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "failed to list suppressions")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"suppressions": sups})
}

func (s *Server) handleAPISuppressionCreate(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "write") {
		return
	}
	var in struct {
		Email  string `json:"email"`
		Reason string `json:"reason"`
		Source string `json:"source"`
	}
	if err := decodeJSONBody(r, &in); err != nil {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}

	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if in.Email == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "email is required")
		return
	}
	if in.Reason == "" {
		in.Reason = "manual"
	}
	if in.Source == "" {
		in.Source = "api"
	}

	id, err := s.store.InsertSuppression(r.Context(), models.Suppression{
		Email:  in.Email,
		Reason: in.Reason,
		Source: in.Source,
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeAPIError(w, http.StatusConflict, "conflict", "suppression already exists")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "internal", "failed to create suppression")
		return
	}
	s.requestSync("suppressions.change")
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "email": in.Email})
}

func (s *Server) handleAPISuppressionDelete(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "write") {
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PathValue("email")))
	if email == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "email is required")
		return
	}

	deleted, err := s.store.DeleteSuppressionByEmail(r.Context(), email)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "failed to delete suppression")
		return
	}
	if !deleted {
		writeAPIError(w, http.StatusNotFound, "not_found", "suppression not found")
		return
	}
	s.requestSync("suppressions.change")
	w.WriteHeader(http.StatusNoContent)
}

// ---- Transactional send ----------------------------------------------------

// apiMessage is the POST /api/v1/messages request body. To accepts a single
// address or an array, so a one-off send and a small batch share one field.
type apiMessage struct {
	From    string        `json:"from"`
	To      apiStringList `json:"to"`
	Subject string        `json:"subject"`
	Text    string        `json:"text"`
	HTML    string        `json:"html"`
}

// apiStringList unmarshals either a JSON string or a JSON array of strings.
type apiStringList []string

func (l *apiStringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '[' {
		var ss []string
		if err := json.Unmarshal(b, &ss); err != nil {
			return err
		}
		*l = ss
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*l = []string{s}
	return nil
}

func (s *Server) handleAPIMessages(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "write") {
		return
	}

	var in apiMessage
	if err := decodeJSONBody(r, &in); err != nil {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}

	var to []string
	for _, t := range in.To {
		if t = strings.TrimSpace(t); t != "" {
			to = append(to, t)
		}
	}
	if len(to) == 0 {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "at least one recipient is required")
		return
	}
	if in.Subject == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "subject is required")
		return
	}
	if in.Text == "" && in.HTML == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "text or html is required")
		return
	}

	from := strings.TrimSpace(in.From)
	if from == "" {
		from = "admin@" + s.primaryDomain(r.Context())
	}

	msg := buildTransactionalMessage(from, to, in.Subject, in.Text, in.HTML)
	// Same path as the welcome mail: Postfix's sendmail with -t reading the
	// recipients from the headers, and -f setting the envelope sender so bounces
	// reach the admin account. The 20s budget leaves headroom under the request
	// deadline; queueing a message is effectively instant.
	if _, err := execx.OutputStdin(r.Context(), 20*time.Second, msg, "sendmail", "-f", from, "-t", "-i"); err != nil {
		writeAPIError(w, http.StatusBadGateway, "send_failed", "sendmail rejected the message: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted":   true,
		"from":       from,
		"recipients": len(to),
		"subject":    in.Subject,
	})
}

// buildTransactionalMessage assembles a multipart/alternative message (plain text
// and HTML) with CR/LF stripped from every header so a caller cannot inject
// extra headers into the queue.
func buildTransactionalMessage(from string, to []string, subject, text, htmlPart string) []byte {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	fmt.Fprintf(&buf, "From: %s\r\n", headerSafe(from))
	fmt.Fprintf(&buf, "To: %s\r\n", headerSafe(strings.Join(to, ", ")))
	fmt.Fprintf(&buf, "Subject: %s\r\n", headerSafe(subject))
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n", w.Boundary())
	fmt.Fprintf(&buf, "\r\n")

	if text != "" {
		p, _ := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=UTF-8"}})
		fmt.Fprintf(p, "%s\r\n", text)
	}
	if htmlPart != "" {
		h, _ := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=UTF-8"}})
		fmt.Fprintf(h, "%s\r\n", htmlPart)
	}

	_ = w.Close()
	return buf.Bytes()
}

// headerSafe removes CR and LF so a value is safe to place in a message header.
func headerSafe(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}
