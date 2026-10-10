package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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
	From           string            `json:"from"`
	To             apiStringList     `json:"to"`
	CC             apiStringList     `json:"cc"`
	BCC            apiStringList     `json:"bcc"`
	ReplyTo        string            `json:"reply_to"`
	Subject        string            `json:"subject"`
	Text           string            `json:"text"`
	HTML           string            `json:"html"`
	Template       string            `json:"template"`
	Variables      map[string]string `json:"variables"`
	Headers        map[string]string `json:"headers"`
	Attachments    []apiAttachment   `json:"attachments"`
	Tag            string            `json:"tag"`
	IdempotencyKey string            `json:"idempotency_key"`
}

// apiAttachment is one file attachment (or inline image) in a message.
type apiAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        string `json:"data"` // base64
	Inline      bool   `json:"inline"`
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
	if !s.requireTransactional(w) {
		return
	}

	var in apiMessage
	if err := decodeJSONBody(r, &in); err != nil {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}

	key := apiKeyFromContext(r.Context())

	// Idempotency: a retried request returns the original message instead of
	// sending a duplicate.
	if in.IdempotencyKey != "" && key != nil {
		if existing, err := s.store.APIMessageByIdempotency(r.Context(), key.ID, in.IdempotencyKey); err == nil && existing != nil {
			writeJSON(w, http.StatusOK, messageView(existing))
			return
		}
	}

	subject, text, htmlPart := in.Subject, in.Text, in.HTML
	if in.Template != "" {
		t, err := s.store.APITemplateByName(r.Context(), in.Template)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, "not_found", "template not found: "+in.Template)
			return
		}
		subject = renderTemplate(t.Subject, in.Variables)
		text = renderTemplate(t.Text, in.Variables)
		htmlPart = renderTemplate(t.HTML, in.Variables)
		// Explicit fields override the template's.
		if in.Subject != "" {
			subject = in.Subject
		}
		if in.Text != "" {
			text = in.Text
		}
		if in.HTML != "" {
			htmlPart = in.HTML
		}
	}

	to := cleanAddresses(in.To)
	if len(to) == 0 {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "at least one recipient is required")
		return
	}
	if subject == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "subject is required")
		return
	}
	if text == "" && htmlPart == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "text or html is required")
		return
	}

	from := strings.TrimSpace(in.From)
	if from == "" {
		from = "admin@" + s.primaryDomain(r.Context())
	}

	messageID := generateMessageID(s.cfg.Server.Hostname)
	msg, err := buildTransactionalMessage(messageID, from, to, cleanAddresses(in.CC), cleanAddresses(in.BCC),
		in.ReplyTo, subject, text, htmlPart, in.Headers, in.Attachments)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	rec := models.APIMessage{
		MessageID:   messageID,
		FromAddr:    from,
		ToAddr:      jsonString(to),
		CC:          jsonString(in.CC),
		BCC:         jsonString(in.BCC),
		ReplyTo:     in.ReplyTo,
		Subject:     subject,
		Tag:         in.Tag,
		Template:    in.Template,
		Headers:     jsonString(in.Headers),
		Attachments: jsonStringAttachmentMeta(in.Attachments),
		Status:      "queued",
	}
	if key != nil {
		rec.APIKeyID = sql.NullInt64{Int64: key.ID, Valid: true}
	}
	if in.IdempotencyKey != "" {
		rec.IdempotencyKey = sql.NullString{String: in.IdempotencyKey, Valid: true}
	}

	id, err := s.store.InsertAPIMessage(r.Context(), rec)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "failed to record message")
		return
	}

	// Same path as the welcome mail: Postfix's sendmail with -t reading the
	// recipients from the headers, and -f setting the envelope sender so bounces
	// reach the admin account.
	if _, err := execx.OutputStdin(r.Context(), 20*time.Second, msg, "sendmail", "-f", from, "-t", "-i"); err != nil {
		_ = s.store.MarkAPIMessageFailed(r.Context(), id, err.Error())
		writeAPIError(w, http.StatusBadGateway, "send_failed", "sendmail rejected the message: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":         messageID,
		"status":     "queued",
		"from":       from,
		"recipients": len(to),
		"subject":    subject,
		"tag":        in.Tag,
	})
}

// buildTransactionalMessage assembles the RFC 5322 message: headers, an optional
// multipart/alternative body (text + HTML) and optional attachments. Every header
// value has CR/LF stripped so a caller cannot inject extra headers.
func buildTransactionalMessage(messageID, from string, to, cc, bcc []string, replyTo, subject, text, htmlPart string, headers map[string]string, atts []apiAttachment) ([]byte, error) {
	var buf bytes.Buffer
	writeHeader := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, headerSafe(v))
		}
	}

	writeHeader("From", from)
	writeHeader("To", strings.Join(to, ", "))
	writeHeader("Cc", strings.Join(cc, ", "))
	writeHeader("Reply-To", replyTo)
	writeHeader("Subject", subject)
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "Message-ID: %s\r\n", messageID)
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	for k, v := range headers {
		if k != "" {
			writeHeader(k, v)
		}
	}

	hasBody := text != "" || htmlPart != ""

	// No attachments: a single multipart/alternative body.
	if len(atts) == 0 {
		w := multipart.NewWriter(&buf)
		writeHeader("Content-Type", "multipart/alternative; boundary="+w.Boundary())
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
		return buf.Bytes(), nil
	}

	// Attachments: build the alternative body first, then wrap in multipart/mixed.
	var altBuf bytes.Buffer
	alt := multipart.NewWriter(&altBuf)
	if text != "" {
		p, _ := alt.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=UTF-8"}})
		fmt.Fprintf(p, "%s\r\n", text)
	}
	if htmlPart != "" {
		h, _ := alt.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=UTF-8"}})
		fmt.Fprintf(h, "%s\r\n", htmlPart)
	}
	_ = alt.Close()

	mixed := multipart.NewWriter(&buf)
	writeHeader("Content-Type", "multipart/mixed; boundary="+mixed.Boundary())
	fmt.Fprintf(&buf, "\r\n")

	if hasBody {
		p, _ := mixed.CreatePart(textproto.MIMEHeader{
			"Content-Type": {"multipart/alternative; boundary=" + alt.Boundary()},
		})
		_, _ = p.Write(altBuf.Bytes())
	}

	for _, a := range atts {
		data, err := base64.StdEncoding.DecodeString(a.Data)
		if err != nil {
			return nil, fmt.Errorf("attachment %s: invalid base64", a.Filename)
		}
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		disposition := "attachment"
		hdr := textproto.MIMEHeader{
			"Content-Type":              {ct},
			"Content-Disposition":       {fmt.Sprintf("%s; filename=%q", disposition, a.Filename)},
			"Content-Transfer-Encoding": {"base64"},
		}
		if a.Inline {
			hdr["Content-Disposition"] = []string{fmt.Sprintf("inline; filename=%q", a.Filename)}
			hdr["Content-ID"] = []string{"<" + a.Filename + ">"}
		}
		p, _ := mixed.CreatePart(hdr)
		fmt.Fprintf(p, "%s\r\n", base64.StdEncoding.EncodeToString(data))
	}
	_ = mixed.Close()
	return buf.Bytes(), nil
}

// headerSafe removes CR and LF so a value is safe to place in a message header.
func headerSafe(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// transactionalEnabled reports whether the transactional email API is usable. It
// is gated behind Postgres: SQLite is single-writer and is the wrong engine for
// high-volume message logging.
func (s *Server) transactionalEnabled() bool {
	return s.dbDriver == "postgres"
}

func (s *Server) requireTransactional(w http.ResponseWriter) bool {
	if s.transactionalEnabled() {
		return true
	}
	writeAPIError(w, http.StatusServiceUnavailable, "requires_postgres",
		"Transactional email requires Postgres; migrate from the Database page first.")
	return false
}

func cleanAddresses(list apiStringList) []string {
	var out []string
	for _, a := range list {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// renderTemplate substitutes {{key}} placeholders with the given variables.
func renderTemplate(s string, vars map[string]string) string {
	if s == "" || len(vars) == 0 {
		return s
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func jsonStringAttachmentMeta(atts []apiAttachment) string {
	type meta struct {
		Filename string `json:"filename"`
		Size     int    `json:"size"`
		Inline   bool   `json:"inline"`
	}
	out := make([]meta, 0, len(atts))
	for _, a := range atts {
		out = append(out, meta{Filename: a.Filename, Size: len(a.Data), Inline: a.Inline})
	}
	return jsonString(out)
}

func generateMessageID(host string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	if host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("<%x@%s>", b, host)
}

// messageView is the JSON shape of a stored message, used by the idempotency
// short-circuit and GET /api/v1/messages/{id}.
func messageView(m *models.APIMessage) map[string]any {
	var to []string
	_ = json.Unmarshal([]byte(m.ToAddr), &to)
	return map[string]any{
		"id":      m.MessageID,
		"status":  m.Status,
		"from":    m.FromAddr,
		"to":      to,
		"subject": m.Subject,
		"tag":     m.Tag,
		"error":   m.Error,
		"created": m.CreatedAt.Format(time.RFC3339),
	}
}
