package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// ---- Message history & status ------------------------------------------------

// handleAPIMessageGet returns the stored record for one message by its id.
func (s *Server) handleAPIMessageGet(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "read") {
		return
	}
	if !s.requireTransactional(w) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "message id is required")
		return
	}
	m, err := s.store.APIMessageByMessageID(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "message not found")
		return
	}
	writeJSON(w, http.StatusOK, messageView(m))
}

// handleAPIMessagesList lists recent messages, optionally filtered by tag.
func (s *Server) handleAPIMessagesList(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "read") {
		return
	}
	if !s.requireTransactional(w) {
		return
	}
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	tag := r.URL.Query().Get("tag")

	msgs, err := s.store.ListAPIMessages(r.Context(), time.Now().AddDate(0, 0, -days), tag, limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "failed to list messages")
		return
	}

	views := make([]map[string]any, 0, len(msgs))
	for i := range msgs {
		views = append(views, messageView(&msgs[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": views})
}

// ---- Templates ----------------------------------------------------------------

// apiTemplateInput is the POST /api/v1/templates request body.
type apiTemplateInput struct {
	Name    string `json:"name"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

func (s *Server) handleAPITemplatesList(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "read") {
		return
	}
	if !s.requireTransactional(w) {
		return
	}
	templates, err := s.store.APITemplates(r.Context())
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "failed to list templates")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": templates})
}

// handleAPITemplateCreate inserts or updates a named template (upsert on name).
func (s *Server) handleAPITemplateCreate(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "write") {
		return
	}
	if !s.requireTransactional(w) {
		return
	}
	var in apiTemplateInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	if in.Subject == "" && in.Text == "" && in.HTML == "" {
		writeAPIError(w, http.StatusBadRequest, "bad_request", "subject, text or html is required")
		return
	}

	existing, err := s.store.APITemplateByName(r.Context(), in.Name)
	if err == nil && existing != nil {
		if err := s.store.UpdateAPITemplate(r.Context(), models.APITemplate{Name: in.Name, Subject: in.Subject, Text: in.Text, HTML: in.HTML}); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal", "failed to update template")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": in.Name, "updated": true})
		return
	}

	if _, err := s.store.InsertAPITemplate(r.Context(), models.APITemplate{Name: in.Name, Subject: in.Subject, Text: in.Text, HTML: in.HTML}); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "failed to create template")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": in.Name, "created": true})
}

func (s *Server) handleAPITemplateGet(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "read") {
		return
	}
	if !s.requireTransactional(w) {
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	t, err := s.store.APITemplateByName(r.Context(), name)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "template not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleAPITemplateDelete(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorize(w, r, "write") {
		return
	}
	if !s.requireTransactional(w) {
		return
	}
	name := strings.TrimSpace(r.PathValue("name"))
	deleted, err := s.store.DeleteAPITemplate(r.Context(), name)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "internal", "failed to delete template")
		return
	}
	if !deleted {
		writeAPIError(w, http.StatusNotFound, "not_found", "template not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
