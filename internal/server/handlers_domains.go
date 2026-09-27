package server

import (
	"net/http"
	"strconv"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
)

func (s *Server) handleDomainsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to load domains")
		return
	}
	s.render(w, 200, "domains.html", pageData{
		Title:     "Domains",
		Session:   auth.SessionFromContext(ctx),
		ActiveNav: "domains",
		Data:      map[string]any{"Domains": snap.Domains},
	})
}

func (s *Server) handleDomainDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to load domain")
		return
	}

	var found *models.Domain
	var users []models.User
	for i := range snap.Domains {
		if snap.Domains[i].ID == id {
			found = &snap.Domains[i]
			break
		}
	}
	if found == nil {
		s.renderError(w, 404, "Domain not found")
		return
	}
	for _, u := range snap.Users {
		if u.DomainID == id {
			users = append(users, u)
		}
	}

	s.render(w, 200, "domain_detail.html", pageData{
		Title:     found.Name,
		Session:   auth.SessionFromContext(ctx),
		ActiveNav: "domains",
		Data: map[string]any{
			"Domain": found,
			"Users":  users,
		},
	})
}
