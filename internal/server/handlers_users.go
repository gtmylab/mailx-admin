package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
)

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to load users")
		return
	}

	users := snap.Users
	if q != "" {
		filtered := users[:0]
		for _, u := range users {
			if strings.Contains(strings.ToLower(u.Email), q) {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}

	data := map[string]any{
		"Users": users,
		"Total": len(users),
		"Query": q,
	}

	// HTMX partial request
	if r.Header.Get("HX-Request") == "true" {
		s.renderPartial(w, "user_table", map[string]any{"Data": data})
		return
	}

	s.render(w, 200, "users.html", pageData{
		Title:     "Users",
		Session:   auth.SessionFromContext(ctx),
		ActiveNav: "users",
		Data:      data,
	})
}

func (s *Server) handleUserDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}

	// For now, just find in snapshot. Phase 3 adds a proper GetUser.
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to load user")
		return
	}

	var found *models.User
	for i := range snap.Users {
		if snap.Users[i].ID == id {
			found = &snap.Users[i]
			break
		}
	}
	if found == nil {
		s.renderError(w, 404, "User not found")
		return
	}

	s.render(w, 200, "user_detail.html", pageData{
		Title:     found.Email,
		Session:   auth.SessionFromContext(ctx),
		ActiveNav: "users",
		Data:      map[string]any{"User": found},
	})
}
