package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	// The list used to show active rows of active domains only, so a mailbox
	// that was disabled - or that exists only in the server's own passwd file -
	// was simply absent. Reading the whole set and hiding the disabled ones
	// afterwards lets the filter say how many there are, instead of a missing
	// user looking like a bug.
	showInactive := r.URL.Query().Get("status") == "all"

	all, err := s.store.Users(ctx, true)
	if err != nil {
		s.renderError(w, 500, "Failed to load users")
		return
	}

	users := make([]models.User, 0, len(all))
	disabled := 0
	for _, u := range all {
		if !u.Active {
			disabled++
			if !showInactive {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(u.Email), q) {
			continue
		}
		users = append(users, u)
	}

	data := map[string]any{
		"Users":        users,
		"Total":        len(users),
		"Disabled":     disabled,
		"Query":        q,
		"ShowInactive": showInactive,
	}

	// HTMX partial request
	if r.Header.Get("HX-Request") == "true" {
		s.renderPartial(w, "user_table", map[string]any{"Data": data})
		return
	}

	s.render(w, 200, "users.html", s.newPageData(w, r, "Users", "users", data))
}

func (s *Server) handleUserDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}

	// The whole set: a disabled mailbox still has a page, and finding it must not
	// depend on a filter.
	users, err := s.store.Users(ctx, true)
	if err != nil {
		s.renderError(w, 500, "Failed to load user")
		return
	}

	var found *models.User
	for i := range users {
		if users[i].ID == id {
			found = &users[i]
			break
		}
	}
	if found == nil {
		s.renderError(w, 404, "User not found")
		return
	}

	s.render(w, 200, "user_detail.html", s.newPageData(w, r, found.Email, "users", map[string]any{"User": found}))
}
