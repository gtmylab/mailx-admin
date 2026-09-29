package server

import (
	"net/http"
	"strconv"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func (s *Server) handleDomainsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to load domains")
		return
	}

	// Counts come from the same snapshot (one consistent read), so the list page
	// never shows a mailbox count that belongs to a different revision.
	userCount := make(map[int64]int, len(snap.Domains))
	for _, u := range snap.Users {
		userCount[u.DomainID]++
	}
	aliasCount := make(map[int64]int, len(snap.Domains))
	for _, a := range snap.Aliases {
		aliasCount[a.DomainID]++
	}
	missingDKIM := 0
	for _, d := range snap.Domains {
		if d.DKIMPrivateKeyPath == "" {
			missingDKIM++
		}
	}

	s.render(w, 200, "domains.html", s.newPageData(w, r, "Domains", "domains", map[string]any{
		"Domains":     snap.Domains,
		"UserCount":   userCount,
		"AliasCount":  aliasCount,
		"MissingDKIM": missingDKIM,
	}))
}

// handleDomainDetail renders the domain page.
//
// The template expects exactly these three keys: "Domain" (a *models.Domain),
// "Users" and "Aliases" filtered to that domain. domain_detail.html used to be
// a copy of domains.html and ranged over .Data.Domains, so this page rendered
// an empty list no matter what the handler passed.
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

	var users []models.User
	for _, u := range snap.Users {
		if u.DomainID == id {
			users = append(users, u)
		}
	}
	var aliases []models.Alias
	for _, a := range snap.Aliases {
		if a.DomainID == id {
			aliases = append(aliases, a)
		}
	}

	s.render(w, 200, "domain_detail.html", s.newPageData(w, r, found.Name, "domains", map[string]any{
		"Domain":  found,
		"Users":   users,
		"Aliases": aliases,
	}))
}
