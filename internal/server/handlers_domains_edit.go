package server

import (
	"net/http"
	"strconv"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/mutations"
)

// handleDomainEdit renders the rename dialog for a domain.
//
// GET /domains/{id}/edit is requested with hx-target="#modal-host" from the
// domain list and the domain page. It used to be missing entirely, which is why
// the panel had no way to change a domain after creating it.
func (s *Server) handleDomainEdit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	domain, err := s.getDomainByID(r.Context(), id)
	if err != nil {
		s.renderError(w, 404, "Domain not found")
		return
	}

	s.renderPartial(w, "domain_form", map[string]any{
		"Domain": domain,
		"Action": "/domains/" + strconv.FormatInt(id, 10),
		"Method": "PATCH",
	})
}

// handleDomainUpdate renames a domain.
//
// PATCH /domains/{id} with form field "name". The mutation rewrites the stored
// address of every mailbox on the domain inside the same transaction, so no
// user row is left pointing at the old name.
func (s *Server) handleDomainUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.UpdateDomain(r.Context(), actor, mutations.UpdateDomainInput{
		DomainID: id,
		Name:     r.FormValue("name"),
	}); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	// Back to the (renamed) detail page, where the flash toast explains what
	// happened. HX-Redirect makes htmx perform a full navigation.
	w.Header().Set("HX-Redirect", "/domains/"+strconv.FormatInt(id, 10)+"?flash="+encodeFlash("Domain renamed"))
	w.WriteHeader(http.StatusOK)
}
