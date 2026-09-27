package server

import (
	"net/http"
	"strconv"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/mutations"
)

// handleAliasCreate creates an alias on a domain.
//
// POST /domains/{id}/aliases with form fields "source" (local part, or
// "@domain" for a catch-all) and "destination" (comma-separated addresses).
func (s *Server) handleAliasCreate(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	in := mutations.CreateAliasInput{
		DomainID:    domainID,
		Source:      r.FormValue("source"),
		Destination: r.FormValue("destination"),
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.CreateAlias(r.Context(), actor, in); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/domains/"+strconv.FormatInt(domainID, 10)+"?flash="+encodeFlash("Alias created"))
	w.WriteHeader(http.StatusOK)
}

// handleAliasUpdate changes the destination(s) of an existing alias.
//
// PATCH /aliases/{id} with form field "destination".
func (s *Server) handleAliasUpdate(w http.ResponseWriter, r *http.Request) {
	aliasID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid alias ID")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	in := mutations.UpdateAliasInput{
		AliasID:     aliasID,
		Destination: r.FormValue("destination"),
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.UpdateAlias(r.Context(), actor, in); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", aliasRedirect(r)+"?flash="+encodeFlash("Alias updated"))
	w.WriteHeader(http.StatusOK)
}

// handleAliasDelete removes an alias.
//
// DELETE /aliases/{id}; the optional "domain_id" query parameter is used to
// send the admin back to the domain page they came from.
func (s *Server) handleAliasDelete(w http.ResponseWriter, r *http.Request) {
	aliasID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid alias ID")
		return
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.DeleteAlias(r.Context(), actor, aliasID); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", aliasRedirect(r)+"?flash="+encodeFlash("Alias deleted"))
	w.WriteHeader(http.StatusOK)
}

// aliasRedirect returns the page to return to after an alias mutation: the
// domain detail page when the caller passed ?domain_id=, otherwise the domain
// list.
func aliasRedirect(r *http.Request) string {
	if did, err := strconv.ParseInt(r.URL.Query().Get("domain_id"), 10, 64); err == nil && did > 0 {
		return "/domains/" + strconv.FormatInt(did, 10)
	}
	return "/domains"
}
