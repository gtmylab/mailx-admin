package server

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/mutations"
)

func (s *Server) handleDomainNew(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "domain_form", map[string]any{
		"Domain": nil,
	})
}

// ---- Preview: user create ----
//
// The client first POSTs the form to /preview/user-create, which returns
// a modal fragment showing the diff. The form's real submit only fires when
// the admin clicks "Confirm" in that modal.

func (s *Server) handlePreviewUserCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	quota, _ := strconv.Atoi(r.FormValue("quota_mb"))

	input := mutations.CreateUserInput{
		DomainID: domainID,
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
		QuotaMB:  quota,
		IsAdmin:  r.FormValue("is_admin") == "on",
	}

	// Preview mode: run the mutation against a tx, then roll back
	res, err := s.mutations.Preview(r.Context(), func(tx *sql.Tx) error {
		// Duplicate the CreateUser validation logic, but against tx
		return s.mutations.ApplyCreateUserToTx(r.Context(), tx, input)
	})
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	s.renderPartial(w, "preview_diff", map[string]any{
		"Title":  "Confirm: Create user",
		"Action": "/users",
		"Diffs":  buildDiffs(res.Changes, 200),
		"Fields": r.Form, // preserve form values for the real submit
	})
}

func (s *Server) handlePreviewDomainCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	input := mutations.CreateDomainInput{
		Name:         r.FormValue("name"),
		MakePrimary:  r.FormValue("make_primary") == "on",
		GenerateDKIM: r.FormValue("generate_dkim") == "on",
	}

	res, err := s.mutations.Preview(r.Context(), func(tx *sql.Tx) error {
		return s.mutations.ApplyCreateDomainToTx(r.Context(), tx, input)
	})
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	s.renderPartial(w, "preview_diff", map[string]any{
		"Title":  "Confirm: Create domain",
		"Action": "/domains",
		"Diffs":  buildDiffs(res.Changes, 200),
		"Fields": r.Form,
	})
}

func (s *Server) handlePreviewDomainDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	res, err := s.mutations.Preview(r.Context(), func(tx *sql.Tx) error {
		// Check for users; refuse if any
		var count int
		if err := tx.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM users WHERE domain_id = ? AND active = 1`, id,
		).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return fmt.Errorf("cannot delete domain with %d active user(s)", count)
		}
		_, err := tx.ExecContext(r.Context(), `DELETE FROM domains WHERE id = ?`, id)
		return err
	})
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	s.renderPartial(w, "preview_diff", map[string]any{
		"Title":  "Confirm: DELETE domain (irreversible)",
		"Action": "/domains/" + strconv.FormatInt(id, 10),
		"Method": "DELETE",
		"Diffs":  buildDiffs(res.Changes, 200),
		"Danger": true,
	})
}

// ---- Real create ----

func (s *Server) handleDomainCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	input := mutations.CreateDomainInput{
		Name:         r.FormValue("name"),
		MakePrimary:  r.FormValue("make_primary") == "on",
		GenerateDKIM: r.FormValue("generate_dkim") == "on",
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.CreateDomain(r.Context(), actor, input); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/domains?flash="+encodeFlash("Domain "+input.Name+" created"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.DeleteDomain(r.Context(), actor, id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/domains?flash="+encodeFlash("Domain deleted"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDomainSetPrimary(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.SetPrimaryDomain(r.Context(), actor, id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/domains/"+strconv.FormatInt(id, 10)+"?flash="+encodeFlash("Primary domain updated"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDomainRegenerateDKIM(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.RegenerateDKIM(r.Context(), actor, id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/domains/"+strconv.FormatInt(id, 10)+"?flash="+encodeFlash("DKIM key regenerated"))
	w.WriteHeader(http.StatusOK)
}
