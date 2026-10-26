package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

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

// handleDomainRateLimitForm renders the outgoing rate-limit dialog.
//
// GET /domains/{id}/rate-limit, requested with hx-target="#modal-host" from the
// domain page. It is a dialog rather than a field on the rename form because a
// limit is a policy decision with three parts, and the rename form has to stay
// a two-field dialog.
func (s *Server) handleDomainRateLimitForm(w http.ResponseWriter, r *http.Request) {
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

	s.renderPartial(w, "domain_rate_limit_form", map[string]any{
		"Domain": domain,
		"Action": "/domains/" + strconv.FormatInt(id, 10) + "/rate-limit",
	})
}

// handleDomainRateLimitUpdate stores the outgoing rate limit.
//
// PATCH /domains/{id}/rate-limit with per_hour, burst and action. The limit is
// enforcement by postfwd, not by the panel: the mutation writes the row, and the
// sync renders /etc/postfwd.cf and the Postfix policy hook from it (see
// reconciler.RenderPostfwdConf). "Nothing happens immediately" is therefore the
// honest thing to say until the sync has run.
func (s *Server) handleDomainRateLimitUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid domain ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	perHour, err := strconv.Atoi(strings.TrimSpace(r.FormValue("per_hour")))
	if err != nil {
		s.renderFormError(w, "Messages per hour has to be a number; use 0 for no cap.")
		return
	}
	perDay := 0
	if v := strings.TrimSpace(r.FormValue("per_day")); v != "" {
		perDay, err = strconv.Atoi(v)
		if err != nil {
			s.renderFormError(w, "Messages per day has to be a number; leave it empty for no cap.")
			return
		}
	}
	perMonth := 0
	if v := strings.TrimSpace(r.FormValue("per_month")); v != "" {
		perMonth, err = strconv.Atoi(v)
		if err != nil {
			s.renderFormError(w, "Messages per month has to be a number; leave it empty for no cap.")
			return
		}
	}
	burst := 0
	if v := strings.TrimSpace(r.FormValue("burst")); v != "" {
		burst, err = strconv.Atoi(v)
		if err != nil {
			s.renderFormError(w, "The burst allowance has to be a number; leave it empty for none.")
			return
		}
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.SetDomainRateLimit(r.Context(), actor, mutations.SetDomainRateLimitInput{
		DomainID: id,
		PerHour:  perHour,
		PerDay:   perDay,
		PerMonth: perMonth,
		Burst:    burst,
		Action:   r.FormValue("action"),
	}); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	// Say which caps are now in force: "set to 500 messages per hour" is wrong
	// once a day or month cap is also present, and an operator who cannot see
	// the result of their edit assumes it did not happen.
	var parts []string
	if perHour > 0 {
		parts = append(parts, fmt.Sprintf("%d/hour", perHour))
	}
	if perDay > 0 {
		parts = append(parts, fmt.Sprintf("%d/day", perDay))
	}
	if perMonth > 0 {
		parts = append(parts, fmt.Sprintf("%d/month", perMonth))
	}
	msg := "Outgoing rate limit removed"
	if len(parts) > 0 {
		msg = "Outgoing caps set to " + strings.Join(parts, ", ")
		if burst > 0 {
			msg += fmt.Sprintf(" with a %d/minute burst", burst)
		}
	}
	w.Header().Set("HX-Redirect", "/domains/"+strconv.FormatInt(id, 10)+"?flash="+encodeFlash(msg))
	w.WriteHeader(http.StatusOK)
}
