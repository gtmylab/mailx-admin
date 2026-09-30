package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/mutations"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleUserSieve(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}

	// Load user
	//
	// The mailbox kind travels with it: the Sieve path is derived from the
	// mailbox's own home (models.User.MailHome), so a system mailbox's rules
	// have to be written into /home/<user>/sieve, not the vmail tree.
	var u models.User
	err = s.db.QueryRowContext(r.Context(), `
        SELECT u.id, u.domain_id, u.username, u.email, u.quota_mb, u.active,
               u.is_admin, d.name,
               u.kind, COALESCE(u.sys_uid, 0), COALESCE(u.sys_gid, 0), COALESCE(u.home, '')
        FROM users u JOIN domains d ON d.id = u.domain_id
        WHERE u.id = ?
    `, userID).Scan(&u.ID, &u.DomainID, &u.Username, &u.Email, &u.QuotaMB, &u.Active, &u.IsAdmin, &u.DomainName,
		&u.Kind, &u.SysUID, &u.SysGID, &u.Home)
	if err != nil {
		s.renderError(w, 404, "User not found")
		return
	}

	rules := s.loadSieveRules(r.Context(), userID)

	s.render(w, 200, "user_sieve.html", s.newPageData(w, r,
		"Rules · "+u.Email, "users",
		map[string]any{
			"User":  u,
			"Rules": rules,
		},
	))
}

func (s *Server) handleSieveRuleNew(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ruleType := r.URL.Query().Get("type")
	if ruleType == "" {
		ruleType = "vacation"
	}

	s.renderPartial(w, "sieve_rule_form", map[string]any{
		"UserID":   userID,
		"RuleType": ruleType,
		"Rule":     nil,
	})
}

func (s *Server) handleSieveRuleCreate(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	ruleType := r.FormValue("rule_type")
	cfg, err := buildRuleConfig(ruleType, r)
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	cfgJSON, _ := json.Marshal(cfg)

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	_, err = s.mutations.Apply(r.Context(), actor, "sieve.create", map[string]any{
		"user_id":   userID,
		"rule_type": ruleType,
	}, func(tx *sql.Tx) error {
		var maxPos int
		_ = tx.QueryRowContext(r.Context(),
			`SELECT COALESCE(MAX(position), 0) FROM sieve_rules WHERE user_id = ?`, userID).Scan(&maxPos)

		_, err := tx.ExecContext(r.Context(), `
            INSERT INTO sieve_rules (user_id, rule_type, enabled, position, config)
            VALUES (?, ?, 1, ?, ?)
        `, userID, ruleType, maxPos+1, string(cfgJSON))
		return err
	})
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/users/"+strconv.FormatInt(userID, 10)+"/sieve?flash="+encodeFlash("Rule added"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSieveRuleDelete(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.ParseInt(r.PathValue("uid"), 10, 64)
	ruleID, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid rule ID")
		return
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	_, err = s.mutations.Apply(r.Context(), actor, "sieve.delete", map[string]any{
		"rule_id": ruleID,
	}, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(r.Context(), `DELETE FROM sieve_rules WHERE id = ? AND user_id = ?`, ruleID, userID)
		return err
	})
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/users/"+strconv.FormatInt(userID, 10)+"/sieve?flash="+encodeFlash("Rule removed"))
	w.WriteHeader(http.StatusOK)
}

// ---- helpers ----

func (s *Server) loadSieveRules(ctx context.Context, userID int64) []models.SieveRule {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, rule_type, enabled, position, config, created_at, updated_at
        FROM sieve_rules WHERE user_id = ? ORDER BY position
    `, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []models.SieveRule
	for rows.Next() {
		var r models.SieveRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.UserID, &r.RuleType, &enabled, &r.Position, &r.Config, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	return out
}

func buildRuleConfig(ruleType string, r *http.Request) (map[string]any, error) {
	switch ruleType {
	case "vacation":
		return map[string]any{
			"subject": r.FormValue("subject"),
			"message": r.FormValue("message"),
			"days":    atoiDefault(r.FormValue("days"), 7),
		}, nil
	case "forward":
		addr := strings.TrimSpace(r.FormValue("address"))
		if !strings.Contains(addr, "@") {
			return nil, fmt.Errorf("valid email required")
		}
		return map[string]any{
			"address":   addr,
			"keep_copy": r.FormValue("keep_copy") == "on",
		}, nil
	case "move_folder":
		return map[string]any{
			"folder":         r.FormValue("folder"),
			"match_header":   r.FormValue("match_header"),
			"match_contains": r.FormValue("match_contains"),
		}, nil
	case "discard":
		return map[string]any{
			"match_header":   r.FormValue("match_header"),
			"match_contains": r.FormValue("match_contains"),
		}, nil
	case "mark_read":
		return map[string]any{
			"match_header":   r.FormValue("match_header"),
			"match_contains": r.FormValue("match_contains"),
		}, nil
	}
	return nil, fmt.Errorf("unknown rule type")
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
