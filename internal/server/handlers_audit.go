package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
)

func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	rows, err := s.db.QueryContext(ctx, `
        SELECT id, ts, actor, action, COALESCE(target_type, ''), COALESCE(target_id, ''),
               result, COALESCE(detail, ''), COALESCE(remote_ip, '')
        FROM audit_log
        ORDER BY ts DESC
        LIMIT ?
    `, limit)
	if err != nil {
		s.renderError(w, 500, "Failed to load audit log")
		return
	}
	defer rows.Close()

	var entries []audit.Entry
	for rows.Next() {
		var e audit.Entry
		var detail string
		if err := rows.Scan(&e.ID, &e.Ts, &e.Actor, &e.Action,
			&e.TargetType, &e.TargetID, &e.Result, &detail, &e.RemoteIP); err != nil {
			s.logger.Error("scan audit", "err", err)
			continue
		}
		e.Detail = detail
		entries = append(entries, e)
	}

	data := map[string]any{"Entries": entries}

	if r.URL.Query().Get("partial") == "1" || r.Header.Get("HX-Request") == "true" {
		s.renderPartial(w, "audit_table", map[string]any{"Data": data})
		return
	}

	s.render(w, 200, "audit.html", pageData{
		Title:     "Audit Log",
		Session:   auth.SessionFromContext(ctx),
		ActiveNav: "audit",
		Data:      data,
	})
}

var _ = time.Now
