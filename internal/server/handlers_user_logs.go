package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// handleUserLogs renders the per-user message audit: every mail event that
// touched this mailbox (as sender or recipient), retained for up to 365 days.
func (s *Server) handleUserLogs(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}

	u, err := s.loadUserForUsage(r.Context(), userID)
	if err != nil {
		s.renderError(w, 404, "User not found")
		return
	}

	q := r.URL.Query()
	limit := 100
	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	status := q.Get("status")
	search := strings.TrimSpace(q.Get("q"))

	events, total, err := s.userLogEvents(r.Context(), u.Email, status, search, limit, offset)
	if err != nil {
		s.renderError(w, 500, "Failed to load message audit")
		return
	}

	first, last := 0, 0
	if len(events) > 0 {
		first = offset + 1
		last = offset + len(events)
	}
	prev := offset - limit
	if prev < 0 {
		prev = 0
	}

	data := map[string]any{
		"User":       u,
		"Events":     events,
		"Status":     status,
		"Search":     search,
		"Total":      total,
		"First":      first,
		"Last":       last,
		"HasMore":    offset+len(events) < total,
		"PrevOffset": prev,
		"NextOffset": offset + limit,
	}

	if r.Header.Get("HX-Request") == "true" {
		s.renderPartial(w, "user_log_rows", data)
		return
	}

	s.render(w, 200, "user_logs.html", s.newPageData(w, r, "Message audit · "+u.Email, "users", data))
}

// userLogEvents returns the mail events where email was the sender or the
// recipient, newest first, plus the matching total.
func (s *Server) userLogEvents(ctx context.Context, email, status, search string, limit, offset int) ([]logEvent, int, error) {
	clauses := []string{"(from_addr = ? OR to_addr = ?)"}
	args := []any{email, email}
	if status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}
	if search != "" {
		clauses = append(clauses, "(message LIKE ? OR raw LIKE ?)")
		args = append(args, "%"+search+"%", "%"+search+"%")
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT id, ts, COALESCE(queue_id,''), service, COALESCE(action,''), COALESCE(status,''),
		       COALESCE(from_addr,''), COALESCE(to_addr,''), COALESCE(domain,''),
		       COALESCE(client_ip,''), COALESCE(relay,''), COALESCE(message,'')
		FROM mail_events %s ORDER BY ts DESC LIMIT ? OFFSET ?`, where),
		append(append([]any{}, args...), limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []logEvent
	for rows.Next() {
		var e logEvent
		if err := rows.Scan(&e.ID, &e.Ts, &e.QueueID, &e.Service, &e.Action, &e.Status,
			&e.FromAddr, &e.ToAddr, &e.Domain, &e.ClientIP, &e.Relay, &e.Message); err != nil {
			continue
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int
	_ = s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM mail_events %s", where), args...).Scan(&total)
	return events, total, nil
}
