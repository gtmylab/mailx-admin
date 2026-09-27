package server

import (
	"database/sql"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/logs"
	"github.com/gtmylab/mailx-admin/internal/models"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type logFilter struct {
	Domain string
	From   string
	To     string
	Status string
	Action string
	Search string
	Since  string
	Limit  int
	Offset int
}

func (s *Server) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "logs.html", s.newPageData(w, r, "Logs", "logs", nil))
}

// handleLogsList returns the log rows partial. Used both for initial load
// and for HTMX filter changes.
func (s *Server) handleLogsList(w http.ResponseWriter, r *http.Request) {
	f := parseLogFilter(r)

	where, args := buildLogWhere(f)

	query := fmt.Sprintf(`
        SELECT id, ts, COALESCE(queue_id,''), service, COALESCE(action,''), COALESCE(status,''),
               COALESCE(from_addr,''), COALESCE(to_addr,''), COALESCE(domain,''),
               COALESCE(client_ip,''), COALESCE(relay,''), COALESCE(message,'')
        FROM mail_events
        %s
        ORDER BY ts DESC
        LIMIT ? OFFSET ?
    `, where)

	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		s.logger.Error("log query", "err", err)
		s.renderError(w, 500, "Failed to load logs")
		return
	}
	defer rows.Close()

	type row struct {
		ID       int64
		Ts       time.Time
		QueueID  string
		Service  string
		Action   string
		Status   string
		FromAddr string
		ToAddr   string
		Domain   string
		ClientIP string
		Relay    string
		Message  string
	}

	var events []row
	for rows.Next() {
		var e row
		if err := rows.Scan(&e.ID, &e.Ts, &e.QueueID, &e.Service, &e.Action, &e.Status,
			&e.FromAddr, &e.ToAddr, &e.Domain, &e.ClientIP, &e.Relay, &e.Message); err != nil {
			continue
		}
		events = append(events, e)
	}

	s.renderPartial(w, "log_rows", map[string]any{
		"Events": events,
		"Filter": f,
	})
}

// handleLogsLive streams new events via SSE.
func (s *Server) handleLogsLive(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	f := parseLogFilter(r)

	// Track the max ID we've sent so we only push new rows
	var lastID int64
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(MAX(id), 0) FROM mail_events`).Scan(&lastID)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Heartbeat
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			where, args := buildLogWhere(f)
			// Prefix with id > lastID
			if where == "" {
				where = "WHERE id > ?"
			} else {
				where = where + " AND id > ?"
			}
			args = append(args, lastID)

			query := fmt.Sprintf(`
                SELECT id, ts, COALESCE(queue_id,''), service, COALESCE(action,''),
                       COALESCE(status,''), COALESCE(from_addr,''), COALESCE(to_addr,''),
                       COALESCE(domain,''), COALESCE(message,'')
                FROM mail_events %s ORDER BY id ASC LIMIT 100
            `, where)

			rows, err := s.db.QueryContext(r.Context(), query, args...)
			if err != nil {
				continue
			}

			for rows.Next() {
				var id int64
				var ts time.Time
				var qid, svc, action, status, from, to, dom, msg string
				if err := rows.Scan(&id, &ts, &qid, &svc, &action, &status, &from, &to, &dom, &msg); err != nil {
					continue
				}
				lastID = id
				// Send as HTML fragment so the client can just innerHTML-append
				fmt.Fprintf(w, "event: log\ndata: %s\n\n", renderLogRowHTML(id, ts, qid, svc, action, status, from, to, dom, msg))
			}
			rows.Close()
			flusher.Flush()
		}
	}
}

// renderLogRowHTML is a small helper so SSE and initial render use identical markup.
func renderLogRowHTML(id int64, ts time.Time, qid, svc, action, status, from, to, dom, msg string) string {
	// Minimal HTML — no template round-trip for speed
	statusClass := ""
	switch status {
	case "sent":
		statusClass = "text-emerald-400"
	case "deferred":
		statusClass = "text-amber-400"
	case "bounced", "rejected":
		statusClass = "text-red-400"
	}

	html := strings.NewReplacer(
		"<", "&lt;", ">", "&gt;", "&", "&amp;", `"`, "&quot;",
	)

	return fmt.Sprintf(
		`<tr class="border-t border-slate-800 hover:bg-slate-800/30" data-id="%d">`+
			`<td class="px-3 py-1.5 text-slate-500 whitespace-nowrap">%s</td>`+
			`<td class="px-3 py-1.5 font-mono text-xs">%s</td>`+
			`<td class="px-3 py-1.5 text-xs %s">%s</td>`+
			`<td class="px-3 py-1.5 text-slate-300 text-xs truncate">%s</td>`+
			`<td class="px-3 py-1.5 text-slate-300 text-xs truncate">%s</td>`+
			`<td class="px-3 py-1.5 text-slate-500 text-xs truncate">%s</td>`+
			`</tr>`,
		id,
		ts.Format("15:04:05"),
		html.Replace(qid),
		statusClass, html.Replace(status),
		html.Replace(from),
		html.Replace(to),
		html.Replace(msg),
	)
}

// ---- filter parsing ----

func parseLogFilter(r *http.Request) logFilter {
	q := r.URL.Query()
	limit := 100
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	return logFilter{
		Domain: q.Get("domain"),
		From:   q.Get("from"),
		To:     q.Get("to"),
		Status: q.Get("status"),
		Action: q.Get("action"),
		Search: q.Get("q"),
		Since:  q.Get("since"),
		Limit:  limit,
	}
}

func buildLogWhere(f logFilter) (string, []any) {
	var clauses []string
	var args []any

	if f.Domain != "" {
		clauses = append(clauses, "domain = ?")
		args = append(args, f.Domain)
	}
	if f.From != "" {
		clauses = append(clauses, "from_addr LIKE ?")
		args = append(args, "%"+f.From+"%")
	}
	if f.To != "" {
		clauses = append(clauses, "to_addr LIKE ?")
		args = append(args, "%"+f.To+"%")
	}
	if f.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, f.Status)
	}
	if f.Action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, f.Action)
	}
	if f.Search != "" {
		clauses = append(clauses, "(raw LIKE ? OR message LIKE ?)")
		args = append(args, "%"+f.Search+"%", "%"+f.Search+"%")
	}
	if f.Since != "" {
		if d, err := time.ParseDuration(f.Since); err == nil {
			clauses = append(clauses, "ts > ?")
			args = append(args, time.Now().Add(-d))
		}
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// handleQueueID shows all events for one message
func (s *Server) handleLogQueueDetail(w http.ResponseWriter, r *http.Request) {
	qid := r.PathValue("qid")
	rows, err := s.db.QueryContext(r.Context(), `
        SELECT id, ts, service, COALESCE(action,''), COALESCE(status,''),
               COALESCE(from_addr,''), COALESCE(to_addr,''), message
        FROM mail_events WHERE queue_id = ? ORDER BY ts ASC
    `, qid)
	if err != nil {
		s.renderError(w, 500, "Failed to load queue detail")
		return
	}
	defer rows.Close()

	type row struct {
		ID                                         int64
		Ts                                         time.Time
		Service, Action, Status, From, To, Message string
	}
	var events []row
	for rows.Next() {
		var e row
		if err := rows.Scan(&e.ID, &e.Ts, &e.Service, &e.Action, &e.Status, &e.From, &e.To, &e.Message); err != nil {
			continue
		}
		events = append(events, e)
	}

	s.renderPartial(w, "log_queue_detail", map[string]any{
		"QueueID": qid,
		"Events":  events,
	})
}

var _ = models.Domain{}
var _ = logs.Event{}
var _ sql.NullString
