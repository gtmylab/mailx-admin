package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/logs"
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

// logEvent is one mail_events row.
type logEvent struct {
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

// logStatusCount is one bar of the summary strip above the table.
type logStatusCount struct {
	Status string
	Count  int
	Class  string // "", ok, warn, err, info - a .badge modifier
}

// handleLogsPage renders the page with the first window of events already in
// place. The filters, the pagination buttons and the live tail then swap only
// the table body.
//
// The page embeds the very same "log_rows" fragment the list endpoint returns
// and feeds it the same data map, which is the contract that keeps the two from
// drifting apart (see the queue page, where they had).
func (s *Server) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	data, err := s.logListData(r)
	if err != nil {
		s.logger.Error("log query", "err", err)
		s.renderError(w, 500, "Failed to load logs")
		return
	}
	s.render(w, 200, "logs.html", s.newPageData(w, r, "Logs", "logs", data))
}

// handleLogsList returns the log rows fragment: initial load, every filter
// change and every page of pagination target it.
func (s *Server) handleLogsList(w http.ResponseWriter, r *http.Request) {
	data, err := s.logListData(r)
	if err != nil {
		s.logger.Error("log query", "err", err)
		s.renderError(w, 500, "Failed to load logs")
		return
	}
	s.renderPartial(w, "log_rows", data)
}

// logListData runs the filtered query and packages everything log_rows.html
// needs: the rows, the total, the per-status counts and the pagination window.
func (s *Server) logListData(r *http.Request) (map[string]any, error) {
	f := parseLogFilter(r)
	ctx := r.Context()
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

	pageArgs := append(append([]any{}, args...), f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	// Total for the current filter: the pagination footer is useless without it.
	var total int
	if err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM mail_events %s`, where), args...,
	).Scan(&total); err != nil {
		return nil, err
	}

	counts, err := s.logStatusCounts(ctx, where, args)
	if err != nil {
		return nil, err
	}

	first, last := 0, 0
	if len(events) > 0 {
		first = f.Offset + 1
		last = f.Offset + len(events)
	}
	prev := f.Offset - f.Limit
	if prev < 0 {
		prev = 0
	}

	return map[string]any{
		"Events":     events,
		"Filter":     f,
		"Total":      total,
		"Counts":     counts,
		"First":      first,
		"Last":       last,
		"HasMore":    f.Offset+len(events) < total,
		"PrevOffset": prev,
		"NextOffset": f.Offset + f.Limit,
		"Limit":      f.Limit,
	}, nil
}

// logStatusCounts summarises how many events of each status match the filter.
func (s *Server) logStatusCounts(ctx context.Context, where string, args []any) ([]logStatusCount, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
        SELECT COALESCE(status,''), COUNT(*)
        FROM mail_events
        %s
        GROUP BY COALESCE(status,'')
        ORDER BY COUNT(*) DESC
    `, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []logStatusCount{}
	for rows.Next() {
		var c logStatusCount
		if err := rows.Scan(&c.Status, &c.Count); err != nil {
			continue
		}
		c.Class = statusBadgeClass(c.Status)
		out = append(out, c)
	}
	return out, rows.Err()
}

// statusBadgeClass maps a delivery status onto a .badge modifier.
func statusBadgeClass(status string) string {
	switch status {
	case "sent", "delivered", "ok":
		return "ok"
	case "deferred", "queued", "hold":
		return "warn"
	case "bounced", "rejected", "failed", "error":
		return "err"
	case "":
		return ""
	default:
		return "info"
	}
}

// ---- log source diagnostics ----

// logSourceInfo answers "why is this page empty?" without shell access: it
// inspects the configured log file and compares it with what the ingester has
// actually stored.
type logSourceInfo struct {
	Path       string
	Source     string // "file" or "journal"
	Exists     bool
	Readable   bool
	SizeBytes  int64
	Modified   time.Time
	LastEvent  time.Time
	HasEvents  bool
	EventsHour int
	Stale      bool
	Hints      []string
}

// handleLogsSource returns the diagnostics panel, loaded with hx-trigger="load"
// so a slow stat (or an unreadable path) never delays the table itself.
func (s *Server) handleLogsSource(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "log_source", s.logSourceInfo(r.Context()))
}

func (s *Server) logSourceInfo(ctx context.Context) logSourceInfo {
	info := logSourceInfo{Path: s.cfg.Logs.MailLogPath}
	if info.Path == "" {
		info.Path = "/var/log/mail.log"
	}
	info.Source = logs.Source(info.Path)

	if st, err := os.Stat(info.Path); err == nil {
		info.Exists = true
		info.SizeBytes = st.Size()
		info.Modified = st.ModTime()
		if f, err := os.Open(info.Path); err == nil {
			info.Readable = true
			_ = f.Close()
		} else {
			info.Hints = append(info.Hints,
				"The log file exists but the panel cannot read it. Run mailx-admin as a user in the "+
					"adm (or systemd-journal) group, or make the file readable, then restart the service.")
		}
	} else if info.Source == "journal" {
		info.Hints = append(info.Hints,
			"No mail log file is present, so events are read from the systemd journal instead.")
	} else {
		info.Hints = append(info.Hints,
			"The configured log file does not exist and the systemd journal is not available. "+
				"Point logs.mail_log_path at a real file in the config, then restart the service.")
	}

	var lastEvent sql.NullTime
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(ts) FROM mail_events`).Scan(&lastEvent); err == nil && lastEvent.Valid {
		info.HasEvents = true
		info.LastEvent = lastEvent.Time
	}
	_ = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mail_events WHERE ts > ?`, time.Now().Add(-time.Hour),
	).Scan(&info.EventsHour)

	if !info.HasEvents {
		info.Hints = append(info.Hints,
			"No mail events have been stored yet. The ingester only keeps the lines it recognises, so "+
				"check the service log for level=ERROR messages from it.")
	} else if info.Exists && info.Modified.After(info.LastEvent) {
		// The file moved on but nothing arrived in the database: a stopped or
		// wedged ingester is invisible from the UI without this comparison.
		info.Stale = true
		info.Hints = append(info.Hints,
			"The log file was written after the last stored event. The ingester may be stopped, or it no "+
				"longer recognises the log format.")
	}
	return info
}

// ---- live tail ----

// handleLogsLive streams new events via SSE. The rows are pre-rendered HTML so
// the browser can insert them straight into the table body.
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

	// Track the max ID we've sent so we only push new rows.
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
				fmt.Fprintf(w, "event: log\ndata: %s\n\n",
					renderLogRowHTML(id, ts, qid, svc, action, status, from, to, dom, msg))
			}
			rows.Close()
			flusher.Flush()
		}
	}
}

// renderLogRowHTML renders one <tr> for the live tail. It is a small helper so
// the streamed rows use exactly the same markup as log_rows.html (no template
// round-trip for every second of streaming).
func renderLogRowHTML(id int64, ts time.Time, qid, svc, action, status, from, to, dom, msg string) string {
	esc := strings.NewReplacer(
		"<", "&lt;", ">", "&gt;", "&", "&amp;", `"`, "&quot;",
	)

	queueCell := ""
	if qid != "" {
		short := qid
		if len(short) > 8 {
			short = short[:8]
		}
		queueCell = fmt.Sprintf(
			`<a href="#" hx-get="/logs/queue/%s" hx-target="#modal-host" hx-swap="innerHTML">%s</a>`,
			esc.Replace(qid), esc.Replace(short))
	}

	return fmt.Sprintf(
		`<tr data-id="%d">`+
			`<td data-label="Time" class="dim text-xs nowrap">%s</td>`+
			`<td data-label="Queue" class="mono text-xs">%s</td>`+
			`<td data-label="Status"><span class="badge %s">%s</span></td>`+
			`<td data-label="From" class="text-xs"><span class="truncate max-w-[220px]">%s</span></td>`+
			`<td data-label="To" class="text-xs"><span class="truncate max-w-[220px]">%s</span></td>`+
			`<td data-label="Message" class="dim text-xs"><span class="truncate max-w-[400px]">%s</span></td>`+
			`</tr>`,
		id,
		ts.Format("15:04:05"),
		queueCell,
		statusBadgeClass(status), esc.Replace(status),
		esc.Replace(from),
		esc.Replace(to),
		esc.Replace(msg),
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
	offset := 0
	if o := q.Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n > 0 {
			offset = n
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
		Offset: offset,
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

// handleLogQueueDetail shows all events for one message, as a dialog.
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
