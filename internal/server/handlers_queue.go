package server

import (
	"net/http"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/queue"
)

func (s *Server) handleQueuePage(w http.ResponseWriter, r *http.Request) {
	messages, err := queue.List(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to read queue: "+err.Error())
		return
	}

	var totalSize int64
	for _, m := range messages {
		totalSize += m.Size
	}

	s.render(w, 200, "queue.html", s.newPageData(w, r, "Mail Queue", "queue",
		map[string]any{
			"Messages":  messages,
			"TotalSize": totalSize,
		},
	))
}

func (s *Server) handleQueueRefresh(w http.ResponseWriter, r *http.Request) {
	messages, err := queue.List(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to read queue")
		return
	}
	s.renderPartial(w, "queue_table", map[string]any{
		"Messages": messages,
	})
}

func (s *Server) handleQueueFlush(w http.ResponseWriter, r *http.Request) {
	qid := r.PathValue("qid")
	session := auth.SessionFromContext(r.Context())

	err := queue.Flush(r.Context(), qid)
	result := "ok"
	if err != nil {
		result = "error"
	}

	s.auditor.Log(r.Context(), audit.Entry{
		Actor:      "admin:" + session.Username,
		Action:     "queue.flush",
		TargetType: "queue",
		TargetID:   qid,
		Result:     result,
		Detail:     map[string]any{"error": errStr(err)},
		RemoteIP:   clientIP(r),
	})

	s.db.ExecContext(r.Context(), `
        INSERT INTO queue_actions (admin_user_id, queue_id, action, result, message)
        VALUES (?, ?, 'retry', ?, ?)
    `, session.AdminUserID, qid, result, errStr(err))

	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/queue?flash="+encodeFlash("Retry triggered for "+qid))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleQueueDelete(w http.ResponseWriter, r *http.Request) {
	qid := r.PathValue("qid")
	session := auth.SessionFromContext(r.Context())

	err := queue.Delete(r.Context(), qid)
	result := "ok"
	if err != nil {
		result = "error"
	}

	s.auditor.Log(r.Context(), audit.Entry{
		Actor:      "admin:" + session.Username,
		Action:     "queue.delete",
		TargetType: "queue",
		TargetID:   qid,
		Result:     result,
		Detail:     map[string]any{"error": errStr(err)},
		RemoteIP:   clientIP(r),
	})

	s.db.ExecContext(r.Context(), `
        INSERT INTO queue_actions (admin_user_id, queue_id, action, result, message)
        VALUES (?, ?, 'delete', ?, ?)
    `, session.AdminUserID, qid, result, errStr(err))

	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/queue?flash="+encodeFlash("Message "+qid+" deleted"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleQueueFlushAll(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	err := queue.FlushAll(r.Context())
	result := "ok"
	if err != nil {
		result = "error"
	}

	s.auditor.Log(r.Context(), audit.Entry{
		Actor:    "admin:" + session.Username,
		Action:   "queue.flush_all",
		Result:   result,
		Detail:   map[string]any{"error": errStr(err)},
		RemoteIP: clientIP(r),
	})

	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/queue?flash="+encodeFlash("Queue flushed"))
	w.WriteHeader(http.StatusOK)
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
