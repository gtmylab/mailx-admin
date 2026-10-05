package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
)

// postfixResult carries the output of a postfix check/reload/restart for the
// result panel.
type postfixResult struct {
	Result string
	Error  bool
}

func (s *Server) postfixConfPath(name string) string {
	return filepath.Join(s.cfg.Mail.PostfixConfDir, name)
}

func (s *Server) handlePostfixPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "postfix_editor.html", s.newPageData(w, r, "Postfix config", "postfix", map[string]any{
		"MainCF":   s.readPostfixFile("main.cf"),
		"MasterCF": s.readPostfixFile("master.cf"),
		"ConfDir":  s.cfg.Mail.PostfixConfDir,
	}))
}

func (s *Server) readPostfixFile(name string) string {
	b, err := os.ReadFile(s.postfixConfPath(name))
	if err != nil {
		return ""
	}
	return string(b)
}

// handlePostfixFileSave writes one of the two Postfix files, then runs
// `postfix check` so the operator sees validation errors immediately.
func (s *Server) handlePostfixFileSave(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name != "main.cf" && name != "master.cf" {
		s.renderError(w, 400, "Unknown file: "+name)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	if err := os.WriteFile(s.postfixConfPath(name), []byte(r.FormValue("content")), 0o644); err != nil {
		s.renderFormError(w, "Failed to write "+name+": "+err.Error())
		return
	}

	out, err := execx.Output(r.Context(), 30*time.Second, "postfix", "check")
	res := postfixResult{Result: "Saved " + name + "."}
	if err != nil {
		res.Error = true
		res.Result += "\npostfix check failed: " + err.Error()
	} else {
		res.Result += "\npostfix check ok."
	}
	if t := strings.TrimSpace(string(out)); t != "" {
		res.Result += "\n" + t
	}
	s.renderPartial(w, "postfix_result", res)
}

func (s *Server) handlePostfixCheck(w http.ResponseWriter, r *http.Request) {
	out, err := execx.Output(r.Context(), 30*time.Second, "postfix", "check")
	res := postfixResult{Result: "postfix check ok."}
	if err != nil {
		res.Error = true
		res.Result = "postfix check failed: " + err.Error()
	}
	if t := strings.TrimSpace(string(out)); t != "" {
		res.Result += "\n" + t
	}
	s.renderPartial(w, "postfix_result", res)
}

func (s *Server) handlePostfixReload(w http.ResponseWriter, r *http.Request) {
	out, err := execx.Output(r.Context(), 30*time.Second, "postfix", "reload")
	res := postfixResult{Result: "postfix reloaded."}
	if err != nil {
		res.Error = true
		res.Result = "postfix reload failed: " + err.Error()
	}
	if t := strings.TrimSpace(string(out)); t != "" {
		res.Result += "\n" + t
	}
	s.renderPartial(w, "postfix_result", res)
}

func (s *Server) handlePostfixRestart(w http.ResponseWriter, r *http.Request) {
	out, err := execx.Output(r.Context(), 30*time.Second, "systemctl", "restart", "postfix")
	res := postfixResult{Result: "postfix restarted."}
	if err != nil {
		res.Error = true
		res.Result = "postfix restart failed: " + err.Error()
	}
	if t := strings.TrimSpace(string(out)); t != "" {
		res.Result += "\n" + t
	}
	s.renderPartial(w, "postfix_result", res)
}
