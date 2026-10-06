package server

import (
	"encoding/json"
	"net/http"
	"os/exec"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
)

// upgrader turns the terminal page's WebSocket request into a connection. The
// session has already been checked by RequireAuth, so every caller here is a
// signed-in admin; origin is not used for anything.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func (s *Server) handleTerminalPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "terminal.html", s.newPageData(w, r, "Terminal", "terminal", map[string]any{}))
}

// handleTerminalWS serves an interactive shell over a WebSocket. It runs the
// panel's own login shell (bash) inside a PTY and bridges the browser's
// keystrokes and the shell's output. Only the session's existence is audited;
// the contents of the session are never logged.
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	cmd := exec.Command("/bin/bash", "-l")
	f, err := pty.Start(cmd)
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("\r\n\x1b[31mFailed to start a shell: "+err.Error()+"\x1b[0m\r\n"))
		return
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = f.Close()
		_, _ = cmd.Process.Wait()
	}()

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: "admin:" + sess.Username, Action: "terminal.session", TargetType: "terminal", TargetID: sess.Username,
		Result: "ok", RemoteIP: clientIP(r),
	})

	// Reader: pty output -> websocket. This is the only writer; the loop below
	// is the only reader, which is what gorilla/websocket requires.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				if werr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Writer: websocket input -> pty. Control messages (resize) are JSON; every
	// other message is raw terminal input.
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.TextMessage && len(data) > 1 && data[0] == '{' {
			var ctrl struct {
				Type string `json:"type"`
				Cols uint16 `json:"cols"`
				Rows uint16 `json:"rows"`
			}
			if json.Unmarshal(data, &ctrl) == nil && ctrl.Type == "resize" && ctrl.Cols > 0 && ctrl.Rows > 0 {
				_ = pty.Setsize(f, &pty.Winsize{Cols: ctrl.Cols, Rows: ctrl.Rows})
				continue
			}
		}
		if len(data) > 0 {
			_, _ = f.Write(data)
		}
	}
}
