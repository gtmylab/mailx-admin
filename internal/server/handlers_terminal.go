package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
)

// terminalSSHAddr is where the panel connects to open a shell: the loopback
// address of the server it is running on. The login dialog's credentials are
// handed to sshd, which does the real authentication — PAM for passwords,
// authorized_keys for private keys.
const terminalSSHAddr = "127.0.0.1:22"

// upgrader turns the terminal page's WebSocket request into a connection. The
// session has already been checked by RequireAuth, so every caller here is a
// signed-in admin; origin is not used for anything.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// termMsg is the JSON control protocol over the terminal WebSocket. Terminal
// output travels as binary frames; control messages (login, resize, status) are
// text frames with a "type" field.
type termMsg struct {
	Type     string `json:"type"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"`
	Cols     int    `json:"cols,omitempty"`
	Rows     int    `json:"rows,omitempty"`
	Message  string `json:"message,omitempty"`
}

// replayCap bounds the recent output kept for replay when a tab re-attaches.
const replayCap = 32 * 1024

// TerminalManager holds one SSH terminal session per panel admin. Sessions live
// in memory for the lifetime of the process and are destroyed on logout.
type TerminalManager struct {
	mu  sync.Mutex
	ses map[int64]*TermSession
}

func NewTerminalManager() *TerminalManager {
	return &TerminalManager{ses: map[int64]*TermSession{}}
}

func (m *TerminalManager) Get(adminID int64) *TermSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ses[adminID]
}

func (m *TerminalManager) Put(s *TermSession) {
	m.mu.Lock()
	m.ses[s.adminID] = s
	m.mu.Unlock()
}

func (m *TerminalManager) Destroy(adminID int64) {
	m.mu.Lock()
	s := m.ses[adminID]
	delete(m.ses, adminID)
	m.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

// TermSession is one SSH shell and its attached browser tabs. The SSH session's
// stdout is broadcast to every attached tab and buffered for replay.
type TermSession struct {
	adminID  int64
	username string

	client *ssh.Client
	sess   *ssh.Session
	stdin  io.WriteCloser

	mu      sync.Mutex
	stdinMu sync.Mutex
	conns   map[*websocket.Conn]struct{}
	replay  []byte
	closed  bool
}

func startTermSession(adminID int64, username, password, key string) (*TermSession, error) {
	var methods []ssh.AuthMethod
	if key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("invalid SSH private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if password != "" {
		methods = append(methods, ssh.Password(password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("a password or SSH private key is required")
	}

	cfg := &ssh.ClientConfig{
		User: username,
		Auth: methods,
		// Loopback only: the host key is the server's own and changes if sshd is
		// reinstalled, so pinning it would lock the admin out after a rebuild.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", terminalSSHAddr, cfg)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", 40, 80, modes); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}

	ts := &TermSession{
		adminID:  adminID,
		username: username,
		client:   client,
		sess:     sess,
		stdin:    stdin,
		conns:    map[*websocket.Conn]struct{}{},
	}

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				ts.broadcast(buf[:n])
			}
			if err != nil {
				ts.Close()
				return
			}
		}
	}()

	return ts, nil
}

func (s *TermSession) broadcast(p []byte) {
	s.mu.Lock()
	s.replay = append(s.replay, p...)
	if len(s.replay) > replayCap {
		s.replay = s.replay[len(s.replay)-replayCap:]
	}
	conns := make([]*websocket.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		_ = c.WriteMessage(websocket.BinaryMessage, p)
	}
}

func (s *TermSession) Attach(conn *websocket.Conn) {
	s.mu.Lock()
	s.conns[conn] = struct{}{}
	replay := append([]byte(nil), s.replay...)
	s.mu.Unlock()
	if len(replay) > 0 {
		_ = conn.WriteMessage(websocket.BinaryMessage, replay)
	}
}

func (s *TermSession) Detach(conn *websocket.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

func (s *TermSession) Write(p []byte) {
	s.stdinMu.Lock()
	_, _ = s.stdin.Write(p)
	s.stdinMu.Unlock()
}

func (s *TermSession) Resize(cols, rows int) {
	if s.sess != nil {
		_ = s.sess.WindowChange(rows, cols)
	}
}

func (s *TermSession) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := make([]*websocket.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = map[*websocket.Conn]struct{}{}
	s.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.client != nil {
		_ = s.client.Close()
	}
}

func (s *Server) handleTerminalPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "terminal.html", s.newPageData(w, r, "Terminal", "terminal", map[string]any{}))
}

// handleTerminalWS serves the interactive shell over a WebSocket. It resumes an
// existing session for this admin, or asks the browser for credentials and
// establishes a fresh SSH session to localhost.
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

	// Resume an existing session if one is open for this admin.
	if ts := s.terminals.Get(sess.AdminUserID); ts != nil {
		_ = conn.WriteJSON(termMsg{Type: "login-ok"})
		ts.Attach(conn)
		defer ts.Detach(conn)
		s.terminalReadLoop(conn, ts)
		return
	}

	// No session: prompt for credentials and retry until a login succeeds or the
	// connection closes.
	_ = conn.WriteJSON(termMsg{Type: "login-required"})
	var ts *TermSession
	var target string
	for ts == nil {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.TextMessage {
			continue
		}
		var msg termMsg
		if json.Unmarshal(data, &msg) != nil || msg.Type != "login" {
			continue
		}
		ts, err = startTermSession(sess.AdminUserID, msg.Username, msg.Password, msg.Key)
		if err != nil {
			_ = conn.WriteJSON(termMsg{Type: "login-error", Message: err.Error()})
			ts = nil
			continue
		}
		target = msg.Username
	}
	s.terminals.Put(ts)
	_ = conn.WriteJSON(termMsg{Type: "login-ok"})
	ts.Attach(conn)
	defer ts.Detach(conn)

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: "admin:" + sess.Username, Action: "terminal.login", TargetType: "terminal", TargetID: target,
		Result: "ok", RemoteIP: clientIP(r),
	})

	s.terminalReadLoop(conn, ts)
}

// terminalReadLoop forwards browser input to the shell and handles resize
// control messages. It runs until the WebSocket closes.
func (s *Server) terminalReadLoop(conn *websocket.Conn, ts *TermSession) {
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.TextMessage && len(data) > 1 && data[0] == '{' {
			var msg termMsg
			if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" && msg.Cols > 0 && msg.Rows > 0 {
				ts.Resize(msg.Cols, msg.Rows)
				continue
			}
		}
		if len(data) > 0 {
			ts.Write(data)
		}
	}
}
