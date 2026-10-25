package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/store"
)

// loginTestServer builds a Server on a real, migrated database with the login
// plumbing wired. It skips when this build's SQLite driver is the non-cgo stub
// (see internal/db), which is the only configuration where these tests cannot
// run.
func loginTestServer(t *testing.T) (*Server, *db.DB) {
	t.Helper()

	dir := t.TempDir()
	database, err := db.Open(db.Config{Driver: db.DriverSQLite, SQLitePath: filepath.Join(dir, "state.db")})
	if err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skipf("sqlite driver is a non-cgo stub in this build: %v", err)
		}
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	return &Server{
		db:        database.DB,
		store:     store.New(database),
		sessions:  auth.NewSessionStore(database.DB),
		csrf:      auth.NewCSRFManager([]byte("0123456789abcdef0123456789abcdef")),
		auditor:   audit.New(database.DB),
		templates: tmpl,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, database
}

// seedTwoFactorAdmin inserts an administrator with a working password and TOTP
// secret, and returns both.
func seedTwoFactorAdmin(t *testing.T, database *db.DB, username string) (password, secret string) {
	t.Helper()

	password = "correct horse battery staple"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	secret, err = auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate totp secret: %v", err)
	}

	if _, err := database.Exec(`
		INSERT INTO admin_users (username, password_hash, totp_secret, totp_enabled, active)
		VALUES (?, ?, ?, 1, 1)
	`, username, hash, secret); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return password, secret
}

func postLogin(t *testing.T, s *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "mailx-admin-test")
	req.RemoteAddr = "203.0.113.7:5555"

	rec := httptest.NewRecorder()
	s.handleLoginSubmit(rec, req)
	return rec
}

var challengeRe = regexp.MustCompile(`name="challenge" value="([^"]+)"`)

func challengeFrom(t *testing.T, body string) string {
	t.Helper()

	m := challengeRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no challenge token in the rendered page:\n%s", body)
	}
	return m[1]
}

func countRows(t *testing.T, database *db.DB, query string) int {
	t.Helper()

	var n int
	if err := database.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// TestTwoFactorLoginAsksForTheCodeWithoutThePassword is the regression this
// handler was rewritten for.
//
// The second step used to re-render the *whole* login form, empty: the operator
// had to type the password again, and the request that carried the code was a
// second complete sign-in. Anything that went wrong after the password had been
// accepted then looked like a two-factor bug ("Internal error"), and a password
// manager filling the form could turn a correct code into "Invalid
// credentials".
func TestTwoFactorLoginAsksForTheCodeWithoutThePassword(t *testing.T) {
	s, database := loginTestServer(t)
	password, _ := seedTwoFactorAdmin(t, database, "alice")

	rec := postLogin(t, s, url.Values{"username": {"alice"}, "password": {password}})
	if rec.Code != http.StatusOK {
		t.Fatalf("password step = %d, want 200:\n%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, `name="challenge"`) {
		t.Errorf("the 2FA step does not carry a challenge token:\n%s", body)
	}
	if !strings.Contains(body, `name="totp"`) {
		t.Errorf("the 2FA step does not ask for a code:\n%s", body)
	}
	if strings.Contains(body, `name="password"`) {
		t.Errorf("the 2FA step asks for the password again:\n%s", body)
	}
	if countRows(t, database, `SELECT COUNT(*) FROM sessions`) != 0 {
		t.Error("a session was created before the second factor was checked")
	}
}

// TestTwoFactorLoginWithTheCodeStartsTheSession walks the whole flow the way a
// browser does: password first, then the code with the token from the page.
func TestTwoFactorLoginWithTheCodeStartsTheSession(t *testing.T) {
	s, database := loginTestServer(t)
	password, secret := seedTwoFactorAdmin(t, database, "alice")

	first := postLogin(t, s, url.Values{"username": {"alice"}, "password": {password}})
	challenge := challengeFrom(t, first.Body.String())

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	rec := postLogin(t, s, url.Values{"challenge": {challenge}, "totp": {code}})
	if rec.Code != http.StatusFound {
		t.Fatalf("code step = %d, want 302 (redirect to /):\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "mailx_session=") {
		t.Errorf("no session cookie was set: %q", rec.Header().Get("Set-Cookie"))
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM sessions`); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM admin_users WHERE username = 'alice' AND last_login IS NOT NULL`); n != 1 {
		t.Error("last_login was not stamped")
	}

	// Single use: replaying the same page must not mint a second session.
	replay := postLogin(t, s, url.Values{"challenge": {challenge}, "totp": {code}})
	if replay.Code != http.StatusUnauthorized {
		t.Errorf("replayed challenge = %d, want 401", replay.Code)
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM sessions`); n != 1 {
		t.Errorf("sessions after a replay = %d, want 1", n)
	}
}

// TestTwoFactorLoginWithAWrongCodeKeepsTheStep: a typo must not cost the
// password, and the operator has to be able to try again without starting over.
func TestTwoFactorLoginWithAWrongCodeKeepsTheStep(t *testing.T) {
	s, database := loginTestServer(t)
	password, _ := seedTwoFactorAdmin(t, database, "alice")

	first := postLogin(t, s, url.Values{"username": {"alice"}, "password": {password}})
	challenge := challengeFrom(t, first.Body.String())

	rec := postLogin(t, s, url.Values{"challenge": {challenge}, "totp": {"000000"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code = %d, want 401", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="totp"`) || strings.Contains(body, `name="password"`) {
		t.Errorf("a wrong code sent the operator back to the password form:\n%s", body)
	}
	if next := challengeFrom(t, body); next == challenge {
		t.Error("the challenge was not renewed after a wrong code")
	}
	if countRows(t, database, `SELECT COUNT(*) FROM sessions`) != 0 {
		t.Error("a session was created for a wrong code")
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM login_attempts WHERE username = 'alice' AND success = 0`); n != 1 {
		t.Errorf("failed attempts = %d, want 1: a wrong code has to feed the lockout counter", n)
	}
}

// TestTwoFactorLoginWithAnExpiredChallengeAsksForThePassword: an unknown or
// expired token is not a crash and not a loop -- it is "start again".
func TestTwoFactorLoginWithAnExpiredChallengeAsksForThePassword(t *testing.T) {
	s, database := loginTestServer(t)
	seedTwoFactorAdmin(t, database, "alice")

	rec := postLogin(t, s, url.Values{"challenge": {"not-a-real-token"}, "totp": {"123456"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale challenge = %d, want 401", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "expired") {
		t.Errorf("the page does not say the sign-in session expired:\n%s", body)
	}
	if !strings.Contains(body, `name="password"`) {
		t.Errorf("the page does not offer the password form again:\n%s", body)
	}
}

// TestTwoFactorLoginWithoutASecretSaysSo: an account whose 2FA is enabled but
// whose secret is missing could never finish a sign-in, and the old code
// answered "Invalid 2FA code" forever -- blaming the operator for a broken row.
func TestTwoFactorLoginWithoutASecretSaysSo(t *testing.T) {
	s, database := loginTestServer(t)
	password, _ := seedTwoFactorAdmin(t, database, "alice")

	if _, err := database.Exec(`UPDATE admin_users SET totp_secret = NULL WHERE username = 'alice'`); err != nil {
		t.Fatal(err)
	}

	rec := postLogin(t, s, url.Values{"username": {"alice"}, "password": {password}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("missing secret = %d, want 500 with an explanation", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no secret is stored") {
		t.Errorf("the page does not explain the misconfiguration:\n%s", rec.Body.String())
	}
}

// TestPendingLoginsExpire covers the store's own contract: single use, and gone
// after the TTL -- a challenge is the only proof that a password was checked, so
// keeping it alive would be a standing half-authenticated session.
func TestPendingLoginsExpire(t *testing.T) {
	base := time.Now().Add(-time.Hour)
	store := newPendingLogins(5 * time.Minute)
	store.now = func() time.Time { return base }

	token, err := store.Put(pendingLogin{AdminID: 1, Username: "alice"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := store.Take(token); !ok {
		t.Fatal("a fresh challenge was rejected")
	}
	if _, ok := store.Take(token); ok {
		t.Fatal("a replayed challenge was accepted")
	}

	live, err := store.Put(pendingLogin{AdminID: 1, Username: "alice"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	store.now = func() time.Time { return base.Add(6 * time.Minute) }
	if _, ok := store.Take(live); ok {
		t.Fatal("an expired challenge was accepted")
	}
}
