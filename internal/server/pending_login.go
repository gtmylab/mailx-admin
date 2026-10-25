package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

const (
	// pendingLoginTTL is how long a password-verified sign-in waits for its
	// second factor. Long enough to fetch a phone, short enough that a
	// forgotten tab is not a standing key: the record is the only proof that
	// the password was already checked, and it is single-use.
	pendingLoginTTL = 5 * time.Minute

	// maxPendingLogins caps the map. Only a correct password creates an entry,
	// so this is not an unauthenticated growth vector -- but a cap keeps a
	// stuck map from growing without bound on a panel that never restarts.
	maxPendingLogins = 4096

	// maxTOTPAttempts is how many wrong codes one password check tolerates
	// before the operator has to prove the password again. Six decimal digits
	// are a million possibilities; five tries per password entry is what the
	// plain login path already allows per username and window.
	maxTOTPAttempts = 5
)

// pendingLogin is a sign-in whose password has already been verified, waiting
// for the second factor.
//
// It exists because the two-factor step used to be a second *full* login POST:
// the handler re-rendered an empty form, the operator typed the password again
// and the whole thing ran twice. That is why a failing session insert looked
// like a 2FA-only bug, and why a password manager re-filling the form could
// turn a correct code into "Invalid credentials".
type pendingLogin struct {
	AdminID  int64
	Username string
	Attempts int
	Expires  time.Time
}

// pendingLogins holds them, in memory and for the lifetime of the process: a
// panel restart dropping a half-finished sign-in is the correct behaviour
// (there is nothing to resume after a redeploy), and it keeps the credentials
// path away from the database.
type pendingLogins struct {
	mu   sync.Mutex
	byID map[string]pendingLogin
	ttl  time.Duration
	now  func() time.Time
}

func newPendingLogins(ttl time.Duration) *pendingLogins {
	if ttl <= 0 {
		ttl = pendingLoginTTL
	}
	return &pendingLogins{
		byID: make(map[string]pendingLogin),
		ttl:  ttl,
		now:  time.Now,
	}
}

// Put records a verified password and returns the token the second step has to
// send back.
func (p *pendingLogins) Put(rec pendingLogin) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	rec.Expires = p.now().Add(p.ttl)

	p.mu.Lock()
	defer p.mu.Unlock()

	p.sweepLocked()
	if len(p.byID) >= maxPendingLogins {
		return "", fmt.Errorf("too many sign-ins are waiting for their second factor")
	}
	p.byID[token] = rec
	return token, nil
}

// Take consumes a token. It is single-use on purpose: a replayed form (back
// button, a double-clicked button) must not mint two sessions.
func (p *pendingLogins) Take(token string) (pendingLogin, bool) {
	if token == "" {
		return pendingLogin{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sweepLocked()
	rec, ok := p.byID[token]
	if !ok {
		return pendingLogin{}, false
	}
	delete(p.byID, token)
	if !p.now().Before(rec.Expires) {
		return pendingLogin{}, false
	}
	return rec, true
}

// sweepLocked drops expired entries. Callers hold the mutex.
func (p *pendingLogins) sweepLocked() {
	now := p.now()
	for token, rec := range p.byID {
		if !now.Before(rec.Expires) {
			delete(p.byID, token)
		}
	}
}
