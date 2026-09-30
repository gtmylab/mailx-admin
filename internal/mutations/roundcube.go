package mutations

import (
	"context"
	"fmt"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/config"
	"github.com/gtmylab/mailx-admin/internal/roundcube"
)

// NewRoundcubeSeeder builds the Roundcube pre-seed from the [roundcube]
// section, or returns nil when it is disabled.
//
// The nil is returned as the interface, not as a (*roundcube.Client)(nil): a
// typed nil in an interface is not nil, so the service's "nothing is wired"
// check would pass and the first mailbox creation would panic instead of
// skipping the step.
func NewRoundcubeSeeder(rc config.RoundcubeConfig) RoundcubeSeeder {
	if !rc.Enabled {
		return nil
	}
	return roundcube.New(rc.ToClientConfig())
}

// seedRoundcube pre-seeds a mailbox in Roundcube's own database.
//
// It runs *after* the transaction has committed and it is never fatal. The
// mailbox is already created by then: the row is in the panel, the hash is in
// Dovecot's passwd-file, the maps are rendered and the maildir exists. Roundcube
// creates the two rows it needs on first login anyway, so a database the panel
// cannot reach is a missing default identity and a missing language — not a
// reason to undo a mailbox that works, or to make the admin retry a creation
// that already happened.
//
// What the operator gets instead is a warning on the same response, a line in
// the audit trail, and `mailx-admin roundcube sync` to finish the job later.
func (s *Service) seedRoundcube(ctx context.Context, actor Actor, email string, res *Result) {
	if s.roundcube == nil || res == nil {
		return
	}

	rcRes, err := s.roundcube.EnsureUser(ctx, email)
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"Roundcube was not told about %s: %v — webmail still works (Roundcube creates the account "+
				"on first login); run `mailx-admin roundcube sync` to add it later.", email, err))

		_ = s.auditor.Log(ctx, audit.Entry{
			Actor:    actor.Name,
			Action:   "roundcube.seed",
			Result:   "error",
			Detail:   map[string]any{"email": email, "error": err.Error()},
			RemoteIP: actor.RemoteIP,
		})
		return
	}

	_ = s.auditor.Log(ctx, audit.Entry{
		Actor:  actor.Name,
		Action: "roundcube.seed",
		Result: "ok",
		Detail: map[string]any{
			"email":   email,
			"outcome": rcRes.String(),
			"user_id": rcRes.UserID,
		},
		RemoteIP: actor.RemoteIP,
	})
}
