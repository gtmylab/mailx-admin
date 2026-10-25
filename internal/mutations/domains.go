package mutations

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/dkim"
	"github.com/gtmylab/mailx-admin/internal/models"
)

type CreateDomainInput struct {
	Name         string
	MakePrimary  bool
	GenerateDKIM bool
}

func (s *Service) CreateDomain(ctx context.Context, actor Actor, in CreateDomainInput) (*Result, error) {
	if err := validateCreateDomain(&in); err != nil {
		return nil, err
	}

	// Generate DKIM key OUTSIDE the tx (it touches the filesystem and is slow).
	var dkimPrivPath, dkimPubRecord string
	if in.GenerateDKIM {
		result, err := dkim.Generate(ctx, in.Name, "/etc/opendkim")
		if err != nil {
			return nil, fmt.Errorf("generate DKIM: %w", err)
		}
		dkimPrivPath = result.PrivateKeyPath
		dkimPubRecord = result.PublicRecord
	}

	// The password of the postmaster mailbox is hashed outside the tx too: the
	// scheme depends on what this Dovecot can verify, which is a probe, and a
	// probe inside a transaction is a second connection waiting on the one the
	// transaction holds (see Service's doc comment).
	postmasterHash, err := s.postmasterPasswordHash(ctx)
	if err != nil {
		if dkimPrivPath != "" {
			_ = os.RemoveAll(filepath.Dir(dkimPrivPath))
		}
		return nil, err
	}

	res, err := s.Apply(ctx, actor, "domain.create", map[string]any{
		"domain":   in.Name,
		"primary":  in.MakePrimary,
		"dkim_gen": in.GenerateDKIM,
	}, func(tx *sql.Tx) error {
		return applyCreateDomainTx(ctx, tx, in, dkimPrivPath, dkimPubRecord, postmasterHash)
	})
	if err != nil {
		// Roll back the DKIM key if the DB write failed
		if dkimPrivPath != "" {
			_ = os.RemoveAll(filepath.Dir(dkimPrivPath))
		}
		return nil, err
	}

	// Say it out loud: an operator who does not know the mailbox exists will
	// either be surprised by it in the user list or delete it and lose the
	// DMARC reports silently.
	res.Warnings = append(res.Warnings, fmt.Sprintf(
		"Created the mailbox postmaster@%s so DMARC and TLS reports have an inbox. "+
			"It has a random, unknown password: set one from Mailboxes if you want to read it.",
		in.Name))

	return res, nil
}

// validateCreateDomain normalizes and checks the domain name in place.
func validateCreateDomain(in *CreateDomainInput) error {
	in.Name = strings.TrimSpace(strings.ToLower(in.Name))
	return validateDomainName(in.Name)
}

// validateDomainName is the single place that decides what a domain name may
// look like; both create and rename go through it.
func validateDomainName(name string) error {
	if name == "" || !strings.Contains(name, ".") {
		return fmt.Errorf("%w: invalid domain name", ErrInvalidInput)
	}
	if strings.ContainsAny(name, "@/ ") {
		return fmt.Errorf("%w: domain may not contain @, /, or space", ErrInvalidInput)
	}
	return nil
}

// postmasterQuotaMB is the quota of the mailbox created with every new domain.
//
// Not 0: the reconciler renders quota_mb straight into the passdb as
// `storage=<n>M` (see reconciler.RenderDovecotPasswd), and a 0 quota is a
// mailbox that bounces every message it receives -- including the DMARC
// reports it exists for.
const postmasterQuotaMB = 1024

// postmasterPreviewHash stands in for the random password in a preview
// transaction: the row is rolled back and nothing needs to be hashed for a
// hypothetical domain.
const postmasterPreviewHash = "{PLAIN}preview-only"

// postmasterPasswordHash hashes a password nobody is told, for the postmaster
// mailbox created with every domain.
//
// The mailbox exists to receive DMARC and TLS reports, so it has to be a real,
// deliverable address with a real hash in the passwd-file; it does not need to
// be a login. 32 random bytes give an operator a password no one -- including
// anyone who can read the passwd-file's hash -- can guess, and setting a known
// one later is an ordinary password change from the Mailboxes page.
func (s *Service) postmasterPasswordHash(ctx context.Context) (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate postmaster password: %w", err)
	}
	return s.hashPassword(ctx, hex.EncodeToString(secret))
}

// insertPostmasterTx creates postmaster@<domain> for a domain that was just
// inserted in this transaction.
func insertPostmasterTx(ctx context.Context, tx *sql.Tx, domainName, hash string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO users (domain_id, username, email, password_hash, quota_mb,
		                   active, is_admin, display_name)
		VALUES ((SELECT id FROM domains WHERE name = ?), 'postmaster', ?, ?, ?, 1, 0, 'Postmaster')
	`, domainName, "postmaster@"+domainName, hash, postmasterQuotaMB)
	if err != nil {
		return fmt.Errorf("create postmaster mailbox: %w", err)
	}
	return nil
}

// applyCreateDomainTx inserts the domain row inside an existing transaction.
// dkimPrivPath/dkimPubRecord are produced outside the tx by CreateDomain
// (filesystem work) and may be empty, and so is postmasterHash.
//
// The postmaster mailbox is created in the same transaction on purpose: a
// domain whose DMARC record points at an address that does not exist is worse
// than no DMARC record at all, because the reports are lost silently. Every
// caller that creates a domain therefore gets the mailbox, previews included
// (the preview sees it in the diff and then rolls it back).
func applyCreateDomainTx(ctx context.Context, tx *sql.Tx, in CreateDomainInput, dkimPrivPath, dkimPubRecord, postmasterHash string) error {
	// Uniqueness
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM domains WHERE name = ?`, in.Name).Scan(&exists)
	if err == nil {
		return fmt.Errorf("%w: domain %s already exists", ErrConflict, in.Name)
	}
	if err != sql.ErrNoRows {
		return err
	}

	// If making primary, unset others
	if in.MakePrimary {
		if _, err := tx.ExecContext(ctx, `UPDATE domains SET is_primary = 0`); err != nil {
			return err
		}
	}

	if _, err = tx.ExecContext(ctx, `
		INSERT INTO domains (name, is_primary, dkim_selector, dkim_private_key_path, dkim_public_record, active)
		VALUES (?, ?, 'default', NULLIF(?, ''), NULLIF(?, ''), 1)
	`, in.Name, boolInt(in.MakePrimary), dkimPrivPath, dkimPubRecord); err != nil {
		return err
	}

	return insertPostmasterTx(ctx, tx, in.Name, postmasterHash)
}

// ApplyCreateDomainToTx creates a domain inside an existing transaction.
// Exported for the server's preview handler, which runs it and rolls back.
// No DKIM key is generated here, because that touches the filesystem, and the
// postmaster mailbox gets a placeholder hash for the same reason -- see
// postmasterPreviewHash.
func (s *Service) ApplyCreateDomainToTx(ctx context.Context, tx *sql.Tx, in CreateDomainInput) error {
	if err := validateCreateDomain(&in); err != nil {
		return err
	}
	return applyCreateDomainTx(ctx, tx, in, "", "", postmasterPreviewHash)
}

func (s *Service) DeleteDomain(ctx context.Context, actor Actor, domainID int64) (*Result, error) {
	// Refuse if the domain has users (unless they're being deleted too).
	var userCount int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE domain_id = ? AND active = 1`, domainID,
	).Scan(&userCount)
	if err != nil {
		return nil, err
	}
	if userCount > 0 {
		return nil, fmt.Errorf("%w: domain has %d active user(s); delete them first",
			ErrConflict, userCount)
	}

	var name string
	err = s.db.QueryRowContext(ctx, `SELECT name FROM domains WHERE id = ?`, domainID).Scan(&name)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: domain not found", ErrNotFound)
	}

	res, err := s.Apply(ctx, actor, "domain.delete", map[string]any{
		"domain_id": domainID,
		"domain":    name,
	}, func(tx *sql.Tx) error {
		// ON DELETE CASCADE removes aliases. The DKIM key on disk is
		// left in place intentionally — if you re-add the domain, DKIM
		// continuity is preserved. Files under /etc/opendkim/keys/<domain>/
		// can be cleaned up manually.
		_, err := tx.ExecContext(ctx, `DELETE FROM domains WHERE id = ?`, domainID)
		return err
	})
	return res, err
}

// SetDomainRateLimitInput is the outgoing rate limit for one domain, as the
// operator entered it.
type SetDomainRateLimitInput struct {
	DomainID int64
	// PerHour is messages per hour; 0 disables the limit.
	PerHour int
	// Burst is the extra allowance in a 60s window (0 = none).
	Burst int
	// Action is models.RateActionDefer or models.RateActionReject.
	Action string
}

// rateLimitCeiling is the highest hourly limit the panel accepts. Above this the
// limit is not a limit: it exists to protect the server's reputation, and a
// number this large cannot be reached by accident.
const (
	rateLimitMaxPerHour = 100000
	rateLimitMaxBurst   = 10000
)

func validateRateLimit(in *SetDomainRateLimitInput) error {
	in.Action = strings.TrimSpace(strings.ToLower(in.Action))
	if in.Action == "" {
		in.Action = models.RateActionDefer
	}
	switch in.Action {
	case models.RateActionDefer, models.RateActionReject:
	default:
		return fmt.Errorf("%w: the action has to be %q or %q", ErrInvalidInput,
			models.RateActionDefer, models.RateActionReject)
	}
	if in.PerHour < 0 || in.PerHour > rateLimitMaxPerHour {
		return fmt.Errorf("%w: messages per hour has to be between 0 and %d", ErrInvalidInput, rateLimitMaxPerHour)
	}
	if in.Burst < 0 || in.Burst > rateLimitMaxBurst {
		return fmt.Errorf("%w: the burst allowance has to be between 0 and %d", ErrInvalidInput, rateLimitMaxBurst)
	}
	if in.PerHour == 0 && in.Burst > 0 {
		// A burst allowance without an hourly limit is not a limit at all: it
		// would allow Burst messages per minute forever. Refuse instead of
		// silently storing something that reads as "limited" in the panel.
		return fmt.Errorf("%w: a burst allowance needs an hourly limit", ErrInvalidInput)
	}
	return nil
}

// SetDomainRateLimit stores the outgoing limit for one domain.
//
// The limit is not enforced by the panel: it is rendered into postfwd's config
// and Postfix asks postfwd about every message (see
// reconciler.RenderPostfwdConf and RenderPostfixMainCF), so the change only
// takes effect after the sync has written the file and reloaded postfwd.
func (s *Service) SetDomainRateLimit(ctx context.Context, actor Actor, in SetDomainRateLimitInput) (*Result, error) {
	if err := validateRateLimit(&in); err != nil {
		return nil, err
	}

	var name string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM domains WHERE id = ?`, in.DomainID).Scan(&name)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: domain not found", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}

	res, err := s.Apply(ctx, actor, "domain.rate_limit", map[string]any{
		"domain_id": in.DomainID,
		"domain":    name,
		"per_hour":  in.PerHour,
		"burst":     in.Burst,
		"action":    in.Action,
	}, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE domains
			SET outbound_rate_limit = ?, outbound_rate_burst = ?, outbound_rate_action = ?
			WHERE id = ?
		`, in.PerHour, in.Burst, in.Action, in.DomainID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// UpdateDomainInput renames a domain.
type UpdateDomainInput struct {
	DomainID int64
	Name     string
}

// UpdateDomain renames a domain and every mailbox address on it.
//
// A rename is not just a row update: users.email is stored (it is what the
// reconciler writes into the mail server config), so the addresses are rewritten
// in the same transaction. Doing it separately would leave the panel briefly
// disagreeing with the mail server about who exists.
//
// The DKIM key on disk keeps its current path and selector: the private key is
// not bound to the domain name, and moving it would break DKIM for messages
// that are already in flight.
func (s *Service) UpdateDomain(ctx context.Context, actor Actor, in UpdateDomainInput) (*Result, error) {
	in.Name = strings.TrimSpace(strings.ToLower(in.Name))
	if err := validateDomainName(in.Name); err != nil {
		return nil, err
	}

	var current string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM domains WHERE id = ?`, in.DomainID).Scan(&current)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: domain not found", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	if current == in.Name {
		return nil, fmt.Errorf("%w: the domain is already named %s", ErrInvalidInput, in.Name)
	}

	res, err := s.Apply(ctx, actor, "domain.update", map[string]any{
		"domain_id": in.DomainID,
		"old_name":  current,
		"new_name":  in.Name,
	}, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM domains WHERE name = ?`, in.Name).Scan(&exists)
		if err == nil {
			return fmt.Errorf("%w: domain %s already exists", ErrConflict, in.Name)
		}
		if err != sql.ErrNoRows {
			return err
		}

		now := time.Now()
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET email = LOWER(username) || '@' || ?, updated_at = ? WHERE domain_id = ?`,
			in.Name, now, in.DomainID,
		); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE domains SET name = ?, updated_at = ? WHERE id = ?`,
			in.Name, now, in.DomainID,
		)
		return err
	})
	return res, err
}

func (s *Service) SetPrimaryDomain(ctx context.Context, actor Actor, domainID int64) (*Result, error) {
	var name string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM domains WHERE id = ?`, domainID).Scan(&name)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: domain not found", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}

	res, err := s.Apply(ctx, actor, "domain.set_primary", map[string]any{
		"domain_id": domainID,
		"domain":    name,
	}, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE domains SET is_primary = 0`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE domains SET is_primary = 1 WHERE id = ?`, domainID)
		return err
	})
	return res, err
}

func (s *Service) RegenerateDKIM(ctx context.Context, actor Actor, domainID int64) (*Result, error) {
	var name, selector string
	err := s.db.QueryRowContext(ctx,
		`SELECT name, dkim_selector FROM domains WHERE id = ?`, domainID,
	).Scan(&name, &selector)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: domain not found", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}

	// Rotate: generate new key with a timestamped selector, so the old
	// DNS record can coexist during propagation.
	newSelector := "default" // Phase 4 will make this time-based for smooth rotation
	result, err := dkim.GenerateWithSelector(ctx, name, "/etc/opendkim", newSelector, true)
	if err != nil {
		return nil, fmt.Errorf("generate DKIM: %w", err)
	}

	res, err := s.Apply(ctx, actor, "domain.regenerate_dkim", map[string]any{
		"domain_id": domainID,
		"domain":    name,
	}, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
            UPDATE domains
            SET dkim_selector = ?, dkim_private_key_path = ?, dkim_public_record = ?
            WHERE id = ?
        `, newSelector, result.PrivateKeyPath, result.PublicRecord, domainID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
