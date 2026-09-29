package mutations

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/dkim"
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
		result, err := dkim.Generate(in.Name, "/etc/opendkim")
		if err != nil {
			return nil, fmt.Errorf("generate DKIM: %w", err)
		}
		dkimPrivPath = result.PrivateKeyPath
		dkimPubRecord = result.PublicRecord
	}

	res, err := s.Apply(ctx, actor, "domain.create", map[string]any{
		"domain":   in.Name,
		"primary":  in.MakePrimary,
		"dkim_gen": in.GenerateDKIM,
	}, func(tx *sql.Tx) error {
		return applyCreateDomainTx(ctx, tx, in, dkimPrivPath, dkimPubRecord)
	})
	if err != nil {
		// Roll back the DKIM key if the DB write failed
		if dkimPrivPath != "" {
			_ = os.RemoveAll(filepath.Dir(dkimPrivPath))
		}
		return nil, err
	}

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

// applyCreateDomainTx inserts the domain row inside an existing transaction.
// dkimPrivPath/dkimPubRecord are produced outside the tx by CreateDomain
// (filesystem work) and may be empty.
func applyCreateDomainTx(ctx context.Context, tx *sql.Tx, in CreateDomainInput, dkimPrivPath, dkimPubRecord string) error {
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

	_, err = tx.ExecContext(ctx, `
		INSERT INTO domains (name, is_primary, dkim_selector, dkim_private_key_path, dkim_public_record, active)
		VALUES (?, ?, 'default', NULLIF(?, ''), NULLIF(?, ''), 1)
	`, in.Name, boolInt(in.MakePrimary), dkimPrivPath, dkimPubRecord)
	return err
}

// ApplyCreateDomainToTx creates a domain inside an existing transaction.
// Exported for the server's preview handler, which runs it and rolls back.
// No DKIM key is generated here, because that touches the filesystem.
func (s *Service) ApplyCreateDomainToTx(ctx context.Context, tx *sql.Tx, in CreateDomainInput) error {
	if err := validateCreateDomain(&in); err != nil {
		return err
	}
	return applyCreateDomainTx(ctx, tx, in, "", "")
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
	result, err := dkim.GenerateWithSelector(name, "/etc/opendkim", newSelector, true)
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
