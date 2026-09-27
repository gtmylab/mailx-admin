package mutations

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	if in.Name == "" || !strings.Contains(in.Name, ".") {
		return fmt.Errorf("%w: invalid domain name", ErrInvalidInput)
	}
	if strings.ContainsAny(in.Name, "@/ ") {
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

// helper: run a command, return combined output on error
func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, out)
	}
	return nil
}
