package mutations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type CreateAliasInput struct {
	DomainID    int64
	Source      string // local part or "@domain" for catch-all
	Destination string // can be comma-separated
}

func (s *Service) CreateAlias(ctx context.Context, actor Actor, in CreateAliasInput) (*Result, error) {
	in.Source = strings.TrimSpace(strings.ToLower(in.Source))
	in.Destination = strings.TrimSpace(in.Destination)

	if in.Source == "" || in.Destination == "" {
		return nil, fmt.Errorf("%w: source and destination required", ErrInvalidInput)
	}
	if strings.ContainsAny(in.Source, " /\\") {
		return nil, fmt.Errorf("%w: source may not contain space or slash", ErrInvalidInput)
	}

	var domainName string
	err := s.db.QueryRowContext(ctx,
		`SELECT name FROM domains WHERE id = ? AND active = 1`, in.DomainID,
	).Scan(&domainName)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: domain not found", ErrNotFound)
	}

	// Validate destination emails
	for _, dest := range strings.Split(in.Destination, ",") {
		dest = strings.TrimSpace(dest)
		if dest == "" || !strings.Contains(dest, "@") {
			return nil, fmt.Errorf("%w: invalid destination %q", ErrInvalidInput, dest)
		}
	}

	res, err := s.Apply(ctx, actor, "alias.create", map[string]any{
		"domain": domainName,
		"source": in.Source,
	}, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM aliases WHERE domain_id = ? AND source = ?`,
			in.DomainID, in.Source,
		).Scan(&exists)
		if err == nil {
			return fmt.Errorf("%w: alias %s@%s already exists",
				ErrConflict, in.Source, domainName)
		}
		if err != sql.ErrNoRows {
			return err
		}

		_, err = tx.ExecContext(ctx,
			`INSERT INTO aliases (domain_id, source, destination) VALUES (?, ?, ?)`,
			in.DomainID, in.Source, in.Destination)
		return err
	})
	return res, err
}

func (s *Service) DeleteAlias(ctx context.Context, actor Actor, aliasID int64) (*Result, error) {
	var source, dest string
	var domainID int64
	err := s.db.QueryRowContext(ctx,
		`SELECT domain_id, source, destination FROM aliases WHERE id = ?`, aliasID,
	).Scan(&domainID, &source, &dest)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: alias not found", ErrNotFound)
	}

	res, err := s.Apply(ctx, actor, "alias.delete", map[string]any{
		"alias_id": aliasID,
		"source":   source,
	}, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM aliases WHERE id = ?`, aliasID)
		return err
	})
	return res, err
}

type UpdateAliasInput struct {
	AliasID     int64
	Destination string
}

func (s *Service) UpdateAlias(ctx context.Context, actor Actor, in UpdateAliasInput) (*Result, error) {
	in.Destination = strings.TrimSpace(in.Destination)
	if in.Destination == "" {
		return nil, fmt.Errorf("%w: destination required", ErrInvalidInput)
	}

	res, err := s.Apply(ctx, actor, "alias.update", map[string]any{
		"alias_id": in.AliasID,
	}, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM aliases WHERE id = ?`, in.AliasID).Scan(&exists)
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: alias not found", ErrNotFound)
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE aliases SET destination = ? WHERE id = ?`,
			in.Destination, in.AliasID)
		return err
	})
	return res, err
}
