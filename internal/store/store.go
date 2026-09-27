package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/gtmylab/mailx-admin/internal/db"
	"github.com/gtmylab/mailx-admin/internal/models"
)

type Store struct {
	db *db.DB
}

func New(d *db.DB) *Store { return &Store{db: d} }

func (s *Store) listDomains(ctx context.Context, tx *sql.Tx) ([]models.Domain, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT id, name, is_primary, dkim_selector,
               COALESCE(dkim_private_key_path, ''), COALESCE(dkim_public_record, ''),
               dkim_created_at, active, created_at, updated_at
        FROM domains
        WHERE active = 1
        ORDER BY is_primary DESC, name ASC
    `)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	defer rows.Close()

	var out []models.Domain
	for rows.Next() {
		var d models.Domain
		var isPrimary, active int
		var dkimCreated sql.NullTime

		if err := rows.Scan(
			&d.ID, &d.Name, &isPrimary, &d.DKIMSelector,
			&d.DKIMPrivateKeyPath, &d.DKIMPublicRecord,
			&dkimCreated, &active, &d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		d.IsPrimary = isPrimary == 1
		d.Active = active == 1
		if dkimCreated.Valid {
			d.DKIMCreatedAt = &dkimCreated.Time
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) listUsers(ctx context.Context, tx *sql.Tx) ([]models.User, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT u.id, u.domain_id, u.username, u.email, u.password_hash,
               u.quota_mb, u.active, u.is_admin, u.last_login,
               u.created_at, u.updated_at, d.name
        FROM users u
        JOIN domains d ON d.id = u.domain_id
        WHERE u.active = 1 AND d.active = 1
        ORDER BY d.name, u.username
    `)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []models.User
	for rows.Next() {
		var u models.User
		var active, isAdmin int
		var lastLogin sql.NullTime

		if err := rows.Scan(
			&u.ID, &u.DomainID, &u.Username, &u.Email, &u.PasswordHash,
			&u.QuotaMB, &active, &isAdmin, &lastLogin,
			&u.CreatedAt, &u.UpdatedAt, &u.DomainName,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.Active = active == 1
		u.IsAdmin = isAdmin == 1
		if lastLogin.Valid {
			u.LastLogin = &lastLogin.Time
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) listAliases(ctx context.Context, tx *sql.Tx) ([]models.Alias, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT a.id, a.domain_id, a.source, a.destination, a.created_at, d.name
        FROM aliases a
        JOIN domains d ON d.id = a.domain_id
        WHERE d.active = 1
        ORDER BY d.name, a.source
    `)
	if err != nil {
		return nil, fmt.Errorf("list aliases: %w", err)
	}
	defer rows.Close()

	var out []models.Alias
	for rows.Next() {
		var a models.Alias
		if err := rows.Scan(
			&a.ID, &a.DomainID, &a.Source, &a.Destination,
			&a.CreatedAt, &a.DomainName,
		); err != nil {
			return nil, fmt.Errorf("scan alias: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) listPorts(ctx context.Context, tx *sql.Tx) ([]models.PortListener, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT id, port, service, tls_mode, require_sasl, COALESCE(description,''), enabled
        FROM port_listeners ORDER BY port
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.PortListener
	for rows.Next() {
		var l models.PortListener
		var sasl, enabled int
		if err := rows.Scan(&l.ID, &l.Port, &l.Service, &l.TLSMode, &sasl, &l.Description, &enabled); err != nil {
			continue
		}
		l.RequireSASL = sasl == 1
		l.Enabled = enabled == 1
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) listSieveRules(ctx context.Context, tx *sql.Tx) (map[int64][]models.SieveRule, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT id, user_id, rule_type, enabled, position, config, created_at, updated_at
        FROM sieve_rules ORDER BY user_id, position
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int64][]models.SieveRule)
	for rows.Next() {
		var r models.SieveRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.UserID, &r.RuleType, &enabled, &r.Position,
			&r.Config, &r.CreatedAt, &r.UpdatedAt); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		out[r.UserID] = append(out[r.UserID], r)
	}
	return out, rows.Err()
}

// CountUsersByDomain returns per-domain user counts for the dashboard.
func (s *Store) CountUsersByDomain(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT d.name, COUNT(u.id)
        FROM domains d
        LEFT JOIN users u ON u.domain_id = d.id AND u.active = 1
        WHERE d.active = 1
        GROUP BY d.name
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]int)
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		out[name] = count
	}
	return out, rows.Err()
}

// BeginTx exposes a transaction for the seed package.
func (s *Store) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}

type DomainInsert struct {
	Name               string
	IsPrimary          bool
	DKIMSelector       string
	DKIMPrivateKeyPath string
	DKIMPublicRecord   string
}

func (s *Store) InsertDomainTx(ctx context.Context, tx *sql.Tx, in DomainInsert) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `
        INSERT INTO domains (name, is_primary, dkim_selector, dkim_private_key_path, dkim_public_record, active)
        VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), 1)
        RETURNING id
    `, in.Name, boolInt(in.IsPrimary), in.DKIMSelector, in.DKIMPrivateKeyPath, in.DKIMPublicRecord).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert domain: %w", err)
	}
	return id, nil
}

type UserInsert struct {
	DomainID     int64
	Username     string
	Email        string
	PasswordHash string
	QuotaMB      int
	Active       bool
}

func (s *Store) InsertUserTx(ctx context.Context, tx *sql.Tx, in UserInsert) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `
        INSERT INTO users (domain_id, username, email, password_hash, quota_mb, active)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id
    `, in.DomainID, in.Username, in.Email, in.PasswordHash, in.QuotaMB, boolInt(in.Active)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert user: %w", err)
	}
	return id, nil
}

type AliasInsert struct {
	DomainID    int64
	Source      string
	Destination string
}

func (s *Store) InsertAliasTx(ctx context.Context, tx *sql.Tx, in AliasInsert) error {
	_, err := tx.ExecContext(ctx, `
        INSERT INTO aliases (domain_id, source, destination)
        VALUES (?, ?, ?)
    `, in.DomainID, in.Source, in.Destination)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Snapshot loads the full state the reconciler needs, in one consistent read.
func (s *Store) Snapshot(ctx context.Context) (*models.Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin snapshot tx: %w", err)
	}
	defer tx.Rollback()
	return s.SnapshotTx(ctx, tx)
}

func (s *Store) SnapshotTx(ctx context.Context, tx *sql.Tx) (*models.Snapshot, error) {
	domains, err := s.listDomains(ctx, tx)
	if err != nil {
		return nil, err
	}
	users, err := s.listUsers(ctx, tx)
	if err != nil {
		return nil, err
	}
	aliases, err := s.listAliases(ctx, tx)
	if err != nil {
		return nil, err
	}

	sieveRules, err := s.listSieveRules(ctx, tx)
	if err != nil {
		return nil, err
	}

	ports, err := s.listPorts(ctx, tx)
	if err != nil {
		return nil, err
	}

	return &models.Snapshot{
		Domains:    domains,
		Users:      users,
		Aliases:    aliases,
		Ports:      ports,
		SieveRules: sieveRules,
	}, nil
}
