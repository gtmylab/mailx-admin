package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

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

// userColumns is the column list every users query selects, in the order
// scanUsers reads it.
//
// It lives in one place because the list view, the users page and the
// reconciler's snapshot all have to agree. When the snapshot grows a column and
// only one query is updated, the panel quietly renders one shape of mailbox as
// another — which is exactly how system mailboxes used to be written into
// /var/mail/vhosts instead of /home.
const userColumns = `u.id, u.domain_id, u.username, u.email, u.display_name, u.password_hash,
               u.quota_mb, u.active, u.is_admin, u.last_login,
               u.created_at, u.updated_at, d.name,
               u.kind, COALESCE(u.sys_uid, 0), COALESCE(u.sys_gid, 0), COALESCE(u.home, '')`

// scanUsers drains a users query into models, applying the same conversions for
// every caller.
func scanUsers(rows *sql.Rows) ([]models.User, error) {
	var out []models.User
	for rows.Next() {
		var u models.User
		var active, isAdmin int
		var lastLogin sql.NullTime

		if err := rows.Scan(
			&u.ID, &u.DomainID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash,
			&u.QuotaMB, &active, &isAdmin, &lastLogin,
			&u.CreatedAt, &u.UpdatedAt, &u.DomainName,
			&u.Kind, &u.SysUID, &u.SysGID, &u.Home,
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

func (s *Store) listUsers(ctx context.Context, tx *sql.Tx) ([]models.User, error) {
	rows, err := tx.QueryContext(ctx, `
        SELECT `+userColumns+`
        FROM users u
        JOIN domains d ON d.id = u.domain_id
        WHERE u.active = 1 AND d.active = 1
        ORDER BY d.name, u.username
    `)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	return scanUsers(rows)
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

	// Kind is models.KindVirtual (the default when empty) or
	// models.KindSystem.
	Kind string

	// SysUID/SysGID/Home are only meaningful for a system mailbox: the uid,
	// gid and maildir parent of the Unix account it belongs to.
	SysUID int
	SysGID int
	Home   string
}

func (s *Store) InsertUserTx(ctx context.Context, tx *sql.Tx, in UserInsert) (int64, error) {
	if in.Kind == "" {
		in.Kind = models.KindVirtual
	}
	var id int64
	err := tx.QueryRowContext(ctx, `
        INSERT INTO users (domain_id, username, email, password_hash, quota_mb, active,
                           kind, sys_uid, sys_gid, home)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, 0), NULLIF(?, 0), NULLIF(?, ''))
        RETURNING id
    `, in.DomainID, in.Username, in.Email, in.PasswordHash, in.QuotaMB, boolInt(in.Active),
		in.Kind, in.SysUID, in.SysGID, in.Home).Scan(&id)
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

// Users returns the mailboxes for the users list.
//
// includeInactive exists because the list used to hide them: a mailbox that was
// disabled in the panel (or that lives only in the server's own passwd file)
// simply was not there, which is indistinguishable from "my user disappeared
// again". The filter is opt-in so the default view stays short.
func (s *Store) Users(ctx context.Context, includeInactive bool) ([]models.User, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin users tx: %w", err)
	}
	defer tx.Rollback()

	query := `
        SELECT ` + userColumns + `
        FROM users u
        JOIN domains d ON d.id = u.domain_id
        WHERE d.active = 1`
	if !includeInactive {
		query += ` AND u.active = 1`
	}
	query += ` ORDER BY d.name, u.username`

	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	return scanUsers(rows)
}

// ExistingKeysTx returns the identifiers already in the database, for the
// comparison the "Import from server" flow needs. It is read inside the caller's
// transaction: adopt must decide on the same snapshot it writes to.
//
// Inactive rows count as existing. Importing a mailbox that was deliberately
// disabled would trip the unique index, and the operator would see a constraint
// error instead of "already imported".
func (s *Store) ExistingKeysTx(ctx context.Context, tx *sql.Tx) (domains, emails, aliases map[string]bool, err error) {
	domains, err = stringSet(ctx, tx, `SELECT name FROM domains`)
	if err != nil {
		return nil, nil, nil, err
	}
	emails, err = stringSet(ctx, tx, `SELECT LOWER(email) FROM users`)
	if err != nil {
		return nil, nil, nil, err
	}

	aliases = map[string]bool{}
	rows, err := tx.QueryContext(ctx, `
        SELECT LOWER(a.source), d.name FROM aliases a JOIN domains d ON d.id = a.domain_id
    `)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list aliases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var source, domain string
		if err := rows.Scan(&source, &domain); err != nil {
			return nil, nil, nil, fmt.Errorf("scan alias: %w", err)
		}
		aliases[source+"@"+domain] = true
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	return domains, emails, aliases, nil
}

func stringSet(ctx context.Context, tx *sql.Tx, query string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query %q: %w", query, err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan %q: %w", query, err)
		}
		out[v] = true
	}
	return out, rows.Err()
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

	outboundIPs, err := s.listOutboundIPsTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	suppressions, err := s.listSuppressionsTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	relay, err := s.loadRelayTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	return &models.Snapshot{
		Domains:      domains,
		Users:        users,
		Aliases:      aliases,
		Ports:        ports,
		SieveRules:   sieveRules,
		OutboundIPs:  outboundIPs,
		Suppressions: suppressions,
		Relay:        relay,
	}, nil
}

// settingTx reads one settings value inside a transaction, returning "" when the
// key is absent.
func (s *Store) settingTx(ctx context.Context, tx *sql.Tx, key string) (string, error) {
	var v string
	err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// loadRelayTx reads the outbound smarthost settings. A disabled relay (or one
// with no host) returns an empty config, which means "deliver directly".
func (s *Store) loadRelayTx(ctx context.Context, tx *sql.Tx) (*models.RelayConfig, error) {
	enabled, err := s.settingTx(ctx, tx, "relay_enabled")
	if err != nil {
		return nil, err
	}
	if enabled != "1" && enabled != "true" {
		return &models.RelayConfig{}, nil
	}

	host, err := s.settingTx(ctx, tx, "relay_host")
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &models.RelayConfig{}, nil
	}

	portStr, _ := s.settingTx(ctx, tx, "relay_port")
	username, _ := s.settingTx(ctx, tx, "relay_username")
	password, _ := s.settingTx(ctx, tx, "relay_password")
	tlsMode, _ := s.settingTx(ctx, tx, "relay_tls")

	port, _ := strconv.Atoi(portStr)
	return &models.RelayConfig{
		Enabled:  true,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		TLSMode:  tlsMode,
	}, nil
}
