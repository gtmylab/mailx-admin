package mutations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/dovecot"
	"github.com/gtmylab/mailx-admin/internal/models"
)

type CreateUserInput struct {
	DomainID int64
	Username string
	Password string
	QuotaMB  int
	IsAdmin  bool

	// Kind is models.KindVirtual (the default when empty) or
	// models.KindSystem.
	//
	// A system mailbox is one that belongs to a real Unix account — the
	// installer's "Add MailX User", a shell `useradd`. The panel does not
	// create the account; it records it, renders it into the same passwd-file
	// with the account's own uid/gid/home, and from then on the sync keeps it
	// instead of deleting its alias.
	Kind string

	// SysUID/SysGID/Home describe that account. Required for a system mailbox,
	// ignored for a virtual one.
	SysUID int
	SysGID int
	Home   string

	// PasswordHash, when set, is stored as-is instead of hashing Password.
	//
	// It is how a system mailbox keeps the password its Unix account already
	// has: the scanner reads the crypt(3) hash from /etc/shadow as
	// "{CRYPT}..." and that scheme is the only one the account's own tools
	// understand. Re-hashing the *Unix* password with argon2 would change what
	// `passwd` and login read, which is why this field exists at all.
	//
	// It is no longer how the installer registers the accounts it creates: the
	// installer knows the plaintext and hands it over with --password-stdin, so
	// the mailbox gets a hash the local Dovecot was asked about — and, on the
	// CLI path where the reconcile is inline, a login that was proven (see
	// ensureLoginUsable). What is left here is the adopted account: whether this
	// host's crypt() can check a given shadow hash depends on what hashed the
	// Unix password (yescrypt, $y$, is the one that gets refused), which is why
	// doctor reports every {CRYPT} row as unproven rather than as fine.
	PasswordHash string
}

func (s *Service) CreateUser(ctx context.Context, actor Actor, in CreateUserInput) (*Result, string, error) {
	if err := validateCreateUser(&in); err != nil {
		return nil, "", err
	}
	// resolve domain name for email
	var domainName string
	err := s.db.QueryRowContext(ctx, `SELECT name FROM domains WHERE id = ? AND active = 1`, in.DomainID).Scan(&domainName)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("%w: domain not found", ErrNotFound)
	}
	if err != nil {
		return nil, "", err
	}
	email := strings.ToLower(in.Username) + "@" + domainName

	hash, err := s.passwordHashFor(ctx, in)
	if err != nil {
		return nil, "", err
	}

	res, err := s.Apply(ctx, actor, "user.create", map[string]any{"email": email}, func(tx *sql.Tx) error {
		return applyCreateUserTx(ctx, tx, in, email, hash)
	})
	if err != nil {
		return nil, "", err
	}

	// Prove the login before answering. This is the last moment the plaintext
	// is known and the config is already on disk, and the one place a hash this
	// Dovecot refuses can still be turned into one it accepts (see
	// ensureLoginUsable). It runs before the Roundcube seed so the warnings the
	// operator sees describe the credentials that will actually work.
	s.ensureLoginUsable(ctx, actor, res, email, in.Password, hash)

	// Roundcube only after the commit, and never fatal: see seedRoundcube.
	s.seedRoundcube(ctx, actor, email, res)

	return res, email, nil
}

// validateCreateUser normalizes the username and kind in place and checks the
// input.
func validateCreateUser(in *CreateUserInput) error {
	in.Username = strings.TrimSpace(strings.ToLower(in.Username))

	switch in.Kind {
	case "":
		in.Kind = models.KindVirtual
	case models.KindVirtual:
	case models.KindSystem:
		// The panel cannot create Unix accounts, so a system mailbox is only
		// ever recorded from an account that already exists. Without its uid
		// and home the renderer would write the vmail defaults into the
		// passwd-file, and Dovecot would then refuse every folder of a
		// maildir owned by somebody else.
		if in.SysUID <= 0 || in.Home == "" {
			return fmt.Errorf("%w: a system mailbox needs the account's uid and home; "+
				"use `mailbox add --kind system` so they are read from /etc/passwd", ErrInvalidInput)
		}
		if !strings.HasPrefix(in.Home, "/") || strings.ContainsAny(in.Home, " \t") {
			return fmt.Errorf("%w: home must be an absolute path without spaces", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: unknown mailbox kind %q (want %q or %q)",
			ErrInvalidInput, in.Kind, models.KindVirtual, models.KindSystem)
	}

	if in.DomainID == 0 {
		return fmt.Errorf("%w: domain is required", ErrInvalidInput)
	}
	if in.Username == "" {
		return fmt.Errorf("%w: username is required", ErrInvalidInput)
	}
	if strings.ContainsAny(in.Username, "@/ ") {
		return fmt.Errorf("%w: username may not contain @, /, or space", ErrInvalidInput)
	}
	switch {
	case in.PasswordHash != "":
		// Pre-hashed input has to look like the passwd-file's own format, or
		// the account silently becomes impossible to log into.
		if !strings.HasPrefix(in.PasswordHash, "{") {
			return fmt.Errorf("%w: password hash must be in Dovecot format, e.g. {CRYPT}$6$...",
				ErrInvalidInput)
		}
	case len(in.Password) < 8:
		return fmt.Errorf("%w: password must be at least 8 characters", ErrInvalidInput)
	}
	if in.QuotaMB < 0 {
		return fmt.Errorf("%w: quota may not be negative", ErrInvalidInput)
	}
	return nil
}

// passwordHashFor produces the value the passwd-file will hold: either the hash
// the caller supplied (already in Dovecot format) or a fresh hash of the
// plaintext password.
func (s *Service) passwordHashFor(ctx context.Context, in CreateUserInput) (string, error) {
	if in.PasswordHash != "" {
		return in.PasswordHash, nil
	}
	return s.hashPassword(ctx, in.Password)
}

// hashPassword hashes one plaintext password with a scheme the local Dovecot
// can verify.
//
// The scheme is asked for, never assumed. An argon2id hash handed to a Dovecot
// built without libsodium is not a strong password — it is a login that always
// fails, with nothing in the panel able to explain why. internal/dovecot
// decides (and internal/reconciler renders the same answer into the passdb),
// so the hash and the daemon that has to check it always agree.
func (s *Service) hashPassword(ctx context.Context, password string) (string, error) {
	scheme, err := dovecot.Resolve(ctx, s.passwdScheme(), dovecot.ProbeCached)
	if err != nil {
		return "", fmt.Errorf("password scheme: %w", err)
	}

	hash, err := auth.DovecotHashScheme(password, scheme.Scheme)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return hash, nil
}

// passwdScheme is [mail] passwd_scheme, as the reconciler was configured with
// it ("" and "auto" both mean "ask the local Dovecot").
func (s *Service) passwdScheme() string {
	if s.rec == nil {
		return ""
	}
	return s.rec.Config().PasswdScheme
}

func applyCreateUserTx(ctx context.Context, tx *sql.Tx, in CreateUserInput, email, hash string) error {
	var exists int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE email = ?`, email).Scan(&exists)
	if err == nil {
		return fmt.Errorf("%w: user %s already exists", ErrConflict, email)
	}
	if err != sql.ErrNoRows {
		return err
	}
	_, err = tx.ExecContext(ctx, `
        INSERT INTO users (domain_id, username, email, password_hash, quota_mb, active, is_admin,
                           kind, sys_uid, sys_gid, home)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, NULLIF(?, 0), NULLIF(?, 0), NULLIF(?, ''))
    `, in.DomainID, in.Username, email, hash, in.QuotaMB, boolInt(in.IsAdmin),
		in.Kind, in.SysUID, in.SysGID, in.Home)
	return err
}

// exported for server's preview handler
func (s *Service) ApplyCreateUserToTx(ctx context.Context, tx *sql.Tx, in CreateUserInput) error {
	if err := validateCreateUser(&in); err != nil {
		return err
	}
	var domainName string
	err := tx.QueryRowContext(ctx, `SELECT name FROM domains WHERE id = ? AND active = 1`, in.DomainID).Scan(&domainName)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: domain not found", ErrNotFound)
	}
	if err != nil {
		return err
	}
	email := strings.ToLower(in.Username) + "@" + domainName

	hash, err := s.passwordHashFor(ctx, in)
	if err != nil {
		return err
	}
	return applyCreateUserTx(ctx, tx, in, email, hash)
}

type UpdateUserInput struct {
	UserID  int64
	QuotaMB *int
	IsAdmin *bool
	Active  *bool
}

func (s *Service) UpdateUser(ctx context.Context, actor Actor, in UpdateUserInput) (*Result, error) {
	res, err := s.Apply(ctx, actor, "user.update", map[string]any{
		"user_id": in.UserID,
	}, func(tx *sql.Tx) error {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, in.UserID).Scan(&exists)
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: user not found", ErrNotFound)
		}
		if err != nil {
			return err
		}

		if in.QuotaMB != nil {
			if *in.QuotaMB <= 0 {
				return fmt.Errorf("%w: quota must be positive", ErrInvalidInput)
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE users SET quota_mb = ?, updated_at = ? WHERE id = ?`,
				*in.QuotaMB, time.Now(), in.UserID,
			); err != nil {
				return err
			}
		}
		if in.IsAdmin != nil {
			if _, err := tx.ExecContext(ctx,
				`UPDATE users SET is_admin = ?, updated_at = ? WHERE id = ?`,
				boolInt(*in.IsAdmin), time.Now(), in.UserID,
			); err != nil {
				return err
			}
		}
		if in.Active != nil {
			if _, err := tx.ExecContext(ctx,
				`UPDATE users SET active = ?, updated_at = ? WHERE id = ?`,
				boolInt(*in.Active), time.Now(), in.UserID,
			); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

func (s *Service) DeleteUser(ctx context.Context, actor Actor, userID int64) (*Result, error) {
	// ---- Fetch what we're deleting for the audit trail ----
	var email string
	err := s.db.QueryRowContext(ctx, `SELECT email FROM users WHERE id = ?`, userID).Scan(&email)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}

	res, err := s.Apply(ctx, actor, "user.delete", map[string]any{
		"user_id": userID,
		"email":   email,
	}, func(tx *sql.Tx) error {
		// ON DELETE CASCADE handles policies. Aliases referencing this user
		// are NOT automatically removed — we leave them, since the maildir
		// path is what matters and stale aliases are a config smell the
		// operator should see.
		_, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
		return err
	})
	return res, err
}

type ResetPasswordInput struct {
	UserID   int64
	Password string
}

func (s *Service) ResetUserPassword(ctx context.Context, actor Actor, in ResetPasswordInput) (*Result, error) {
	if len(in.Password) < 8 {
		return nil, fmt.Errorf("%w: password must be at least 8 characters", ErrInvalidInput)
	}

	hash, err := s.hashPassword(ctx, in.Password)
	if err != nil {
		return nil, err
	}

	// The name a login arrives as, filled in by the transaction below: it is
	// what the probe has to prove (see ensureLoginUsable).
	var email string

	res, err := s.Apply(ctx, actor, "user.reset_password", map[string]any{
		"user_id": in.UserID,
	}, func(tx *sql.Tx) error {
		// The address is what the login probe needs: a passwd-file is keyed by
		// the full address, so the row's own email is the name to prove.
		err := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = ?`, in.UserID).Scan(&email)
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: user not found", ErrNotFound)
		}
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
			hash, time.Now(), in.UserID,
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Same proof as a new mailbox: a password that was just set is the only one
	// whose plaintext anyone can check, and a hash this Dovecot refuses is a
	// password reset that reset nothing (see ensureLoginUsable). The panel's own
	// path queues its sync, so there it is a no-op and doctor reports the row.
	s.ensureLoginUsable(ctx, actor, res, email, in.Password, hash)

	return res, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
