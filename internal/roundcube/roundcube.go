// Package roundcube pre-seeds mailboxes in Roundcube's own MySQL database.
//
// Roundcube has its own `users` and `identities` tables. It also has
// auto_create_user on by default, so a login it has never seen still works —
// which is exactly why a *missing* row is not what refuses a login. What the
// row buys is the rest of webmail: a default identity (so the From: address is
// the mailbox' own, not Roundcube's guess), the user's language and preference
// blob, and something an operator can look at when they ask "does webmail know
// about this mailbox?".
//
// The panel therefore creates the same two rows the installer creates when it
// adds a user, through the same client: `mysql <database>`, on the local
// socket, as root. That is deliberate — it needs no MySQL driver compiled into
// the binary, no credentials stored in admin.toml beyond what the installer
// already wrote, and it talks to the server the way every other command in this
// project does.
//
// Nothing here ever migrates or otherwise touches Roundcube's schema. The
// statements are INSERTs against `users` and `identities`, both of which come
// from Roundcube's own SQL/MySQL/*.initial.sql and have kept this shape since
// 1.x.
package roundcube

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
)

const (
	// DefaultDatabase is the schema name the installer creates.
	DefaultDatabase = "roundcubemail"

	// DefaultBinary is the MySQL client. The panel runs as root on the mail
	// server, which is how the installer's own `mysql ...` calls work.
	DefaultBinary = "mysql"

	// DefaultMailHost has to match Roundcube's `imap_host` (or the older
	// `default_host`), or the row written here is not the one a login looks up.
	DefaultMailHost = "localhost"

	// DefaultLanguage is the language of a pre-seeded user.
	DefaultLanguage = "en_GB"

	// DefaultTimeout bounds one client invocation: a mailbox creation must
	// not hang on a wedged MySQL client.
	DefaultTimeout = 20 * time.Second

	// DefaultPreferences is the preference blob the installer writes, kept
	// byte-for-byte so a mailbox created in the panel and one created by the
	// installer start from the same webmail settings: compose in a window,
	// HTML editor on, no MDN, no DSN.
	DefaultPreferences = `a:6:{s:14:"compose_extwin";i:1;s:10:"htmleditor";i:1;` +
		`s:11:"mdn_default";b:0;s:11:"dsn_default";b:0;s:13:"sig_separator";b:0;` +
		`s:25:"compose_save_localstorage";i:1;}`
)

// Config describes where Roundcube's database is and how to talk to it.
type Config struct {
	Database    string
	Binary      string
	Args        []string
	MailHost    string
	Language    string
	Name        string // identity name; empty = the address' local part
	Preferences string // empty = DefaultPreferences
	Timeout     time.Duration
}

// Normalize returns the config with every default applied, so callers that
// build one by hand get the same behaviour as the ones that load admin.toml.
func (c Config) Normalize() Config {
	if c.Database == "" {
		c.Database = DefaultDatabase
	}
	if c.Binary == "" {
		c.Binary = DefaultBinary
	}
	if c.MailHost == "" {
		c.MailHost = DefaultMailHost
	}
	if c.Language == "" {
		c.Language = DefaultLanguage
	}
	if c.Preferences == "" {
		c.Preferences = DefaultPreferences
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	return c
}

// Client runs the pre-seed and the reads `roundcube sync` needs.
type Client struct {
	cfg Config
}

// New builds a client, filling in the defaults for anything left empty.
func New(cfg Config) *Client { return &Client{cfg: cfg.Normalize()} }

// Config returns what this client was built with.
func (c *Client) Config() Config { return c.cfg }

// Result reports what one EnsureUser call did.
type Result struct {
	Login         string
	UserID        int64
	Created       bool // the `users` row was inserted
	IdentityAdded bool // an `identities` row was inserted
}

// String renders the outcome for the CLI and the audit trail.
func (r Result) String() string {
	switch {
	case r.Created && r.IdentityAdded:
		return fmt.Sprintf("created Roundcube user %d and its default identity", r.UserID)
	case r.Created:
		return fmt.Sprintf("created Roundcube user %d (it already had an identity)", r.UserID)
	case r.IdentityAdded:
		return fmt.Sprintf("roundcube already knew user %d; added its default identity", r.UserID)
	default:
		return fmt.Sprintf("roundcube already knew user %d", r.UserID)
	}
}

// EnsureUser makes sure Roundcube has a `users` row and a default `identities`
// row for login, and reports what it had to create.
//
// It is idempotent on purpose: Roundcube's unique key is (mail_host, username),
// so a mailbox whose row already exists — created by the installer, or by
// Roundcube itself on an earlier login — is left exactly as it is, preferences
// included.
func (c *Client) EnsureUser(ctx context.Context, login string) (Result, error) {
	login = normalizeLogin(login)
	if err := validateLogin(login); err != nil {
		return Result{}, err
	}

	sql, err := c.ensureUserSQL(login)
	if err != nil {
		return Result{}, err
	}

	out, err := c.run(ctx, sql)
	if err != nil {
		return Result{}, err
	}

	existed, userID, hadIdentity, err := parseEnsureOutput(out)
	if err != nil {
		return Result{}, fmt.Errorf("unexpected output from the mysql client: %w (got %q)", err, strings.TrimSpace(out))
	}

	return Result{
		Login:         login,
		UserID:        userID,
		Created:       !existed,
		IdentityAdded: !hadIdentity,
	}, nil
}

// ListUsers returns the logins Roundcube already knows, lower-cased. It is the
// back-fill's starting point: what the panel has, minus what Roundcube has, is
// what `mailx-admin roundcube sync` creates.
func (c *Client) ListUsers(ctx context.Context) ([]string, error) {
	out, err := c.run(ctx, "SELECT username FROM users ORDER BY username;")
	if err != nil {
		return nil, err
	}

	var logins []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		logins = append(logins, strings.ToLower(line))
	}
	return logins, nil
}

// Ping checks that Roundcube's database can be reached at all, and says how
// many users it holds. Both the doctor check and `roundcube sync` start here,
// because "MySQL is unreachable" and "the mailbox is missing" look identical
// from a failed INSERT.
func (c *Client) Ping(ctx context.Context) (int, error) {
	out, err := c.run(ctx, "SELECT COUNT(*) FROM users;")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(lastLine(out))
	if err != nil {
		return 0, fmt.Errorf("unexpected output from the mysql client: %w (got %q)", err, strings.TrimSpace(out))
	}
	return n, nil
}

// run executes one script through the MySQL client and returns its output.
//
// The client binary is looked up first so a host without mysql-client gets
// "not installed" instead of a bare exec error, and the whole invocation is
// bounded by execx (deadline, process-group kill, bounded output).
func (c *Client) run(ctx context.Context, sql string) (string, error) {
	if _, err := exec.LookPath(c.cfg.Binary); err != nil {
		return "", fmt.Errorf("the %s client is not installed on this server: %w", c.cfg.Binary, err)
	}

	// The database name goes first, exactly as in the installer's own calls:
	// `mysql <database> --batch -e <sql>`.
	args := make([]string, 0, len(c.cfg.Args)+7)
	args = append(args, c.cfg.Args...)
	args = append(args, c.cfg.Database, "--batch", "--skip-column-names",
		"--connect-timeout=5", "-e", sql)

	out, err := execx.Output(ctx, c.cfg.Timeout, c.cfg.Binary, args...)
	if err != nil {
		return string(out), fmt.Errorf("mysql %s: %w\n%s", c.cfg.Database, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// normalizeLogin lower-cases and trims an address the way the panel stores it.
func normalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

// validateLogin rejects anything that cannot be a mailbox address before a
// single byte reaches MySQL. Quoting (see quote) is what makes the statements
// safe; this is the other half — a "user name" with a space or a newline in it
// is a bug somewhere else, and it must not end up in the database.
func validateLogin(login string) error {
	switch {
	case login == "":
		return fmt.Errorf("roundcube: empty login")
	case len(login) > 254:
		return fmt.Errorf("roundcube: login %q is too long", login)
	case strings.ContainsAny(login, " \t\r\n\x00"):
		return fmt.Errorf("roundcube: login %q contains whitespace or a control character", login)
	case strings.Count(login, "@") != 1:
		return fmt.Errorf("roundcube: login %q is not an address (want local@domain)", login)
	}
	return nil
}

// databaseName is the one identifier that is interpolated unquoted, so it is
// restricted to what MySQL accepts in a schema name and always backquoted.
var databaseName = regexp.MustCompile(`^[A-Za-z0-9_$]+$`)

// quote makes a value safe to embed in a MySQL single-quoted string literal.
//
// The panel never builds SQL from anything but an address it validated and its
// own preferences blob, but "never" is not a guarantee that survives a
// refactor: this is the part that has to hold.
func quote(s string) (string, error) {
	if strings.ContainsAny(s, "\x00\n\r\x1a") {
		return "", fmt.Errorf("roundcube: value %q contains a control character", s)
	}
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, `"`, `\"`)
	return r.Replace(s), nil
}

// lastLine returns the last non-empty line of the client's output, trimmed.
// Result sets are printed one row per line, but a warning on stderr (which
// execx merges in) would otherwise be mistaken for the answer.
func lastLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}
