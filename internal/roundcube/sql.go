package roundcube

import (
	"fmt"
	"strconv"
	"strings"
)

// ensureUserSQL builds the script EnsureUser runs.
//
// It is one invocation on purpose: the three steps have to happen in the same
// MySQL session, because @existed, @uid and @hasidentity are session variables
// and LAST_INSERT_ID() is per-session too. Splitting it into three `mysql`
// calls would make "the row was created by somebody else in between" possible
// and would report it as this call's work.
//
// Nothing here uses INSERT ... SELECT ... WHERE NOT EXISTS against the target
// table: MySQL rejects a subquery that reads the table being inserted into
// (error 1093). The session-variable form does the same job and works on MySQL
// and MariaDB alike.
//
// `reply-to` is deliberately not set. It is one of the columns Roundcube
// declares NOT NULL DEFAULT ” (an empty reply-to is what Roundcube itself
// writes), and omitting it keeps the statement free of the only identifier that
// would need backquoting, which a Go raw string cannot hold anyway.
func (c *Client) ensureUserSQL(login string) (string, error) {
	if !databaseName.MatchString(c.cfg.Database) {
		return "", fmt.Errorf("roundcube: %q is not a valid database name", c.cfg.Database)
	}

	quoted := make([]string, 0, 5)
	for _, v := range []string{login, c.cfg.MailHost, c.cfg.Language, c.cfg.Preferences, identityName(c.cfg, login)} {
		q, err := quote(v)
		if err != nil {
			return "", err
		}
		quoted = append(quoted, q)
	}
	addr, mailHost, language, prefs, name := quoted[0], quoted[1], quoted[2], quoted[3], quoted[4]

	return fmt.Sprintf(`SET @existed = (SELECT COUNT(*) FROM users WHERE username = '%[1]s' AND mail_host = '%[2]s');
INSERT INTO users (username, mail_host, created, last_login, language, preferences)
  SELECT '%[1]s', '%[2]s', NOW(), NOW(), '%[3]s', '%[4]s' FROM DUAL WHERE @existed = 0;
SET @uid = IF(@existed = 0, LAST_INSERT_ID(), (SELECT user_id FROM users WHERE username = '%[1]s' AND mail_host = '%[2]s'));
SET @hasidentity = (SELECT COUNT(*) FROM identities WHERE user_id = @uid AND email = '%[1]s');
INSERT INTO identities (user_id, changed, del, standard, name, organization, email, signature, html_signature)
  SELECT @uid, NOW(), 0, 1, '%[5]s', '%[2]s', '%[1]s', '', 1 FROM DUAL WHERE @hasidentity = 0;
SELECT @existed, @uid, @hasidentity;`,
		addr, mailHost, language, prefs, name), nil
}

// identityName is the display name of the default identity: the configured one,
// or the address' local part, which is what the installer writes too.
func identityName(cfg Config, login string) string {
	if cfg.Name != "" {
		return cfg.Name
	}
	local, _, _ := strings.Cut(login, "@")
	return local
}

// parseEnsureOutput reads the single result row the script finishes with:
// @existed, @uid, @hasidentity.
//
// The row is read from the end of the output, because execx merges stderr into
// it: a MySQL warning ("Using a password on the command line interface...") is
// printed before the result and must not be mistaken for the answer.
func parseEnsureOutput(out string) (existed bool, userID int64, hadIdentity bool, err error) {
	fields := strings.Split(lastLine(out), "\t")
	if len(fields) != 3 {
		return false, 0, false, fmt.Errorf("want 3 columns, got %d", len(fields))
	}

	existedInt, err := strconv.Atoi(fields[0])
	if err != nil {
		return false, 0, false, fmt.Errorf("column 1: %w", err)
	}
	uid, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return false, 0, false, fmt.Errorf("column 2: %w", err)
	}
	identityInt, err := strconv.Atoi(fields[2])
	if err != nil {
		return false, 0, false, fmt.Errorf("column 3: %w", err)
	}

	if uid <= 0 {
		return false, 0, false, fmt.Errorf("the mailbox was not found in users after the insert")
	}
	return existedInt > 0, uid, identityInt > 0, nil
}
