package seed

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/store"
)

type Options struct {
	PostfixConfDir    string
	DovecotConfDir    string
	OpenDKIMDir       string
	PrimaryDomainFile string
	DryRun            bool

	// PasswdFile and ShadowFile are the system's own account databases. The
	// scanner reads them to find mailboxes that live on a real Unix account —
	// the installer's "Add MailX User", a shell `useradd`, an older Roundcube
	// install. Empty means /etc/passwd and /etc/shadow.
	PasswdFile string
	ShadowFile string

	// SystemMailDomain is the domain a system mailbox is attributed to when it
	// cannot be derived. Empty means "the primary domain", which is what the
	// installer records in PrimaryDomainFile.
	SystemMailDomain string

	// MinSystemMailboxUID is the lowest uid that can own a mailbox. Everything
	// below it is a service account (daemon, www-data, ...), and vmail itself
	// is excluded by name. Debian and Ubuntu start user accounts at 1000.
	// Zero means 1000.
	MinSystemMailboxUID int
}

// defaultMinSystemMailboxUID is where user accounts start on the distributions
// this project installs on.
const defaultMinSystemMailboxUID = 1000

// defaultQuotaMB is what a mailbox gets when the server says nothing about its
// quota — the same default the passwd-file scan has always used.
const defaultQuotaMB = 1024

type Found struct {
	Domains []FoundDomain
	Users   []FoundUser
	Aliases []FoundAlias
}

type FoundDomain struct {
	Name             string
	IsPrimary        bool
	DKIMPrivateKey   string
	DKIMPublicRecord string
}

type FoundUser struct {
	Email        string
	Domain       string
	LocalPart    string
	PasswordHash string // in Dovecot format, e.g. "{ARGON2ID}$argon2id$..."
	QuotaMB      int

	// Kind is models.KindVirtual for a mailbox the panel owns, or
	// models.KindSystem for one that belongs to a real Unix account.
	Kind string

	// SysUID/SysGID/Home describe that account. Zero/empty for a virtual
	// mailbox.
	SysUID int
	SysGID int
	Home   string
}

type FoundAlias struct {
	Domain      string
	Source      string
	Destination string
}

// Scan reads the existing server configs and returns what was found.
// It does NOT touch the DB.
func Scan(opts Options) (*Found, error) {
	out := &Found{}

	// ---- Primary domain -------------------------------------------------
	var primaryDomain string
	if opts.PrimaryDomainFile != "" {
		if b, err := os.ReadFile(opts.PrimaryDomainFile); err == nil {
			primaryDomain = strings.TrimSpace(string(b))
		}
	}

	// ---- Domains from helo_access / virtual_domains ---------------------
	domainsSeen := map[string]bool{}

	virtualDomains := filepath.Join(opts.PostfixConfDir, "virtual_domains")
	if f, err := os.Open(virtualDomains); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// format: "example.com OK"
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				domainsSeen[parts[0]] = true
			}
		}
		f.Close()
	}

	// Fallback: parse virtual_mailbox_domains from main.cf
	if len(domainsSeen) == 0 {
		mainCF := filepath.Join(opts.PostfixConfDir, "main.cf")
		if f, err := os.Open(mainCF); err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "virtual_mailbox_domains") {
					_, val, _ := strings.Cut(line, "=")
					for _, d := range strings.Split(val, ",") {
						d = strings.TrimSpace(d)
						if d != "" && !strings.HasPrefix(d, "$") {
							domainsSeen[d] = true
						}
					}
				}
			}
			f.Close()
		}
	}

	if primaryDomain != "" {
		domainsSeen[primaryDomain] = true
	}

	for name := range domainsSeen {
		d := FoundDomain{
			Name:      name,
			IsPrimary: name == primaryDomain,
		}

		// DKIM key
		keyDir := filepath.Join(opts.OpenDKIMDir, "keys", name)
		privKey := filepath.Join(keyDir, "default.private")
		txtFile := filepath.Join(keyDir, "default.txt")

		if _, err := os.Stat(privKey); err == nil {
			d.DKIMPrivateKey = privKey
		}
		if b, err := os.ReadFile(txtFile); err == nil {
			d.DKIMPublicRecord = extractDKIMRecord(string(b))
		}

		out.Domains = append(out.Domains, d)
	}
	sort.Slice(out.Domains, func(i, j int) bool {
		return out.Domains[i].Name < out.Domains[j].Name
	})

	// ---- Users from /etc/dovecot/users (passwd-file) --------------------
	dovecotUsers := filepath.Join(opts.DovecotConfDir, "users")
	if f, err := os.Open(dovecotUsers); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Format: email:password:uid:gid:gecos:home:shell:extra
			fields := strings.Split(line, ":")
			if len(fields) < 6 {
				continue
			}

			email := fields[0]
			hash := fields[1]
			home := fields[5]
			extra := ""
			if len(fields) >= 8 {
				extra = fields[7]
			}

			local, domain, ok := strings.Cut(email, "@")
			if !ok {
				continue
			}

			quota := 1024
			if q := parseQuotaRule(extra); q > 0 {
				quota = q
			} else if q := parseQuotaFromHome(home); q > 0 {
				quota = q
			}

			out.Users = append(out.Users, FoundUser{
				Email:        email,
				Domain:       domain,
				LocalPart:    local,
				PasswordHash: hash,
				QuotaMB:      quota,
				Kind:         models.KindVirtual,
			})
		}
		f.Close()
	}

	// ---- Users that live on real Unix accounts --------------------------
	//
	// "Add MailX User" in the installer, a shell `useradd`, an older Roundcube
	// install: all of them create a real account whose mail is in
	// /home/<user>/Maildir, and none of them ever told the panel. The mailbox
	// was therefore invisible in the UI *and* the /etc/postfix/virtual line the
	// installer wrote for it was deleted by the next sync — the panel rewrites
	// that file from its own database.
	//
	// The server's own files are the way in: /etc/passwd for the account,
	// /etc/shadow for the password it already authenticates with, the maildir
	// for proof that it really is a mailbox.
	seenEmail := make(map[string]bool, len(out.Users))
	for _, u := range out.Users {
		seenEmail[strings.ToLower(u.Email)] = true
	}
	out.Users = append(out.Users, scanSystemMailboxes(opts, primaryDomain, seenEmail)...)

	sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].Email < out.Users[j].Email })

	// ---- Aliases from /etc/postfix/virtual ------------------------------
	virtualMap := filepath.Join(opts.PostfixConfDir, "virtual")
	if f, err := os.Open(virtualMap); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			source, destination := fields[0], fields[1]

			// Skip self-maps (user -> same user) — these are generated from users
			if source == destination {
				continue
			}

			_, domain, ok := strings.Cut(source, "@")
			if !ok {
				continue
			}

			// Strip leading @ for catch-all: "@example.com" -> "@" + domain
			local := source[:strings.Index(source, "@")]

			out.Aliases = append(out.Aliases, FoundAlias{
				Domain:      domain,
				Source:      local,
				Destination: destination,
			})
		}
		f.Close()
	}

	return out, nil
}

// Apply inserts everything Found into the DB in one transaction.
func Apply(ctx context.Context, st *store.Store, f *Found) error {
	tx, err := st.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Domains
	domainIDs := map[string]int64{}
	for _, d := range f.Domains {
		id, err := st.InsertDomainTx(ctx, tx, store.DomainInsert{
			Name:               d.Name,
			IsPrimary:          d.IsPrimary,
			DKIMSelector:       "default",
			DKIMPrivateKeyPath: d.DKIMPrivateKey,
			DKIMPublicRecord:   d.DKIMPublicRecord,
		})
		if err != nil {
			return fmt.Errorf("insert domain %s: %w", d.Name, err)
		}
		domainIDs[d.Name] = id
	}

	// Users
	for _, u := range f.Users {
		domainID, ok := domainIDs[u.Domain]
		if !ok {
			return fmt.Errorf("user %s references unknown domain %s", u.Email, u.Domain)
		}
		_, err := st.InsertUserTx(ctx, tx, store.UserInsert{
			DomainID:     domainID,
			Username:     u.LocalPart,
			Email:        u.Email,
			PasswordHash: u.PasswordHash, // already in Dovecot format
			QuotaMB:      u.QuotaMB,
			Active:       true,
			Kind:         u.Kind,
			SysUID:       u.SysUID,
			SysGID:       u.SysGID,
			Home:         u.Home,
		})
		if err != nil {
			return fmt.Errorf("insert user %s: %w", u.Email, err)
		}
	}

	// Aliases
	for _, a := range f.Aliases {
		domainID, ok := domainIDs[a.Domain]
		if !ok {
			continue // skip orphans
		}
		if err := st.InsertAliasTx(ctx, tx, store.AliasInsert{
			DomainID:    domainID,
			Source:      a.Source,
			Destination: a.Destination,
		}); err != nil {
			return fmt.Errorf("insert alias %s@%s: %w", a.Source, a.Domain, err)
		}
	}

	return tx.Commit()
}

// ---- helpers -------------------------------------------------------------

func extractDKIMRecord(txtFileContent string) string {
	// The .txt file looks like:
	//   default._domainkey IN TXT ( "v=DKIM1; h=sha256; k=rsa; "
	//     "p=MIIBIjANBgkq..." )
	// We extract just the concatenated quoted strings.
	var parts []string
	for _, line := range strings.Split(txtFileContent, "\n") {
		start := strings.Index(line, `"`)
		end := strings.LastIndex(line, `"`)
		if start >= 0 && end > start {
			parts = append(parts, line[start+1:end])
		}
	}
	joined := strings.Join(parts, "")
	// Collapse whitespace runs into a single space
	return strings.Join(strings.Fields(joined), " ")
}

func parseQuotaRule(s string) int {
	// Looks for `storage=<size>`, as written by the panel
	// (`userdb_quota_rule=*:storage=2048M`) and by the installer
	// (`quota_rule = *:storage=2048M`). A bare number is bytes, which is what
	// Dovecot means by it.
	idx := strings.Index(s, "storage=")
	if idx < 0 {
		return 0
	}
	rest := s[idx+len("storage="):]

	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	n, err := strconv.Atoi(rest[:i])
	if err != nil || n < 0 {
		return 0
	}

	suffix := ""
	if i < len(rest) {
		suffix = strings.ToUpper(rest[i : i+1])
	}
	switch suffix {
	case "M":
		return n
	case "G":
		return n * 1024
	case "T":
		return n * 1024 * 1024
	case "", "B":
		// Bytes, rounded up, never zero: a 0 MB quota rule is a mailbox
		// nobody can receive into.
		mb := (n + 1<<20 - 1) >> 20
		if mb < 1 {
			mb = 1
		}
		return mb
	default:
		// An unknown suffix is not a size we understand; the caller falls back
		// to the default rather than importing nonsense.
		return 0
	}
}

// parseQuotaFromHome reads the quota note the installer leaves in an account's
// home:
//
//	echo "quota_rule = *:storage=2048M" > /home/<user>/.dovecot.quota
//
// Dovecot never reads that file itself. It is the installer's note to whoever
// comes next, and the only record of a shell-created mailbox's quota — before
// this, importing such a mailbox silently reset it to the default.
func parseQuotaFromHome(home string) int {
	if home == "" {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(home, ".dovecot.quota"))
	if err != nil {
		return 0
	}
	return parseQuotaRule(string(b))
}

// scanSystemMailboxes finds mailboxes that belong to real Unix accounts.
//
// Only accounts that look like a mailbox are returned: a uid at or above the
// first user account, a login shell, a home directory that actually contains a
// Maildir, and a password in /etc/shadow that can be used — a locked or missing
// password would import an account nobody can log into, which is worse than not
// importing it at all.
func scanSystemMailboxes(opts Options, primaryDomain string, alreadyKnown map[string]bool) []FoundUser {
	domain := opts.SystemMailDomain
	if domain == "" {
		domain = primaryDomain
	}
	if domain == "" {
		// Without a domain, a login name says nothing about the address it
		// answers, and inventing one would create mailboxes nobody can use.
		// A single-domain server is the common case, and it has a primary.
		return nil
	}

	passwdPath := opts.PasswdFile
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	shadowPath := opts.ShadowFile
	if shadowPath == "" {
		shadowPath = "/etc/shadow"
	}
	minUID := opts.MinSystemMailboxUID
	if minUID <= 0 {
		minUID = defaultMinSystemMailboxUID
	}

	f, err := os.Open(passwdPath)
	if err != nil {
		// Not a host with a passwd file, or not allowed to read it. There is
		// nothing to import, and this is not an error: the passwd-file scan
		// above still describes every mailbox the panel itself manages.
		return nil
	}
	defer f.Close()

	hashes := readShadowHashes(shadowPath)

	var out []FoundUser
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		// name:passwd:uid:gid:gecos:home:shell
		if len(fields) < 7 {
			continue
		}
		name, gidStr, home, shell := fields[0], fields[3], fields[5], fields[6]
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(gidStr)
		if err != nil {
			continue
		}

		switch {
		case name == "" || strings.ContainsAny(name, " @/:\\"):
			continue
		case name == "vmail":
			// vmail owns the virtual mailboxes; it is a delivery account, not
			// somebody's mailbox.
			continue
		case uid < minUID:
			continue
		case !isLoginShell(shell):
			continue
		case !hasMaildir(home):
			continue
		}

		email := strings.ToLower(name) + "@" + domain
		if alreadyKnown[email] {
			// The passwd-file already described it, so the panel manages it.
			// Keeping both would put two entries with one address into the
			// import plan.
			continue
		}

		hash, ok := hashes[name]
		if !ok || !isUsableShadowHash(hash) {
			continue
		}

		quota := parseQuotaFromHome(home)
		if quota <= 0 {
			quota = defaultQuotaMB
		}

		out = append(out, FoundUser{
			Email:        email,
			Domain:       domain,
			LocalPart:    strings.ToLower(name),
			PasswordHash: "{CRYPT}" + hash,
			QuotaMB:      quota,
			Kind:         models.KindSystem,
			SysUID:       uid,
			SysGID:       gid,
			Home:         home,
		})
	}
	return out
}

// readShadowHashes returns the account -> hash map from /etc/shadow. An
// unreadable file (not root, no shadow database) yields an empty map, which
// makes every system mailbox look like it has no password — and therefore be
// reported as skipped instead of being imported with a hash that cannot work.
func readShadowHashes(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	out := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 2 {
			continue
		}
		out[fields[0]] = fields[1]
	}
	return out
}

// isUsableShadowHash reports whether a shadow field is a crypt(3) hash Dovecot
// can verify with the {CRYPT} scheme.
//
// "*" means no password and "!" means locked; "x" means the hash lives in
// /etc/shadow rather than in /etc/passwd. None of them is a password, and
// importing one would produce a mailbox that accepts no login — the failure the
// operator would then report as "the panel broke my user".
func isUsableShadowHash(h string) bool {
	return strings.HasPrefix(h, "$") && len(h) > 3
}

// isLoginShell reports whether an account is meant to be logged into by its
// owner. Service accounts carry nologin/false there, and their home directories
// are not mailboxes.
func isLoginShell(shell string) bool {
	switch shell {
	case "", "/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/false", "/bin/false",
		"/bin/sync", "/sbin/halt", "/sbin/shutdown":
		return false
	}
	return true
}

// hasMaildir is the difference between "a Unix account" and "a mailbox". A home
// directory without one is somebody's shell account, and importing it would
// create an address that receives nothing.
func hasMaildir(home string) bool {
	if home == "" || home == "/" {
		return false
	}
	fi, err := os.Stat(filepath.Join(home, "Maildir"))
	return err == nil && fi.IsDir()
}

// SystemAccount is a Unix account as the system's own files describe it.
type SystemAccount struct {
	Name string
	UID  int
	GID  int
	Home string

	// PasswordHash is the account's crypt(3) hash with the {CRYPT} prefix
	// Dovecot expects, or "" when the account cannot log in (locked, no
	// password, or /etc/shadow was not readable).
	PasswordHash string
}

// LookupSystemAccount reads one account from /etc/passwd and /etc/shadow.
//
// It exists so `mailx-admin mailbox add --kind system` can adopt an account that
// already exists instead of inventing one: creating a *second* account with the
// same name is what makes a mailbox "not appear" in the panel, and the panel
// cannot create Unix accounts anyway.
//
// A missing account returns (nil, nil) — absent is an answer here, not an error.
func LookupSystemAccount(opts Options, name string) (*SystemAccount, error) {
	passwdPath := opts.PasswdFile
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	shadowPath := opts.ShadowFile
	if shadowPath == "" {
		shadowPath = "/etc/shadow"
	}

	f, err := os.Open(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", passwdPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ":")
		if len(fields) < 7 || fields[0] != name {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("account %s has a non-numeric uid %q", name, fields[2])
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			return nil, fmt.Errorf("account %s has a non-numeric gid %q", name, fields[3])
		}

		acct := &SystemAccount{Name: name, UID: uid, GID: gid, Home: fields[5]}
		if hash := readShadowHashes(shadowPath)[name]; isUsableShadowHash(hash) {
			acct.PasswordHash = "{CRYPT}" + hash
		}
		return acct, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", passwdPath, err)
	}
	return nil, nil
}

// PasswordFromPlaintext is a convenience for the seed CLI when the operator
// wants to reset a user password during adoption.
func PasswordFromPlaintext(plain string) (string, error) {
	return auth.DovecotHash(plain)
}

// Ensure database/sql is imported (used by Apply's tx interface).
var _ = sql.ErrNoRows
