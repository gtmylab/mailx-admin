package seed

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/store"
)

type Options struct {
	PostfixConfDir    string
	DovecotConfDir    string
	OpenDKIMDir       string
	PrimaryDomainFile string
	DryRun            bool
}

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
			})
		}
		f.Close()
	}
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

func parseQuotaRule(extra string) int {
	// Look for userdb_quota_rule=*:storage=2048M
	idx := strings.Index(extra, "storage=")
	if idx < 0 {
		return 0
	}
	rest := extra[idx+len("storage="):]
	end := strings.IndexAny(rest, "MKB, \t")
	if end < 0 {
		end = len(rest)
	}
	var mb int
	fmt.Sscanf(rest[:end], "%d", &mb)
	return mb
}

func parseQuotaFromHome(home string) int {
	// Fallback: read /home/<user>/.dovecot.quota if it exists
	// Not implemented in seed — the passwd-file format is authoritative.
	_ = home
	return 0
}

// PasswordFromPlaintext is a convenience for the seed CLI when the operator
// wants to reset a user password during adoption.
func PasswordFromPlaintext(plain string) (string, error) {
	return auth.DovecotHash(plain)
}

// Ensure database/sql is imported (used by Apply's tx interface).
var _ = sql.ErrNoRows
