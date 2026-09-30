package seed

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/store"
)

// ImportItem is one entry a plan would import.
type ImportItem struct {
	Key    string `json:"key"`    // domain name, email address, or source@domain
	Detail string `json:"detail"` // what the entry carries, for the preview
}

// ImportPlan is what "Import from server" would do.
type ImportPlan struct {
	Domains []ImportItem `json:"domains"`
	Users   []ImportItem `json:"users"`
	Aliases []ImportItem `json:"aliases"`

	// Skipped lists entries the plan refuses to import, with the reason. Today
	// that means a mailbox with no password hash: importing it would create an
	// account nobody can ever log into.
	Skipped []ImportItem `json:"skipped"`
}

// Total counts everything the plan would write.
func (p *ImportPlan) Total() int {
	if p == nil {
		return 0
	}
	return len(p.Domains) + len(p.Users) + len(p.Aliases)
}

// Empty reports whether there is nothing to import.
func (p *ImportPlan) Empty() bool { return p.Total() == 0 }

// Plan reports what Adopt would import, without writing anything. The panel
// shows it in the preview dialog before the admin confirms.
func Plan(ctx context.Context, st *store.Store, f *Found) (*ImportPlan, error) {
	return adopt(ctx, st, f, true)
}

// Adopt imports everything that exists on the server but not in the database:
// the mailboxes, domains and aliases the panel has never seen, which is exactly
// the state a shell-managed install is in when the panel is first pointed at it.
//

// adopt is the shared implementation. dryRun stops after the comparison.
//
// Everything happens in one transaction: the existence check and the inserts
// have to agree, or two concurrent imports would both decide the same mailbox is
// missing. No other database call may happen while that transaction is open
// (SQLite has a single-connection pool); the caller audits afterwards.
func adopt(ctx context.Context, st *store.Store, f *Found, dryRun bool) (*ImportPlan, error) {
	tx, err := st.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin import tx: %w", err)
	}
	defer tx.Rollback()

	existingDomains, existingEmails, existingAliases, err := st.ExistingKeysTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	plan := computePlan(f, existingDomains, existingEmails, existingAliases)
	if dryRun {
		return plan, nil
	}

	// Domains first: users and aliases reference them.
	domainIDs := map[string]int64{}
	for _, item := range plan.Domains {
		src := findDomain(f, item.Key)
		if src == nil {
			continue
		}
		id, err := st.InsertDomainTx(ctx, tx, store.DomainInsert{
			Name:               src.Name,
			IsPrimary:          src.IsPrimary,
			DKIMSelector:       "default",
			DKIMPrivateKeyPath: src.DKIMPrivateKey,
			DKIMPublicRecord:   src.DKIMPublicRecord,
		})
		if err != nil {
			return nil, fmt.Errorf("import domain %s: %w", src.Name, err)
		}
		domainIDs[src.Name] = id
	}

	for _, item := range plan.Users {
		src := findUser(f, item.Key)
		if src == nil {
			continue
		}
		domainID, err := importDomainID(ctx, tx, st, src.Domain, domainIDs)
		if err != nil {
			return nil, err
		}
		if _, err := st.InsertUserTx(ctx, tx, store.UserInsert{
			DomainID:     domainID,
			Username:     src.LocalPart,
			Email:        strings.ToLower(src.Email),
			PasswordHash: src.PasswordHash, // already in Dovecot format
			QuotaMB:      src.QuotaMB,
			Active:       true,
			// A mailbox on a real Unix account keeps that account: the
			// renderer needs its uid, gid and home to write a passwd-file
			// line Dovecot can actually deliver into.
			Kind:   src.Kind,
			SysUID: src.SysUID,
			SysGID: src.SysGID,
			Home:   src.Home,
		}); err != nil {
			return nil, fmt.Errorf("import user %s: %w", src.Email, err)
		}
	}

	for _, item := range plan.Aliases {
		src := findAlias(f, item.Key)
		if src == nil {
			continue
		}
		domainID, err := importDomainID(ctx, tx, st, src.Domain, domainIDs)
		if err != nil {
			return nil, err
		}
		if err := st.InsertAliasTx(ctx, tx, store.AliasInsert{
			DomainID:    domainID,
			Source:      src.Source,
			Destination: src.Destination,
		}); err != nil {
			return nil, fmt.Errorf("import alias %s@%s: %w", src.Source, src.Domain, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit import: %w", err)
	}
	return plan, nil
}

// importDomainID resolves the domain a user or alias belongs to, inserting it
// when the plan did not (a domain that is in the database but was not part of
// the scan still needs its id).
func importDomainID(ctx context.Context, tx *sql.Tx, st *store.Store, name string, known map[string]int64) (int64, error) {
	if id, ok := known[name]; ok {
		return id, nil
	}
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT id FROM domains WHERE name = ?`, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("look up domain %s: %w", name, err)
	}
	id, err = st.InsertDomainTx(ctx, tx, store.DomainInsert{Name: name, DKIMSelector: "default"})
	if err != nil {
		return 0, fmt.Errorf("import domain %s: %w", name, err)
	}
	known[name] = id
	return id, nil
}

// It is idempotent — anything already present (by name, address or
// source@domain) is skipped — so pressing the button twice is harmless, and so
// is running it again after every `useradd`.
func Adopt(ctx context.Context, st *store.Store, f *Found) (*ImportPlan, error) {
	return adopt(ctx, st, f, false)
}

// computePlan is the whole decision, kept free of the database so it can be
// tested directly: what is on the server that the panel does not have?
func computePlan(f *Found, existingDomains, existingEmails, existingAliases map[string]bool) *ImportPlan {
	plan := &ImportPlan{}

	known := map[string]bool{}
	for name := range existingDomains {
		known[name] = true
	}

	for _, d := range f.Domains {
		if known[d.Name] {
			continue
		}
		known[d.Name] = true
		detail := "imported from the server's Postfix configuration"
		if d.IsPrimary {
			detail += " (primary domain)"
		}
		if d.DKIMPrivateKey != "" {
			detail += ", DKIM key found"
		}
		plan.Domains = append(plan.Domains, ImportItem{Key: d.Name, Detail: detail})
	}

	for _, u := range f.Users {
		email := strings.ToLower(u.Email)
		if existingEmails[email] {
			continue
		}
		if strings.TrimSpace(u.PasswordHash) == "" {
			detail := "no password hash found on the server; create the mailbox in the panel instead"
			if u.Kind == models.KindSystem {
				detail = "the account exists but its password could not be read from /etc/shadow (run as root); create the mailbox in the panel to set one"
			}
			plan.Skipped = append(plan.Skipped, ImportItem{
				Key:    email,
				Detail: detail,
			})
			continue
		}
		detail := fmt.Sprintf("%s, quota %d MB", u.Domain, u.QuotaMB)
		if u.Kind == models.KindSystem {
			// Say which account it belongs to: this is the line the operator
			// uses to recognise the mailbox they created with useradd.
			detail = fmt.Sprintf("system mailbox on uid %d, %s, quota %d MB", u.SysUID, u.Home, u.QuotaMB)
		}
		if !known[u.Domain] {
			detail += ", creates the domain"
		}
		plan.Users = append(plan.Users, ImportItem{Key: email, Detail: detail})
	}

	for _, a := range f.Aliases {
		key := strings.ToLower(a.Source) + "@" + a.Domain
		if existingAliases[key] {
			continue
		}
		if !known[a.Domain] {
			plan.Skipped = append(plan.Skipped, ImportItem{
				Key:    key,
				Detail: "domain is not part of this server's configuration",
			})
			continue
		}
		plan.Aliases = append(plan.Aliases, ImportItem{Key: key, Detail: "-> " + a.Destination})
	}

	return plan
}

func findDomain(f *Found, name string) *FoundDomain {
	for i := range f.Domains {
		if f.Domains[i].Name == name {
			return &f.Domains[i]
		}
	}
	return nil
}

func findUser(f *Found, email string) *FoundUser {
	for i := range f.Users {
		if strings.EqualFold(f.Users[i].Email, email) {
			return &f.Users[i]
		}
	}
	return nil
}

func findAlias(f *Found, key string) *FoundAlias {
	for i := range f.Aliases {
		if strings.ToLower(f.Aliases[i].Source)+"@"+f.Aliases[i].Domain == key {
			return &f.Aliases[i]
		}
	}
	return nil
}
