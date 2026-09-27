package models

import "time"

type Domain struct {
	ID                 int64
	Name               string
	IsPrimary          bool
	DKIMSelector       string
	DKIMPrivateKeyPath string
	DKIMPublicRecord   string
	DKIMCreatedAt      *time.Time
	Active             bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type User struct {
	ID           int64
	DomainID     int64
	Username     string
	Email        string
	PasswordHash string
	QuotaMB      int
	Active       bool
	IsAdmin      bool
	LastLogin    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time

	// Populated by joins, not stored
	DomainName string
}

// internal/models/models.go

type PortListener struct {
	ID          int64
	Port        int
	Service     string
	TLSMode     string
	RequireSASL bool
	Description string
	Enabled     bool
	CreatedAt   time.Time
}

// internal/models/models.go
type SieveRule struct {
	ID        int64
	UserID    int64
	RuleType  string // vacation, forward, move_folder, discard, mark_read
	Enabled   bool
	Position  int
	Config    []byte // JSON
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Alias struct {
	ID          int64
	DomainID    int64
	Source      string
	Destination string
	CreatedAt   time.Time
	DomainName  string // populated by joins
}

type Policy struct {
	ID        int64
	UserID    int64
	Key       string
	Value     string
	CreatedAt time.Time
}

// Snapshot is what the reconciler consumes. Immutable, rendered from DB.
type Snapshot struct {
	Domains    []Domain
	Users      []User
	Aliases    []Alias
	Ports      []PortListener
	SieveRules map[int64][]SieveRule
}

// PrimaryDomain returns the primary domain, or the first one if none is marked.
func (s *Snapshot) PrimaryDomain() *Domain {
	for i := range s.Domains {
		if s.Domains[i].IsPrimary {
			return &s.Domains[i]
		}
	}
	if len(s.Domains) > 0 {
		return &s.Domains[0]
	}
	return nil
}
