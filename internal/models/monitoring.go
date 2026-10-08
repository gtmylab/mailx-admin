package models

import "time"

// Outbound IP routing modes.
const (
	IPModeAlways   = "always"
	IPModeRules    = "rules"
	IPModeDisabled = "disabled"
)

// Outbound rule match types.
const (
	RuleMatchDomain = "domain"
	RuleMatchUser   = "user"
	RuleMatchEmail  = "email"
)

// OutboundIP is one of the server's outbound addresses and how it is used.
type OutboundIP struct {
	ID        int64
	IP        string
	Mode      string
	Priority  int
	Active    bool
	PTROK     *bool
	PTRRecord string
	Notes     string
	CreatedAt time.Time
	UpdatedAt time.Time

	// Rules is populated for mode="rules" mailboxes.
	Rules []OutboundRule
}

// OutboundRule maps a sender (domain, user or full address) to an outbound IP.
type OutboundRule struct {
	ID         int64
	IPID       int64
	MatchType  string
	MatchValue string
	Priority   int
}

// BlocklistCheck is one DNS blocklist lookup result.
type BlocklistCheck struct {
	ID        int64
	List      string
	Zone      string
	IP        string
	Status    string // "listed" | "clean" | "error"
	Detail    string
	CheckedAt time.Time
}

// Suppression is a rule that rejects a sender (direction "in") or refuses a
// recipient (direction "out"), matching an exact address or a whole domain.
type Suppression struct {
	ID        int64
	Email     string // the match value: an address, or a bare domain when MatchType == "domain"
	Direction string // "in" (reject inbound sender) | "out" (refuse outbound recipient)
	MatchType string // "email" | "domain"
	Reason    string
	Source    string
	Notes     string
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// QuotaSample is one nightly mailbox-usage observation.
type QuotaSample struct {
	ID        int64
	UserID    int64
	BytesUsed int64
	Messages  int
	SampledAt time.Time
}

// APIKey is a hashed API credential. The plaintext is never stored.
type APIKey struct {
	ID         int64
	Name       string
	Prefix     string
	KeyHash    string
	Scopes     string
	Active     bool
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
}

// Webhook is an outbound HTTP notification subscription.
type Webhook struct {
	ID        int64
	URL       string
	Events    []string
	Secret    string
	Active    bool
	CreatedAt time.Time
}

// WebhookDelivery records one delivery attempt.
type WebhookDelivery struct {
	ID          int64
	WebhookID   int64
	Event       string
	Payload     string
	Success     bool
	StatusCode  int
	Response    string
	AttemptedAt time.Time
}
