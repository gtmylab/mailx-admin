package models

import (
	"fmt"
	"time"
)

// Mailbox kinds. See internal/db/migrations/006_mailboxes.sql.
const (
	// KindVirtual is the panel's own model: the maildir lives under
	// VmailBase, owned by the vmail account, and Postfix delivers it through
	// virtual_mailbox_maps.
	KindVirtual = "virtual"

	// KindSystem is a mailbox on a real Unix account (`useradd`, the
	// installer's "Add MailX User"), with its mail in /home/<user>/Maildir.
	// The panel renders it into the same passwd-file, with the account's own
	// uid/gid/home, and Postfix reaches it through a virtual_alias.
	KindSystem = "system"
)

// VmailUID/VmailGID are the account virtual mailboxes are delivered as. vmail
// is created with these numbers by the installer and is the default in
// /etc/dovecot/conf.d/10-auth-mailx.conf.
const (
	VmailUID = 5000
	VmailGID = 5000

	// VmailBase is Postfix's virtual_mailbox_base.
	VmailBase = "/var/mail/vhosts"
)

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

	// Outbound rate limit for this domain, enforced by postfwd (see
	// internal/reconciler/postfwd.go). OutboundRateLimit is messages per hour
	// and 0 means "no limit" -- the default, and what every install that never
	// set one keeps doing.
	//
	// OutboundRateBurst is how many extra messages may go out in a 60s window
	// (0 = none), so a legitimate batch sender is not throttled by the hourly
	// average alone. OutboundRateAction is what postfwd answers once the limit
	// is reached: RateActionDefer (the sender retries later) or
	// RateActionReject.
	OutboundRateLimit  int
	OutboundRateBurst  int
	OutboundRateAction string
}

// What a domain's outgoing limit does when it is reached. Stored as text because
// it is shown in the panel and written into postfwd's config verbatim.
const (
	RateActionDefer  = "defer"  // 450 4.7.1: temporary, the sender retries
	RateActionReject = "reject" // 554 5.7.1: permanent
)

// RateLimited reports whether this domain has an outgoing rate limit at all.
func (d Domain) RateLimited() bool { return d.OutboundRateLimit > 0 }

// RateAction normalizes an unset action to the default, so a row written before
// the column existed (or by hand) still renders a valid postfwd rule.
func (d Domain) RateAction() string {
	switch d.OutboundRateAction {
	case RateActionDefer, RateActionReject:
		return d.OutboundRateAction
	}
	return RateActionDefer
}

type User struct {
	ID           int64
	DomainID     int64
	Username     string
	Email        string
	DisplayName  string // owner's display name; empty = derive from the local part
	PasswordHash string
	QuotaMB      int
	Active       bool
	IsAdmin      bool
	LastLogin    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time

	// Kind is KindVirtual or KindSystem. Empty is treated as KindVirtual, so
	// rows written before migration 006 keep working.
	Kind string

	// SysUID/SysGID/Home describe the Unix account a KindSystem mailbox
	// lives on. They are 0/"" for virtual mailboxes.
	SysUID int
	SysGID int
	Home   string

	// Populated by joins, not stored
	DomainName string
}

// MailboxKind normalizes an unset kind to KindVirtual.
func (u User) MailboxKind() string {
	if u.Kind == "" {
		return KindVirtual
	}
	return u.Kind
}

// IsSystem reports whether this mailbox belongs to a real Unix account.
func (u User) IsSystem() bool { return u.MailboxKind() == KindSystem }

// DeliveryUID is the ownership the maildir has to have: the vmail account for a
// virtual mailbox, the real account's uid for a system one. Rendering a system
// mailbox with uid 5000 would leave Dovecot unable to write into a directory
// owned by the user, and vice versa.
func (u User) DeliveryUID() int {
	if u.IsSystem() && u.SysUID > 0 {
		return u.SysUID
	}
	return VmailUID
}

// DeliveryGID mirrors DeliveryUID.
func (u User) DeliveryGID() int {
	if u.IsSystem() && u.SysGID > 0 {
		return u.SysGID
	}
	return VmailGID
}

// MailHome is the Dovecot `home` for this mailbox: the directory that contains
// Maildir/. For a virtual mailbox it is derived from the domain and username so
// it always matches virtual_mailbox_base in main.cf.
func (u User) MailHome() string {
	if u.IsSystem() && u.Home != "" {
		return u.Home
	}
	return fmt.Sprintf("%s/%s/%s", VmailBase, u.DomainName, u.Username)
}

// MaildirPath is the mailbox itself, which is what Postfix's vmailbox map and
// the reconciler's directory creation both need.
func (u User) MaildirPath() string { return u.MailHome() + "/Maildir" }

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

// RelayConfig is the outbound smarthost settings. Enabled=false means Postfix
// delivers directly (no relayhost). TLSMode is "", "starttls" (port 587) or
// "smtps" (port 465).
type RelayConfig struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	Password string
	TLSMode  string
}

// CronValueSet is a set of cron field values (selected minutes, hours, …) used by
// the cron form's list boxes. It is persisted as a comma-separated string.
type CronValueSet map[string]bool

// Has reports whether v is selected.
func (s CronValueSet) Has(v string) bool { return s[v] }

// CronJob is a user-defined scheduled job. Schedule is the authoritative 5-field
// cron expression derived from the simple/advanced picker; the command is run by
// the system cron daemon through `mailx-admin cron run <id>`, which records the
// result back to the panel.
type CronJob struct {
	ID          int64
	Name        string
	Schedule    string
	Command     string
	RunAs       string
	Input       string
	Description string
	Enabled     bool
	// UI scheduling fields (the final Schedule is derived from these).
	SimpleSchedule string
	ScheduleMode   string // "simple" | "advanced"
	Minutes        CronValueSet
	Hours          CronValueSet
	Days           CronValueSet
	Months         CronValueSet
	Weekdays       CronValueSet
	DateRangeMode  string // "any" | "range"
	StartMonth     string
	StartDate      string
	EndMonth       string
	EndDate        string
	LastRunAt      *time.Time
	LastStatus     string // "", "ok", "error", "running"
	LastOutput     string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Snapshot is what the reconciler consumes. Immutable, rendered from DB.
type Snapshot struct {
	Domains    []Domain
	Users      []User
	Aliases    []Alias
	Ports      []PortListener
	SieveRules map[int64][]SieveRule

	// OutboundIPs is the outbound address registry, used to route senders to
	// per-IP Postfix transports. Suppressions is the recipient suppression list.
	OutboundIPs  []OutboundIP
	Suppressions []Suppression

	// Relay is the outbound smarthost, nil or disabled when delivering directly.
	Relay *RelayConfig
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
