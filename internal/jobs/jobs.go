// Package jobs runs the panel's scheduled background work: the hourly DNSBL
// check, the nightly mailbox-quota sample, and the daily PTR + outbound-IP
// discovery. Each job is a method on Manager so it can be tested directly, while
// Start wires the three of them onto their schedules.
package jobs

import (
	"context"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/dns"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/store"
	"github.com/gtmylab/mailx-admin/internal/webhooks"
)

// DefaultBlocklistTimeout bounds a single DNSBL lookup. The miekg/dns client has
// no per-query deadline of its own, so the job imposes one per zone.
const DefaultBlocklistTimeout = 10 * time.Second

// Manager carries the dependencies the background jobs need.
type Manager struct {
	store    *store.Store
	resolver string
	logger   *slog.Logger
	webhooks *webhooks.Dispatcher // optional; nil disables dispatch
}

// New builds a Manager. An empty resolver falls back to the same public resolver
// the DNS checker uses, and a nil logger falls back to slog.Default.
func New(st *store.Store, resolver string, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if resolver == "" {
		resolver = "1.1.1.1:53"
	}
	return &Manager{store: st, resolver: resolver, logger: logger}
}

// SetWebhooks attaches an optional webhook dispatcher. When nil (the default),
// event dispatch is a no-op.
func (m *Manager) SetWebhooks(d *webhooks.Dispatcher) { m.webhooks = d }

func (m *Manager) dispatch(ctx context.Context, event string, data any) {
	if m.webhooks != nil {
		m.webhooks.Dispatch(ctx, event, data)
	}
}

// Start launches all three jobs on their schedules and returns immediately. It
// stops everything when ctx is cancelled.
func (m *Manager) Start(ctx context.Context) {
	// Blocklists: immediately, then hourly.
	go m.runLoop(ctx, "blocklist-check", 0, time.Hour, m.CheckBlocklists)
	// Quota: at 03:00 local, daily.
	go m.runLoop(ctx, "quota-sample", nextDelay(3, 0), 24*time.Hour, m.SampleQuotas)
	// PTR + discovery: at 04:00 local, daily.
	go m.runLoop(ctx, "ptr-check-and-ip-discovery", nextDelay(4, 0), 24*time.Hour, m.CheckPTRAndDiscover)
}

// CheckBlocklists queries every default DNSBL for every active outbound IP and
// records the result. A failed lookup is recorded as "error" rather than aborting
// the job, so a single unreachable list does not hide the others.
func (m *Manager) CheckBlocklists(ctx context.Context) error {
	ips, err := m.store.ListOutboundIPs(ctx)
	if err != nil {
		return err
	}

	for _, ip := range ips {
		if !ip.Active {
			continue
		}
		for _, bl := range dns.DefaultBlocklists {
			qctx, cancel := context.WithTimeout(ctx, DefaultBlocklistTimeout)
			listed, detail, err := dns.CheckBlocklist(qctx, m.resolver, bl.Zone, ip.IP)
			cancel()

			status := "clean"
			if err != nil {
				status = "error"
				detail = err.Error()
			} else if listed {
				status = "listed"
			}

			if err := m.store.InsertBlocklistCheck(ctx, bl.Name, bl.Zone, ip.IP, status, detail); err != nil {
				return err
			}
			if status == "listed" {
				m.dispatch(ctx, "blocklist.listed", map[string]any{
					"ip":     ip.IP,
					"list":   bl.Name,
					"zone":   bl.Zone,
					"detail": detail,
				})
			}
		}
	}
	return nil
}

// SampleQuotas records one quota observation per active mailbox. A mailbox whose
// maildir is missing or unreadable is skipped, not an error: the job must keep
// sampling every other mailbox.
func (m *Manager) SampleQuotas(ctx context.Context) error {
	users, err := m.store.Users(ctx, false)
	if err != nil {
		return err
	}

	for _, u := range users {
		bytesUsed, messages, err := maildirUsage(u.MaildirPath())
		if err != nil {
			m.logger.Debug("skip quota sample", "user", u.Email, "err", err)
			continue
		}
		if err := m.store.InsertQuotaSample(ctx, u.ID, bytesUsed, messages); err != nil {
			return err
		}
	}
	return nil
}

// CheckPTRAndDiscover refreshes the PTR status of every active outbound IP, then
// adds any local IPv4 address the registry does not know yet. Discovered IPs are
// inserted disabled and inactive so they are visible but never used for routing
// until the operator opts in.
func (m *Manager) CheckPTRAndDiscover(ctx context.Context) error {
	ips, err := m.store.ListOutboundIPs(ctx)
	if err != nil {
		return err
	}

	registered := map[string]bool{}
	for _, ip := range ips {
		registered[ip.IP] = true
		if !ip.Active {
			continue
		}

		qctx, cancel := context.WithTimeout(ctx, DefaultBlocklistTimeout)
		records, err := dns.LookupPTR(qctx, m.resolver, ip.IP)
		cancel()

		if err != nil || len(records) == 0 {
			// A failed lookup and a missing PTR are the same signal to the
			// operator: "there is no usable reverse record yet".
			_ = m.store.SetOutboundIPPTR(ctx, ip.ID, false, "")
			continue
		}
		if err := m.store.SetOutboundIPPTR(ctx, ip.ID, true, strings.Join(records, ", ")); err != nil {
			return err
		}
	}

	for _, ip := range dns.LocalIPv4s() {
		if registered[ip] {
			continue
		}
		if _, err := m.store.InsertOutboundIP(ctx, models.OutboundIP{
			IP:       ip,
			Mode:     models.IPModeDisabled,
			Priority: 0,
			Active:   false,
		}); err != nil {
			return err
		}
		m.dispatch(ctx, "outbound.ip_discovered", map[string]any{"ip": ip})
	}
	return nil
}

// runLoop runs fn after first, then every period, until ctx is cancelled.
func (m *Manager) runLoop(ctx context.Context, name string, first, period time.Duration, fn func(context.Context) error) {
	timer := time.NewTimer(first)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			start := time.Now()
			if err := fn(ctx); err != nil {
				m.logger.Warn("background job failed", "job", name, "err", err, "took", time.Since(start))
			} else {
				m.logger.Info("background job finished", "job", name, "took", time.Since(start))
			}
			timer.Reset(period)
		}
	}
}

// nextDelay returns the duration until the next occurrence of hour:minute in
// local time, rolling into tomorrow when that time has already passed today.
func nextDelay(hour, minute int) time.Duration {
	return nextDelayAt(time.Now(), hour, minute)
}

// nextDelayAt is nextDelay with an explicit "now", so the roll-over logic is
// testable without sleeping.
func nextDelayAt(now time.Time, hour, minute int) time.Duration {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next.Sub(now)
}

// maildirUsage sums the sizes of the delivered messages under a Maildir and
// counts them. Only cur/ and new/ hold delivered mail — tmp/ is in-flight — and
// dot-folders such as .Sent are Maildirs too, so the walk counts them the same
// way. The Maildir/ root itself is excluded, which is what a caller measuring
// usage wants.
func maildirUsage(root string) (bytes int64, messages int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		parent := filepath.Base(filepath.Dir(path))
		if parent != "cur" && parent != "new" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		messages++
		bytes += info.Size()
		return nil
	})
	return bytes, messages, err
}
