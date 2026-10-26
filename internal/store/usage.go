package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// DomainSendUsage is how many outbound messages a domain produced in each of the
// windows its caps are counted over, plus where the widest window starts.
//
// These are the numbers behind the "Sending" card on the domain page. They exist
// because enforcement itself is invisible: postfwd keeps its counters in memory
// and exposes no API to ask, so the only honest answer is what the log ingester
// recorded. The wording in the UI says "rolling" and "from the mail log",
// because these counts can lag the ingester's interval and can never reach
// further back than the log the panel has seen.
type DomainSendUsage struct {
	// Since is the start of the widest window (30 days before the query).
	Since     time.Time
	LastHour  int
	LastDay   int
	LastMonth int
}

// DomainSendUsage counts a domain's outbound messages over the last hour, day
// and 30 days.
//
// One row per message, not per recipient: postfwd counts a message once at
// end-of-data, while mail_events records one delivery per recipient. Grouping by
// queue id and taking MIN(ts) gives one timestamp per message, which is the
// closest thing the log has to postfwd's count.
//
// The sender is matched by the domain part of from_addr rather than by the
// recipient domain in `domain`, because this is about mail *from* the domain:
// inbound mail addressed to it is exactly what the caps must not count.
//
// LOWER(...) LIKE is used instead of a dialect-specific string function so the
// same query runs on SQLite and Postgres. It cannot use an index, but the ts
// range narrows the scan first.
func (s *Store) DomainSendUsage(ctx context.Context, domain string, now time.Time) (DomainSendUsage, error) {
	usage := DomainSendUsage{Since: now.Add(-30 * 24 * time.Hour)}
	pattern := "%@" + strings.ToLower(strings.TrimSpace(domain))

	const q = `
		SELECT
		  COALESCE(SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END), 0),
		  COALESCE(SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END), 0),
		  COUNT(*)
		FROM (
		  SELECT MIN(ts) AS ts
		  FROM mail_events
		  WHERE action = 'delivery'
		    AND COALESCE(queue_id, '') <> ''
		    AND ts >= ?
		    AND LOWER(from_addr) LIKE ?
		  GROUP BY queue_id
		) sent`

	if err := s.db.QueryRowContext(ctx, q,
		now.Add(-time.Hour),
		now.Add(-24*time.Hour),
		usage.Since,
		pattern,
	).Scan(&usage.LastHour, &usage.LastDay, &usage.LastMonth); err != nil {
		return DomainSendUsage{}, fmt.Errorf("domain send usage: %w", err)
	}
	return usage, nil
}
