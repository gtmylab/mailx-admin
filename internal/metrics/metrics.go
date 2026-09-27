package metrics

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gtmylab/mailx-admin/internal/version"
)

type Collector struct {
	db       *sql.DB
	hostname string
	build    version.Info
	startAt  time.Time

	mu         sync.RWMutex
	svcStatus  map[string]bool
	lastUpdate time.Time
}

// New starts a collector. build is published through mailx_admin_info, which
// is how a running server reports the release it was built from (see
// internal/version for how the values are stamped in).
func New(db *sql.DB, hostname string, build version.Info) *Collector {
	c := &Collector{
		db:        db,
		hostname:  hostname,
		build:     build,
		startAt:   time.Now(),
		svcStatus: make(map[string]bool),
	}
	go c.refreshLoop()
	return c
}

func (c *Collector) refreshLoop() {
	c.refresh()
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		c.refresh()
	}
}

func (c *Collector) refresh() {
	services := []string{"postfix", "dovecot", "opendkim", "mysql", "apache2", "mailx-admin"}
	m := make(map[string]bool, len(services))
	for _, s := range services {
		m[s] = isActive(s)
	}
	c.mu.Lock()
	c.svcStatus = m
	c.lastUpdate = time.Now()
	c.mu.Unlock()
}

func isActive(svc string) bool {
	err := exec.Command("systemctl", "is-active", "--quiet", svc).Run()
	return err == nil
}

func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		c.write(w)
	})
}

func (c *Collector) write(w http.ResponseWriter) {
	// Process-level metrics. The build labels are injected by -ldflags, so on
	// a Linux deployment a real version/commit plus stamped="yes" is the proof
	// that a release binary is running here and not a bare "go build".
	b := c.build
	fmt.Fprintf(w, "# HELP mailx_admin_info Build info\n")
	fmt.Fprintf(w, "# TYPE mailx_admin_info gauge\n")
	fmt.Fprintf(w,
		"mailx_admin_info{version=%q,commit=%q,built=%q,go=%q,os=%q,arch=%q,stamped=%q,hostname=%q} 1\n",
		b.Version, b.Commit, b.Date, b.GoVersion, b.OS, b.Arch, yesNo(b.Stamped()), c.hostname)

	fmt.Fprintf(w, "# HELP mailx_admin_uptime_seconds Time since process start\n")
	fmt.Fprintf(w, "# TYPE mailx_admin_uptime_seconds gauge\n")
	fmt.Fprintf(w, "mailx_admin_uptime_seconds %.0f\n", time.Since(c.startAt).Seconds())

	// Service health
	c.mu.RLock()
	fmt.Fprintf(w, "# HELP mailx_service_up Whether the systemd service is active\n")
	fmt.Fprintf(w, "# TYPE mailx_service_up gauge\n")
	for svc, up := range c.svcStatus {
		val := 0
		if up {
			val = 1
		}
		fmt.Fprintf(w, "mailx_service_up{service=%q} %d\n", svc, val)
	}
	c.mu.RUnlock()

	// Domain / user counts
	if c.db != nil {
		var domainCount, userCount, aliasCount int
		_ = c.db.QueryRow(`SELECT COUNT(*) FROM domains WHERE active = 1`).Scan(&domainCount)
		_ = c.db.QueryRow(`SELECT COUNT(*) FROM users WHERE active = 1`).Scan(&userCount)
		_ = c.db.QueryRow(`SELECT COUNT(*) FROM aliases`).Scan(&aliasCount)

		fmt.Fprintf(w, "# HELP mailx_domains_total Active domains\n")
		fmt.Fprintf(w, "# TYPE mailx_domains_total gauge\n")
		fmt.Fprintf(w, "mailx_domains_total %d\n", domainCount)

		fmt.Fprintf(w, "# HELP mailx_users_total Active users\n")
		fmt.Fprintf(w, "# TYPE mailx_users_total gauge\n")
		fmt.Fprintf(w, "mailx_users_total %d\n", userCount)

		fmt.Fprintf(w, "# HELP mailx_aliases_total Aliases\n")
		fmt.Fprintf(w, "# TYPE mailx_aliases_total gauge\n")
		fmt.Fprintf(w, "mailx_aliases_total %d\n", aliasCount)

		// Mail events in the last 5 minutes
		var recentSent, recentDeferred, recentBounced, recentRejected int
		_ = c.db.QueryRow(`
            SELECT COUNT(*) FROM mail_events
            WHERE ts > datetime('now', '-5 minutes') AND status = 'sent'
        `).Scan(&recentSent)
		_ = c.db.QueryRow(`
            SELECT COUNT(*) FROM mail_events
            WHERE ts > datetime('now', '-5 minutes') AND status = 'deferred'
        `).Scan(&recentDeferred)
		_ = c.db.QueryRow(`
            SELECT COUNT(*) FROM mail_events
            WHERE ts > datetime('now', '-5 minutes') AND status = 'bounced'
        `).Scan(&recentBounced)
		_ = c.db.QueryRow(`
            SELECT COUNT(*) FROM mail_events
            WHERE ts > datetime('now', '-5 minutes') AND status = 'rejected'
        `).Scan(&recentRejected)

		fmt.Fprintf(w, "# HELP mailx_mail_events_5m Mail events in last 5 minutes by status\n")
		fmt.Fprintf(w, "# TYPE mailx_mail_events_5m gauge\n")
		fmt.Fprintf(w, "mailx_mail_events_5m{status=\"sent\"} %d\n", recentSent)
		fmt.Fprintf(w, "mailx_mail_events_5m{status=\"deferred\"} %d\n", recentDeferred)
		fmt.Fprintf(w, "mailx_mail_events_5m{status=\"bounced\"} %d\n", recentBounced)
		fmt.Fprintf(w, "mailx_mail_events_5m{status=\"rejected\"} %d\n", recentRejected)

		// Queue size
		queueSize, _ := queueCount()
		fmt.Fprintf(w, "# HELP mailx_queue_messages Messages in Postfix queue\n")
		fmt.Fprintf(w, "# TYPE mailx_queue_messages gauge\n")
		fmt.Fprintf(w, "mailx_queue_messages %d\n", queueSize)
	}

	// SSL cert expiry
	if c.db != nil {
		rows, err := c.db.Query(`
            SELECT domain_id, days_left FROM ssl_certs
        `)
		if err == nil {
			fmt.Fprintf(w, "# HELP mailx_ssl_days_left Days until SSL cert expires\n")
			fmt.Fprintf(w, "# TYPE mailx_ssl_days_left gauge\n")
			for rows.Next() {
				var did int64
				var days int
				if err := rows.Scan(&did, &days); err != nil {
					continue
				}
				fmt.Fprintf(w, "mailx_ssl_days_left{domain_id=%q} %d\n", did, days)
			}
			rows.Close()
		}
	}
}

// yesNo renders a boolean as a Prometheus label value.
func yesNo(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func queueCount() (int, error) {
	out, err := exec.Command("postqueue", "-p").Output()
	if err != nil {
		return 0, err
	}
	// Count lines that look like queue headers: hex ID followed by size
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ":") && len(line) > 20 && line[0] != ' ' {
			// heuristic: header lines start with queue ID
			if len(line) > 10 && isHex(line[:10]) {
				count++
			}
		}
	}
	return count, nil
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
