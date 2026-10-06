package logs

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Event is a parsed log line.
type Event struct {
	Ts             time.Time
	QueueID        string
	Service        string
	Action         string
	Status         string
	FromAddr       string
	ToAddr         string
	Domain         string
	ClientIP       string
	ClientHostname string
	Relay          string
	SizeBytes      int64
	DelaySec       float64
	DSN            string
	Message        string
	Raw            string
}

// Syslog line prefix (traditional): "Sep 24 12:34:56 host postfix/smtpd[1234]: ..."
var syslogPrefix = regexp.MustCompile(
	`^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+([^\[\s:]+)(?:\[(\d+)\])?:\s+(.*)$`,
)

// RFC3339 prefix (some modern setups): "2024-09-24T12:34:56.789+00:00 host postfix/smtpd[1234]: ..."
var rfc3339Prefix = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+\S+\s+([^\[\s:]+)(?:\[(\d+)\])?:\s+(.*)$`,
)

// Postfix patterns
var (
	pmConnect    = regexp.MustCompile(`^connect from (\S+)\[([^\]]+)\]$`)
	pmDisconnect = regexp.MustCompile(`^disconnect from (\S+)\[([^\]]+)\](?:\s+(.*))?$`)
	pmClient     = regexp.MustCompile(`^([0-9A-F]+): client=(\S+)\[([^\]]+)\]$`)
	pmQmgrInsert = regexp.MustCompile(`^([0-9A-F]+): from=<([^>]*)>, size=(\d+), nrcpt=(\d+)`)
	pmQmgrRemove = regexp.MustCompile(`^([0-9A-F]+): removed$`)
	pmSmtpRelay  = regexp.MustCompile(`^([0-9A-F]+): to=<([^>]+)>(?:, relay=(\S+?)(?:\[\d+\])?)?(?:, delay=([0-9.]+))?(?:, delays=([^,]*))?(?:, dsn=([^,]*))?(?:, status=(\S+)(?:\s+\((.*)\))?)?`)
	pmBounce     = regexp.MustCompile(`^([0-9A-F]+): sender non-delivery notification`)
	pmReject     = regexp.MustCompile(`^NOQUEUE: reject: RCPT from (\S+)\[([^\]]+)\]: \d+ [^:]+: (.*?); from=<([^>]*)> to=<([^>]*)>`)
	pmSASL       = regexp.MustCompile(`^([0-9A-F]+): (?:client=\S+\[[^\]]+\], )?sasl_method=\S+, sasl_username=(\S+)`)
	pmDovecot    = regexp.MustCompile(`^(?:imap|pop3)-login: Login: user=<([^>]+)>, method=(\S+), rip=([\d.]+), lip=([\d.]+)`)
)

// ParseLine converts a raw log line into an Event.
// Returns nil if the line is not recognized (e.g. from another service).
func ParseLine(line string, now time.Time) *Event {
	ts, service, body := splitPrefix(line, now)
	if service == "" {
		return nil
	}
	ev := ParseEvent(service, body, ts)
	if ev != nil {
		ev.Raw = line
	}
	return ev
}

// ParseEvent dispatches an already-separated (service, body, ts) triple into an
// Event. The file ingester reaches it through ParseLine after splitting the
// syslog prefix; the journald source calls it directly with the fields journald
// has already separated for us.
func ParseEvent(service, body string, ts time.Time) *Event {
	if service == "" {
		return nil
	}
	ev := &Event{
		Ts:      ts,
		Service: service,
		Raw:     body,
		Message: body,
	}

	switch {
	case strings.HasPrefix(service, "postfix/"):
		parsePostfix(ev)
	case strings.HasPrefix(service, "dovecot"):
		parseDovecot(ev)
	default:
		// Unknown service — keep the raw line only
		ev.Action = "log"
	}
	return ev
}

func splitPrefix(line string, now time.Time) (time.Time, string, string) {
	if m := rfc3339Prefix.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(time.RFC3339Nano, m[1])
		if err == nil {
			return t, m[2], m[4]
		}
	}
	if m := syslogPrefix.FindStringSubmatch(line); m != nil {
		// m[1]=Mon, m[2]=Day, m[3]=HH, m[4]=MM, m[5]=SS, m[6]=service, m[7]=pid, m[8]=body
		month := parseMonth(m[1])
		day, _ := strconv.Atoi(m[2])
		hh, _ := strconv.Atoi(m[3])
		mm, _ := strconv.Atoi(m[4])
		ss, _ := strconv.Atoi(m[5])
		year := now.Year()
		// Handle Dec -> Jan rollover
		if month == time.January && now.Month() == time.December {
			year++
		} else if month == time.December && now.Month() == time.January {
			year--
		}
		t := time.Date(year, month, day, hh, mm, ss, 0, time.Local)
		return t, m[6], m[8]
	}
	return time.Time{}, "", ""
}

func parseMonth(s string) time.Month {
	switch s {
	case "Jan":
		return time.January
	case "Feb":
		return time.February
	case "Mar":
		return time.March
	case "Apr":
		return time.April
	case "May":
		return time.May
	case "Jun":
		return time.June
	case "Jul":
		return time.July
	case "Aug":
		return time.August
	case "Sep":
		return time.September
	case "Oct":
		return time.October
	case "Nov":
		return time.November
	case "Dec":
		return time.December
	}
	return time.January
}

func parsePostfix(ev *Event) {
	body := ev.Message

	if m := pmConnect.FindStringSubmatch(body); m != nil {
		ev.Action = "connect"
		ev.ClientHostname = m[1]
		ev.ClientIP = m[2]
		ev.Status = "ok"
		return
	}
	if m := pmDisconnect.FindStringSubmatch(body); m != nil {
		ev.Action = "disconnect"
		ev.ClientHostname = m[1]
		ev.ClientIP = m[2]
		if len(m) > 3 && m[3] != "" {
			ev.Message = m[3]
		}
		ev.Status = "ok"
		return
	}
	if m := pmClient.FindStringSubmatch(body); m != nil {
		ev.QueueID = m[1]
		ev.ClientHostname = m[2]
		ev.ClientIP = m[3]
		ev.Action = "client"
		return
	}
	if m := pmQmgrInsert.FindStringSubmatch(body); m != nil {
		ev.QueueID = m[1]
		ev.FromAddr = m[2]
		ev.SizeBytes, _ = strconv.ParseInt(m[3], 10, 64)
		ev.Action = "queue"
		ev.Status = "queued"
		return
	}
	if m := pmQmgrRemove.FindStringSubmatch(body); m != nil {
		ev.QueueID = m[1]
		ev.Action = "removed"
		return
	}
	if m := pmSmtpRelay.FindStringSubmatch(body); m != nil {
		ev.QueueID = m[1]
		ev.ToAddr = m[2]
		ev.Relay = m[3]
		if m[4] != "" {
			ev.DelaySec, _ = strconv.ParseFloat(m[4], 64)
		}
		if m[6] != "" {
			ev.DSN = m[6]
		}
		if m[7] != "" {
			ev.Status = m[7]
		}
		ev.Action = "delivery"
		if len(m) > 8 && m[8] != "" {
			ev.Message = m[8]
		}
		_, domain, _ := strings.Cut(ev.ToAddr, "@")
		ev.Domain = domain
		return
	}
	if m := pmReject.FindStringSubmatch(body); m != nil {
		ev.ClientHostname = m[1]
		ev.ClientIP = m[2]
		ev.FromAddr = m[4]
		ev.ToAddr = m[5]
		ev.Status = "rejected"
		ev.Action = "reject"
		_, domain, _ := strings.Cut(ev.ToAddr, "@")
		ev.Domain = domain
		ev.Message = m[3]
		return
	}
	if m := pmSASL.FindStringSubmatch(body); m != nil {
		ev.QueueID = m[1]
		ev.FromAddr = m[2]
		ev.Action = "auth"
		ev.Status = "ok"
		return
	}
	if pmBounce.MatchString(body) {
		ev.Action = "bounce"
		ev.Status = "bounced"
		return
	}

	// Unmatched postfix line — keep it but don't set action
	ev.Action = "log"
}

func parseDovecot(ev *Event) {
	if m := pmDovecot.FindStringSubmatch(ev.Message); m != nil {
		ev.FromAddr = m[1]
		ev.ClientIP = m[3]
		ev.Action = "login"
		ev.Status = "ok"
		_, domain, _ := strings.Cut(ev.FromAddr, "@")
		ev.Domain = domain
		ev.Message = "Login: " + m[1]
		return
	}
	ev.Action = "log"
}
