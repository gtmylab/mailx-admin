package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/execx"
)

// timeView is what the Server page's "Time & date" card renders.
type timeView struct {
	Now       string
	Date      string
	Time      string
	Timezone  string
	NTPSync   bool
	NTPActive bool
}

// commonTimezones seeds the timezone datalist. The field also accepts any IANA
// zone name, so the list is a convenience, not a limit.
var commonTimezones = []string{
	"UTC", "Africa/Lagos", "Africa/Nairobi", "Africa/Johannesburg",
	"America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
	"America/Mexico_City", "America/Sao_Paulo", "America/Argentina/Buenos_Aires",
	"Asia/Dubai", "Asia/Kolkata", "Asia/Jakarta", "Asia/Shanghai", "Asia/Hong_Kong",
	"Asia/Tokyo", "Asia/Seoul", "Asia/Singapore", "Australia/Sydney",
	"Europe/London", "Europe/Dublin", "Europe/Paris", "Europe/Berlin", "Europe/Madrid",
	"Europe/Rome", "Europe/Amsterdam", "Europe/Stockholm", "Europe/Warsaw", "Europe/Moscow",
	"Pacific/Auckland",
}

// timeStatusView reads the host's clock and NTP state via timedatectl. On a
// host without timedatectl (or a non-Linux dev build) it falls back to the
// process clock and UTC rather than failing the page.
func timeStatusView(ctx context.Context) timeView {
	v := timeView{Timezone: "UTC"}
	out, err := execx.Output(ctx, systemCmdTimeout, "timedatectl", "show")
	var epochUs int64
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			k, val, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch k {
			case "Timezone":
				v.Timezone = val
			case "NTPSynchronized":
				v.NTPSync = val == "yes"
			case "NTP":
				v.NTPActive = val == "yes" || val == "active"
			case "TimeUSec":
				epochUs, _ = strconv.ParseInt(val, 10, 64)
			}
		}
	}

	now := time.Now()
	if epochUs > 0 {
		now = time.Unix(epochUs/1_000_000, (epochUs%1_000_000)*1_000)
	}
	if loc, err := time.LoadLocation(v.Timezone); err == nil {
		now = now.In(loc)
	}
	v.Now = now.Format("2006-01-02 15:04:05 MST")
	v.Date = now.Format("2006-01-02")
	v.Time = now.Format("15:04:05")
	return v
}

// handleServerTimeSave applies timezone, date/time and NTP changes from the
// Server page's time card. Each field is optional; date and time are applied
// together, and setting the clock disables NTP first (timedatectl refuses to set
// the time while NTP is on).
func (s *Server) handleServerTimeSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), systemCmdTimeout)
	defer cancel()

	timezone := strings.TrimSpace(r.FormValue("timezone"))
	date := strings.TrimSpace(r.FormValue("date"))
	clock := strings.TrimSpace(r.FormValue("time"))
	ntp := r.FormValue("ntp") // "on" | "off" | "" (unchanged)

	if timezone != "" {
		if _, err := time.LoadLocation(timezone); err != nil {
			s.renderFormError(w, "Unknown timezone: "+timezone)
			return
		}
		if out, err := execx.Output(ctx, systemCmdTimeout, "timedatectl", "set-timezone", timezone); err != nil {
			s.renderFormError(w, "timedatectl set-timezone failed: "+strings.TrimSpace(string(out)))
			return
		}
	}

	if date != "" || clock != "" {
		if date == "" || clock == "" {
			s.renderFormError(w, "Set both date (YYYY-MM-DD) and time (HH:MM:SS), or leave both empty")
			return
		}
		if _, err := time.Parse("2006-01-02", date); err != nil {
			s.renderFormError(w, "Date must be YYYY-MM-DD")
			return
		}
		if _, err := time.Parse("15:04:05", clock); err != nil {
			s.renderFormError(w, "Time must be HH:MM:SS")
			return
		}
		if _, err := execx.Output(ctx, systemCmdTimeout, "timedatectl", "set-ntp", "false"); err != nil {
			s.renderFormError(w, "Could not disable NTP: "+err.Error())
			return
		}
		if out, err := execx.Output(ctx, systemCmdTimeout, "timedatectl", "set-time", date+" "+clock); err != nil {
			s.renderFormError(w, "timedatectl set-time failed: "+strings.TrimSpace(string(out)))
			return
		}
	}

	switch ntp {
	case "on":
		if out, err := execx.Output(ctx, systemCmdTimeout, "timedatectl", "set-ntp", "true"); err != nil {
			s.renderFormError(w, "timedatectl set-ntp true failed: "+strings.TrimSpace(string(out)))
			return
		}
	case "off":
		if out, err := execx.Output(ctx, systemCmdTimeout, "timedatectl", "set-ntp", "false"); err != nil {
			s.renderFormError(w, "timedatectl set-ntp false failed: "+strings.TrimSpace(string(out)))
			return
		}
	}

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: s.actorName(r), Action: "system.time", TargetType: "system", TargetID: "clock",
		Result: "ok", Detail: map[string]any{"timezone": timezone, "date": date, "time": clock, "ntp": ntp},
		RemoteIP: clientIP(r),
	})

	s.renderPartial(w, "time_result", map[string]any{"View": timeStatusView(r.Context())})
}

// handleServerTimeSync forces an immediate NTP step.
func (s *Server) handleServerTimeSync(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), systemCmdTimeout)
	defer cancel()

	// Enable NTP, then force a step. chrony and systemd-timesyncd are the two
	// daemons the installer supports; try chrony first, then restart timesyncd.
	_, _ = execx.Output(ctx, systemCmdTimeout, "timedatectl", "set-ntp", "true")
	if _, err := execx.Output(ctx, systemCmdTimeout, "chronyc", "makestep"); err != nil {
		_ = execx.Run(ctx, systemCmdTimeout, "systemctl", "restart", "systemd-timesyncd")
	}

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: s.actorName(r), Action: "system.time", TargetType: "system", TargetID: "clock",
		Result: "ok", Detail: map[string]any{"action": "sync"}, RemoteIP: clientIP(r),
	})

	s.renderPartial(w, "time_result", map[string]any{"View": timeStatusView(r.Context())})
}
