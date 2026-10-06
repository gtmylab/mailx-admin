package server

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/gtmylab/mailx-admin/internal/system"
)

// systemView is the dashboard's system-information payload: the latest host
// snapshot, the sparkline history, and the pre-rendered gauges.
type systemView struct {
	Info    system.Info
	History []system.Sample
	Uptime  string
	LoadAvg string

	PackageUpdates int

	CPUgauge  template.HTML
	MemGauge  template.HTML
	DiskGauge template.HTML

	CPUSpark  template.HTML
	MemSpark  template.HTML
	LoadSpark template.HTML
}

func (s *Server) buildSystem() systemView {
	v := systemView{History: []system.Sample{}}
	if s.system == nil {
		return v
	}

	info := s.system.Latest()
	history := s.system.History()
	v.Info = info
	v.History = history
	v.Uptime = formatUptime(info.UptimeSec)
	v.LoadAvg = fmt.Sprintf("%.2f (1 min) %.2f (5 mins) %.2f (15 mins)", info.Load1, info.Load5, info.Load15)
	if s.packages != nil {
		v.PackageUpdates = s.packages.upgradableCount()
	}

	v.CPUgauge = renderGauge(info.CPUUsedPct, "CPU")
	v.MemGauge = renderGauge(info.MemUsedPct, "Memory")
	v.DiskGauge = renderGauge(info.DiskUsedPct, "Disk")

	v.CPUSpark = sparkOf(history, func(s system.Sample) float64 { return s.CPU })
	v.MemSpark = sparkOf(history, func(s system.Sample) float64 { return s.MemUsedPct })
	v.LoadSpark = sparkOf(history, func(s system.Sample) float64 { return s.Load1 })
	return v
}

func sparkOf(history []system.Sample, pick func(system.Sample) float64) template.HTML {
	pts := make([]chartPoint, 0, len(history))
	for _, s := range history {
		pts = append(pts, chartPoint{Value: pick(s)})
	}
	return renderSparkline(pts, 240, 48)
}

// formatUptime renders uptime seconds in a compact human form.
func formatUptime(sec float64) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours, %d minutes", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%d days, %d hours", int(d.Hours()/24), int(d.Hours())%24)
	}
}

// handleDashboardSystem re-renders the system-information card, polled by the
// dashboard so the gauges and sparklines update without a full reload.
func (s *Server) handleDashboardSystem(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "system_info", s.buildSystem())
}
