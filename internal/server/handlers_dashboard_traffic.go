package server

import (
	"context"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/gtmylab/mailx-admin/internal/store"
)

// trafficView is the dashboard's email-traffic analytics: headline totals for
// today/week/month plus the daily series the charts are drawn from.
type trafficView struct {
	SentToday     int64
	SentWeek      int64
	SentMonth     int64
	ReceivedToday int64
	ReceivedWeek  int64
	ReceivedMonth int64
	BouncedMonth  int64
	DeferredMonth int64

	TopDomains []store.DomainCount
	Chart      template.HTML // default (30-day) sent-volume bar chart

	vol []store.DayVolume // unexported; used to re-render other ranges
}

// buildTraffic loads 30 days of volume and the top outbound domains. It never
// fails the page: on error the dashboard renders an empty chart instead.
func (s *Server) buildTraffic(ctx context.Context) *trafficView {
	v := &trafficView{}
	since := time.Now().AddDate(0, 0, -29) // 30 days including today

	vol, err := s.store.MailVolumeByDay(ctx, since)
	if err != nil {
		s.logger.Warn("dashboard traffic", "err", err)
		v.Chart = renderBars(nil, 720, 160)
		return v
	}
	v.vol = vol

	for _, d := range vol {
		v.SentMonth += d.Sent
		v.ReceivedMonth += d.Received
		v.BouncedMonth += d.Bounced
		v.DeferredMonth += d.Deferred
	}

	if n := len(vol); n > 0 {
		v.SentToday = vol[n-1].Sent
		v.ReceivedToday = vol[n-1].Received
		start := n - 7
		if start < 0 {
			start = 0
		}
		for _, d := range vol[start:] {
			v.SentWeek += d.Sent
			v.ReceivedWeek += d.Received
		}
	}

	v.TopDomains, _ = s.store.TopOutboundDomains(ctx, since, 5)
	v.Chart = chartFor(vol, 30)
	return v
}

// handleDashboardTraffic re-renders the volume chart for a chosen range.
func (s *Server) handleDashboardTraffic(w http.ResponseWriter, r *http.Request) {
	days := 7
	if raw := r.URL.Query().Get("days"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && (n == 7 || n == 30) {
			days = n
		}
	}

	tv := s.buildTraffic(r.Context())
	s.renderPartial(w, "traffic_chart", map[string]any{
		"Chart": chartFor(tv.vol, days),
		"Days":  days,
	})
}

// chartFor renders a sent-volume bar chart over the last `days` entries.
func chartFor(vol []store.DayVolume, days int) template.HTML {
	if len(vol) == 0 {
		return renderBars(nil, 720, 160)
	}
	start := len(vol) - days
	if start < 0 {
		start = 0
	}
	pts := make([]chartPoint, 0, len(vol)-start)
	for _, d := range vol[start:] {
		pts = append(pts, chartPoint{Label: d.Day.Format("Jan 2"), Value: float64(d.Sent)})
	}
	return renderBars(pts, 720, 160)
}
