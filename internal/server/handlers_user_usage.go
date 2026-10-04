package server

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/gtmylab/mailx-admin/internal/maildir"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// handleUserUsage renders the mailbox-usage card on a user page. It is loaded
// over HTMX so the user page itself does not wait on a filesystem walk of a
// possibly large Maildir.
func (s *Server) handleUserUsage(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}

	u, err := s.loadUserForUsage(r.Context(), userID)
	if err != nil {
		s.renderPartial(w, "user_usage", map[string]any{"Error": err.Error()})
		return
	}

	s.renderPartial(w, "user_usage", s.buildUserUsage(r.Context(), u))
}

// loadUserForUsage reads just the columns MaildirPath needs (kind, uid/gid,
// home, domain), so a big users table is not scanned for one page.
func (s *Server) loadUserForUsage(ctx context.Context, id int64) (*models.User, error) {
	var u models.User
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.domain_id, u.username, u.email, u.quota_mb, u.active, u.is_admin, d.name,
		       u.kind, COALESCE(u.sys_uid, 0), COALESCE(u.sys_gid, 0), COALESCE(u.home, '')
		FROM users u JOIN domains d ON d.id = u.domain_id
		WHERE u.id = ?`, id).Scan(
		&u.ID, &u.DomainID, &u.Username, &u.Email, &u.QuotaMB, &u.Active, &u.IsAdmin, &u.DomainName,
		&u.Kind, &u.SysUID, &u.SysGID, &u.Home)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return &u, nil
}

// buildUserUsage assembles the data the usage card renders: current usage,
// per-folder breakdown, a growth sparkline and a projection to quota.
func (s *Server) buildUserUsage(ctx context.Context, u *models.User) map[string]any {
	path := u.MaildirPath()

	bytes, messages, err := maildir.Total(path)
	if err != nil {
		return map[string]any{"Error": "maildir not readable: " + err.Error()}
	}

	folders, _ := maildir.Folders(path)
	if len(folders) > 5 {
		folders = folders[:5]
	}

	quotaBytes := int64(u.QuotaMB) * 1024 * 1024
	percent := 0.0
	if quotaBytes > 0 {
		percent = float64(bytes) / float64(quotaBytes) * 100
	}

	samples, _ := s.store.QuotaSamples(ctx, u.ID, time.Now().AddDate(0, 0, -90))

	projection := "No trend yet"
	if hit, ok := projectQuotaHitAt(samples, quotaBytes); ok {
		days := int(time.Until(hit).Hours() / 24)
		if days < 1 {
			projection = "within a day"
		} else {
			projection = fmt.Sprintf("in ~%d days", days)
		}
	}

	return map[string]any{
		"BytesUsed":  bytes,
		"Messages":   messages,
		"QuotaMB":    u.QuotaMB,
		"Percent":    percent,
		"Folders":    folders,
		"Sparkline":  sparkFromSamples(samples),
		"Projection": projection,
	}
}

// sparkFromSamples turns quota samples into a growth sparkline (bytes over time).
func sparkFromSamples(samples []models.QuotaSample) template.HTML {
	pts := make([]chartPoint, 0, len(samples))
	for _, s := range samples {
		pts = append(pts, chartPoint{Label: s.SampledAt.Format("Jan 2"), Value: float64(s.BytesUsed)})
	}
	return renderSparkline(pts, 360, 120)
}

// projectQuotaHitAt fits a straight line to the samples and returns when the
// mailbox will reach quotaBytes at the current rate. It reports false when the
// mailbox is not growing or there is no trend to extrapolate.
func projectQuotaHitAt(samples []models.QuotaSample, quotaBytes int64) (time.Time, bool) {
	if len(samples) < 2 || quotaBytes <= 0 {
		return time.Time{}, false
	}

	var sumX, sumY, sumXX, sumXY float64
	n := float64(len(samples))
	t0 := samples[0].SampledAt.Unix()
	for _, s := range samples {
		x := float64(s.SampledAt.Unix() - t0)
		y := float64(s.BytesUsed)
		sumX += x
		sumY += y
		sumXX += x * x
		sumXY += x * y
	}

	denom := n*sumXX - sumX*sumX
	if denom == 0 {
		return time.Time{}, false
	}
	rate := (n*sumXY - sumX*sumY) / denom // bytes per second
	if rate <= 0 {
		return time.Time{}, false
	}

	last := samples[len(samples)-1]
	secs := (float64(quotaBytes) - float64(last.BytesUsed)) / rate
	if secs <= 0 {
		return time.Time{}, false
	}
	return last.SampledAt.Add(time.Duration(secs) * time.Second), true
}
