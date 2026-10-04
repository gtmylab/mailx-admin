package server

import (
	"testing"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func TestProjectQuotaHitAt(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	samples := []models.QuotaSample{
		{SampledAt: base, BytesUsed: 100},
		{SampledAt: base.Add(24 * time.Hour), BytesUsed: 200},
		{SampledAt: base.Add(48 * time.Hour), BytesUsed: 300},
	}
	// Growing at 100 bytes/day, quota is 400 bytes → hits in ~1 day from the
	// last sample (which is at 48h, value 300).
	hit, ok := projectQuotaHitAt(samples, 400)
	if !ok {
		t.Fatal("expected a projection, got false")
	}
	want := base.Add(72 * time.Hour)
	if diff := hit.Sub(want); diff < -time.Second || diff > time.Second {
		t.Errorf("hit = %v, want ~%v", hit, want)
	}
}

func TestProjectQuotaHitAtNotGrowing(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	samples := []models.QuotaSample{
		{SampledAt: base, BytesUsed: 300},
		{SampledAt: base.Add(24 * time.Hour), BytesUsed: 300},
	}
	if _, ok := projectQuotaHitAt(samples, 1024); ok {
		t.Error("flat usage should not produce a projection")
	}
}

func TestProjectQuotaHitAtTooFewSamples(t *testing.T) {
	if _, ok := projectQuotaHitAt([]models.QuotaSample{{SampledAt: time.Now(), BytesUsed: 1}}, 1024); ok {
		t.Error("a single sample should not produce a projection")
	}
}
