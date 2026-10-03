package doctor

import (
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func bptr(b bool) *bool { return &b }

func TestBlocklistCheckFromNoListings(t *testing.T) {
	c := blocklistCheckFrom([]models.BlocklistCheck{
		{IP: "1.2.3.4", List: "Spamhaus ZEN", Status: "clean"},
		{IP: "1.2.3.4", List: "SpamCop", Status: "error"},
	})
	if c.Status != OK {
		t.Errorf("status = %s, want ok", c.Status)
	}
}

func TestBlocklistCheckFromListed(t *testing.T) {
	c := blocklistCheckFrom([]models.BlocklistCheck{
		{IP: "1.2.3.4", List: "Spamhaus ZEN", Status: "clean"},
		{IP: "5.6.7.8", List: "SpamCop", Status: "listed"},
	})
	if c.Status != Warn {
		t.Errorf("status = %s, want warn", c.Status)
	}
	if !strings.Contains(c.Detail, "5.6.7.8") || !strings.Contains(c.Detail, "SpamCop") {
		t.Errorf("detail does not name the listing: %q", c.Detail)
	}
}

func TestPTRCheckFromOK(t *testing.T) {
	c := ptrCheckFrom([]models.OutboundIP{
		{IP: "1.2.3.4", Active: true, PTROK: bptr(true)},
	})
	if c.Status != OK {
		t.Errorf("status = %s, want ok", c.Status)
	}
}

func TestPTRCheckFromMissing(t *testing.T) {
	c := ptrCheckFrom([]models.OutboundIP{
		{IP: "1.2.3.4", Active: true, PTROK: bptr(true)},
		{IP: "5.6.7.8", Active: true, PTROK: bptr(false)},
		{IP: "9.9.9.9", Active: false, PTROK: bptr(false)}, // inactive: ignored
	})
	if c.Status != Warn {
		t.Errorf("status = %s, want warn", c.Status)
	}
	if !strings.Contains(c.Detail, "5.6.7.8") {
		t.Errorf("detail does not name the missing PTR: %q", c.Detail)
	}
	if strings.Contains(c.Detail, "9.9.9.9") {
		t.Errorf("inactive IP leaked into the detail: %q", c.Detail)
	}
}

func TestPTRCheckFromUnchecked(t *testing.T) {
	c := ptrCheckFrom([]models.OutboundIP{
		{IP: "1.2.3.4", Active: true, PTROK: nil},
	})
	if c.Status != Info {
		t.Errorf("status = %s, want info", c.Status)
	}
	if !strings.Contains(c.Detail, "1.2.3.4") {
		t.Errorf("detail does not name the unchecked IP: %q", c.Detail)
	}
}
