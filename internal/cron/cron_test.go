package cron

import (
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func TestRenderFileOnlyEnabled(t *testing.T) {
	jobs := []models.CronJob{
		{ID: 1, Name: "a", Schedule: "*/15 * * * *", Command: "echo hi", Enabled: true},
		{ID: 2, Name: "b", Schedule: "0 0 * * *", Command: "echo off", Enabled: false},
	}
	out := RenderFile(jobs, "/usr/local/bin/mailx-admin", "/etc/mailx/admin.toml")

	if !strings.Contains(out, "*/15 * * * * root /usr/local/bin/mailx-admin cron run --config /etc/mailx/admin.toml 1") {
		t.Fatalf("enabled job missing from render:\n%s", out)
	}
	if strings.Contains(out, "cron run --config /etc/mailx/admin.toml 2") {
		t.Fatalf("disabled job should not be rendered:\n%s", out)
	}
}

func TestValidate(t *testing.T) {
	for _, ok := range []string{"* * * * *", "*/15 * * * *", "30 2 * * *", "0 0,12 * * 1-5", "0 0 * * 0-6/2"} {
		if err := Validate(ok); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "* * * *", "* * * * * *", "a b c d e", "1 2 3 4 @#$"} {
		if err := Validate(bad); err == nil {
			t.Errorf("Validate(%q) = nil, want error", bad)
		}
	}
}
