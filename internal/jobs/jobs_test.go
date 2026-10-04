package jobs

import (
	"testing"
	"time"
)

func TestNextDelayAt(t *testing.T) {
	loc := time.UTC

	cases := []struct {
		name      string
		now       time.Time
		hour, min int
		want      time.Duration
	}{
		{"future today", time.Date(2026, 1, 1, 1, 0, 0, 0, loc), 3, 0, 2 * time.Hour},
		{"already passed", time.Date(2026, 1, 1, 5, 0, 0, 0, loc), 3, 0, 22 * time.Hour},
		{"exactly now rolls to tomorrow", time.Date(2026, 1, 1, 3, 0, 0, 0, loc), 3, 0, 24 * time.Hour},
		{"midnight boundary", time.Date(2026, 1, 1, 23, 30, 0, 0, loc), 0, 0, 30 * time.Minute},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextDelayAt(tc.now, tc.hour, tc.min); got != tc.want {
				t.Errorf("nextDelayAt = %v, want %v", got, tc.want)
			}
		})
	}
}
