package server

import (
	"strings"
	"testing"
)

func TestRenderBars(t *testing.T) {
	points := []chartPoint{
		{Label: "Jan 1", Value: 3},
		{Label: "Jan 2", Value: 7},
		{Label: "Jan 3", Value: 0},
	}
	got := string(renderBars(points, 300, 100))

	for _, want := range []string{"<svg", "<rect", "<title>Jan 1: 3</title>", "Jan 2: 7"} {
		if !strings.Contains(got, want) {
			t.Errorf("renderBars missing %q:\n%s", want, got)
		}
	}
}

func TestRenderBarsEmpty(t *testing.T) {
	if got := string(renderBars(nil, 300, 100)); !strings.Contains(got, "No data") {
		t.Errorf("renderBars(nil) = %q, want a no-data message", got)
	}
}

func TestRenderBarsNonZeroNeverCollapses(t *testing.T) {
	// A tiny non-zero value next to a huge one must still get a visible
	// (>=1px) bar, not round down to zero.
	got := string(renderBars([]chartPoint{{Label: "small", Value: 1}, {Label: "huge", Value: 1000000}}, 200, 50))
	if !strings.Contains(got, "height=\"1\"") {
		t.Errorf("a tiny non-zero bar collapsed to 0px:\n%s", got)
	}
}

func TestRenderSparkline(t *testing.T) {
	points := []chartPoint{
		{Label: "d1", Value: 1},
		{Label: "d2", Value: 2},
		{Label: "d3", Value: 1.5},
	}
	got := string(renderSparkline(points, 200, 80))
	if !strings.Contains(got, "<polyline") {
		t.Errorf("renderSparkline missing polyline:\n%s", got)
	}
}

func TestRenderSparklineTooFewPoints(t *testing.T) {
	got := string(renderSparkline([]chartPoint{{Label: "d1", Value: 1}}, 200, 80))
	if !strings.Contains(got, "Not enough samples") {
		t.Errorf("renderSparkline(single) = %q, want a not-enough-samples message", got)
	}
}
