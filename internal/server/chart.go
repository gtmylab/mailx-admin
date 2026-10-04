package server

import (
	"fmt"
	"html/template"
	"strings"
)

// chartPoint is one value in a chart, with a label used for tooltips and axis
// hints.
type chartPoint struct {
	Label string
	Value float64
}

// renderBars returns an inline SVG column chart. Bars scale to the tallest
// value; a non-zero value never collapses to an invisible 0px bar. Each bar
// carries a native <title> tooltip ("Label: value"), so hover works with no JS.
// Fill/stroke come from the panel's theme variables, so the chart follows the
// light/dark toggle like everything else.
func renderBars(points []chartPoint, width, height int) template.HTML {
	if len(points) == 0 {
		return template.HTML(`<div class="dim text-sm">No data yet</div>`)
	}

	max := 1.0
	for _, p := range points {
		if p.Value > max {
			max = p.Value
		}
	}

	const gap = 2
	slot := (width - gap*(len(points)-1)) / len(points)
	if slot < 1 {
		slot = 1
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf(
		`<svg class="chart" viewBox="0 0 %d %d" width="100%%" preserveAspectRatio="none" role="img" aria-label="volume chart" style="height:%dpx">`,
		width, height, height))

	for i, p := range points {
		h := int(p.Value / max * float64(height-2))
		if p.Value > 0 && h < 1 {
			h = 1
		}
		x := i * (slot + gap)
		y := height - h
		b.WriteString(fmt.Sprintf(
			`<rect x="%d" y="%d" width="%d" height="%d" rx="1" style="fill:var(--brand)"><title>%s: %g</title></rect>`,
			x, y, slot, h, p.Label, p.Value))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// renderSparkline returns an inline SVG line chart (polyline) with no axes, for
// a growth trend such as mailbox quota over time.
func renderSparkline(points []chartPoint, width, height int) template.HTML {
	if len(points) < 2 {
		return template.HTML(`<div class="dim text-sm">Not enough samples yet</div>`)
	}

	max := 0.0
	for _, p := range points {
		if p.Value > max {
			max = p.Value
		}
	}
	if max <= 0 {
		max = 1
	}

	step := float64(width) / float64(len(points)-1)
	coords := make([]string, 0, len(points))
	for i, p := range points {
		x := float64(i) * step
		y := float64(height-2) - (p.Value/max)*float64(height-4)
		coords = append(coords, fmt.Sprintf("%.1f,%.1f", x, y))
	}

	return template.HTML(fmt.Sprintf(
		`<svg class="chart" viewBox="0 0 %d %d" width="100%%" preserveAspectRatio="none" role="img" aria-label="trend chart" style="height:%dpx">`+
			`<polyline points="%s" fill="none" stroke="var(--brand)" stroke-width="2" stroke-linejoin="round"/></svg>`,
		width, height, height, strings.Join(coords, " ")))
}
