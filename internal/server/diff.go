package server

import (
	"fmt"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/reconciler"
)

type DiffLine struct {
	Kind string // "add", "del", "ctx", "meta"
	Text string
}

type FileDiff struct {
	Path      string
	Action    string
	Lines     []DiffLine
	Truncated bool
}

// buildDiffs turns reconciler changes into UI-friendly diffs.
// In dry-run mode we have Before/After; in real runs we only have hashes.
func buildDiffs(changes []reconciler.FileChange, maxLines int) []FileDiff {
	var out []FileDiff
	for _, c := range changes {
		if c.Action == "unchanged" {
			continue
		}
		fd := FileDiff{
			Path:   c.Path,
			Action: c.Action,
		}
		if c.Before != nil || c.After != nil {
			fd.Lines = diffLines(string(c.Before), string(c.After), maxLines)
		}
		out = append(out, fd)
	}
	return out
}

// diffLines is a trivial line-based diff. For an admin panel this is fine —
// we're showing "these lines were added / removed", not producing git-quality
// diffs. If you want real diffs, swap in github.com/sergi/go-diff.
func diffLines(before, after string, maxLines int) []DiffLine {
	bLines := splitLines(before)
	aLines := splitLines(after)

	// Build sets for quick membership tests (approximate — good enough for UI)
	bSet := make(map[string]int)
	for _, l := range bLines {
		bSet[l]++
	}
	aSet := make(map[string]int)
	for _, l := range aLines {
		aSet[l]++
	}

	var out []DiffLine

	// Removed lines: in before, not in after (or fewer occurrences)
	bSeen := make(map[string]int)
	for _, l := range bLines {
		bSeen[l]++
		if bSeen[l] > aSet[l] {
			out = append(out, DiffLine{Kind: "del", Text: l})
		}
	}

	// Added lines: in after, not in before (or more occurrences)
	aSeen := make(map[string]int)
	for _, l := range aLines {
		aSeen[l]++
		if aSeen[l] > bSet[l] {
			out = append(out, DiffLine{Kind: "add", Text: l})
		}
	}

	if maxLines > 0 && len(out) > maxLines {
		out = out[:maxLines]
		// Signal truncation via a sentinel line
		out = append(out, DiffLine{Kind: "meta", Text: fmt.Sprintf("… (%d more lines)", len(out)-maxLines)})
	}

	return out
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
