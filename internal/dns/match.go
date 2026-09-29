package dns

import (
	"fmt"
	"slices"
	"strings"
)

// matchRecord compares one expected record with what DNS returned, and explains
// the difference when it does not match.
//
// The previous implementation compared strings and, for SPF and DMARC, accepted
// any record that merely started with "v=spf1" / "v=DMARC1" — so a published SPF
// record that did not authorise this server still produced a healthy check mark.
// Each type is now compared by its own rules.
func matchRecord(exp Expected, obs *Observed) (bool, string) {
	if obs == nil || len(obs.Values) == 0 {
		return false, "no record found"
	}

	switch exp.Type {
	case TypeTXT:
		return matchTXT(exp, obs)

	case TypeMX:
		want := fmt.Sprintf("%d %s", exp.Priority, exp.Value)
		for _, v := range obs.Values {
			if strings.EqualFold(v, want) {
				return true, ""
			}
		}
		// Some providers rewrite the priority; the target is what matters.
		for _, v := range obs.Values {
			if parts := strings.SplitN(v, " ", 2); len(parts) == 2 && strings.EqualFold(parts[1], exp.Value) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%s does not list %s (found: %s)", exp.Name, exp.Value, strings.Join(obs.Values, ", "))

	case TypeA, TypeAAAA, TypeCNAME, TypePTR:
		for _, v := range obs.Values {
			if strings.EqualFold(strings.TrimSuffix(v, "."), strings.TrimSuffix(exp.Value, ".")) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("expected %s, found %s", exp.Value, strings.Join(obs.Values, ", "))
	}
	return false, "unsupported record type"
}

// matchTXT dispatches a TXT record to the comparison its content calls for.
func matchTXT(exp Expected, obs *Observed) (bool, string) {
	lower := strings.ToLower(strings.TrimSpace(exp.Value))

	switch {
	case strings.HasPrefix(lower, "v=spf1"):
		return matchSPF(exp, obs)
	case strings.HasPrefix(lower, "v=dmarc1"):
		return matchDMARC(exp, obs)
	case strings.Contains(lower, "_domainkey"), strings.Contains(lower, "v=dkim1"), strings.Contains(lower, "p="):
		return matchDKIM(exp, obs)
	}

	want := normalizeTXT(exp.Value)
	for _, v := range obs.Values {
		if normalizeTXT(v) == want {
			return true, ""
		}
	}
	return false, fmt.Sprintf("expected %q, found %q", exp.Value, strings.Join(obs.Values, " | "))
}

// spfTokens splits an SPF record into its mechanisms, lowercased.
func spfTokens(record string) []string {
	fields := strings.Fields(normalizeTXT(record))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, strings.ToLower(f))
	}
	return out
}

// matchSPF requires every mechanism the panel relies on to be present. Extra
// mechanisms are fine: the operator may send through another provider as well.
func matchSPF(exp Expected, obs *Observed) (bool, string) {
	want := spfTokens(exp.Value)

	for _, v := range obs.Values {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=spf1") {
			continue
		}
		have := spfTokens(v)

		var missing []string
		for _, w := range want {
			switch w {
			case "~all", "-all", "?all":
				continue // the qualifier is deliberately not compared
			}
			if !slices.Contains(have, w) {
				missing = append(missing, w)
			}
		}
		if len(missing) == 0 {
			return true, ""
		}
		return false, fmt.Sprintf(
			"the published SPF record does not authorise this server: missing %s (found: %s)",
			strings.Join(missing, ", "), v)
	}
	return false, fmt.Sprintf(
		"no SPF record found (looked for one starting with v=spf1; found: %s)",
		strings.Join(obs.Values, " | "))
}

// matchDKIM compares the public key. h=, k= and the tag order may differ between
// providers; p= may not: a stale key means every signature fails.
func matchDKIM(exp Expected, obs *Observed) (bool, string) {
	want := dkimKey(exp.Value)
	if want == "" {
		for _, v := range obs.Values {
			if normalizeTXT(v) == normalizeTXT(exp.Value) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("the published key differs from the key in the panel (found: %s)",
			strings.Join(obs.Values, " | "))
	}

	for _, v := range obs.Values {
		if have := dkimKey(v); have != "" && have == want {
			return true, ""
		}
	}
	return false, "the published DKIM key does not match the key the panel generated (p= differs)"
}

// dkimKey extracts the p= value of a DKIM record, whitespace removed.
func dkimKey(record string) string {
	normalized := normalizeTXT(record)
	idx := strings.Index(strings.ToLower(normalized), "p=")
	if idx < 0 {
		return ""
	}
	rest := normalized[idx+2:]
	if end := strings.IndexAny(rest, "; \t"); end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}

// matchDMARC accepts the record when the version is right and the policy is at
// least as strict as the one asked for: p=reject satisfies a plan that says
// p=none, but never the other way round.
func matchDMARC(exp Expected, obs *Observed) (bool, string) {
	wantPolicy := dmarcPolicy(exp.Value)

	for _, v := range obs.Values {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=dmarc1") {
			continue
		}
		have := dmarcPolicy(v)
		if dmarcRank(have) >= dmarcRank(wantPolicy) {
			return true, ""
		}
		return false, fmt.Sprintf("policy p=%s is weaker than the recommended p=%s (found: %s)",
			have, wantPolicy, v)
	}
	return false, fmt.Sprintf("no DMARC record found (looked for one starting with v=DMARC1; found: %s)",
		strings.Join(obs.Values, " | "))
}

func dmarcPolicy(record string) string {
	for _, tag := range strings.Split(normalizeTXT(record), ";") {
		parts := strings.SplitN(strings.TrimSpace(tag), "=", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "p") {
			return strings.ToLower(strings.TrimSpace(parts[1]))
		}
	}
	return ""
}

func dmarcRank(policy string) int {
	switch policy {
	case "reject":
		return 3
	case "quarantine":
		return 2
	case "none":
		return 1
	default:
		return 0
	}
}
