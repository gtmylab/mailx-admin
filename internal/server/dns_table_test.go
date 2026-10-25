package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// A DKIM public key is one unbroken token of several hundred characters. With
// `table-layout: auto` that token sets the table's min-content width, so the
// Value column consumed the whole card and pushed the Copy/Check buttons out of
// view -- the operator could see the record but not copy it. The fix is a fixed
// layout with declared column widths (.table-dns in app.css) plus a break
// opportunity inside the cell, so this test asserts the markup those depend on.
func TestDNSRecordsTableFitsLongTokens(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	// Long enough to overflow any sane column.
	key := "v=DKIM1; h=sha256; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 8)

	var buf bytes.Buffer
	if err := tmpl.fragments.ExecuteTemplate(&buf, "dns_check_results", map[string]any{
		"Domain": &models.Domain{ID: 4, Name: "example.com"},
		"Rows": []dnsRow{{
			Purpose:  "DKIM (selector default)",
			Type:     "TXT",
			Name:     "default._domainkey.example.com",
			Value:    key,
			Required: true,
			Status:   "mismatch",
			Message:  "Public DNS returns a different value for this record.",
		}},
	}); err != nil {
		t.Fatalf("render dns_check_results: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		`class="table table-stack table-dns"`,
		"<colgroup>",
		// The value cell is allowed to wrap, which is what keeps the table
		// inside its card.
		`class="mono text-xs break-all"`,
		// So is the status message, which can quote the published value.
		`class="text-xs break-all `,
		"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dns table is missing %q:\n%s", want, out)
		}
	}

	// The Copy button has to keep the untruncated value: wrapping is a display
	// concern, not permission to change what the operator publishes.
	if !strings.Contains(out, "data-copy-value=") {
		t.Error("the copy button lost its value")
	}
}
