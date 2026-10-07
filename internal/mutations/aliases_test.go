package mutations

import (
	"errors"
	"testing"
)

func TestNormalizeAliasSource(t *testing.T) {
	cases := []struct {
		name    string
		source  string
		domain  string
		want    string
		wantErr bool
	}{
		{"bare catch-all", "@", "example.com", "@example.com", false},
		{"qualified catch-all", "@example.com", "example.com", "@example.com", false},
		{"local part", "sales", "example.com", "sales", false},
		{"embedded at rejected", "sales@example.com", "example.com", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeAliasSource(tc.source, tc.domain)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeAliasSource(%q, %q) = %q, nil; want error", tc.source, tc.domain, got)
				}
				if !errors.Is(err, ErrInvalidInput) {
					t.Errorf("error = %v, want ErrInvalidInput", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeAliasSource(%q, %q) error: %v", tc.source, tc.domain, err)
			}
			if got != tc.want {
				t.Errorf("normalizeAliasSource(%q, %q) = %q, want %q", tc.source, tc.domain, got, tc.want)
			}
		})
	}
}
