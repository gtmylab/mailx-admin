package dns

import "testing"

func TestBlocklistQueryName(t *testing.T) {
	got, err := blocklistQueryName("1.2.3.4", "zen.spamhaus.org")
	if err != nil {
		t.Fatalf("blocklistQueryName: %v", err)
	}
	if want := "4.3.2.1.zen.spamhaus.org"; got != want {
		t.Errorf("blocklistQueryName = %q, want %q", got, want)
	}
}

func TestBlocklistQueryNameRejectsInvalidIP(t *testing.T) {
	if _, err := blocklistQueryName("not-an-ip", "zen.spamhaus.org"); err == nil {
		t.Error("blocklistQueryName accepted an invalid IP")
	}
}
