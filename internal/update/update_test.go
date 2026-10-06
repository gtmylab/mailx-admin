package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/version"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0", "1.1.0", -1},
		{"1.1.0", "1.0.0", 1},
		{"v1.3.0", "1.2.9", 1},
		{"1.2.10", "1.2.9", 1},
		{"1.3.0-beta1", "1.3.0", -1},
		{"1.3.0-dev", "1.2.0", 1},
		{"1.3", "1.3.0", 0},
		{"2.0.0", "1.999.999", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVerifySHA256(t *testing.T) {
	content := []byte("hello")
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])

	t.Run("match", func(t *testing.T) {
		sums := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other-file\n" +
			hexSum + "  mailx-admin-linux-amd64\n")
		if err := verifySHA256(content, sums, "mailx-admin-linux-amd64"); err != nil {
			t.Fatalf("valid sums rejected: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		sums := []byte("0000000000000000000000000000000000000000000000000000000000000000  mailx-admin-linux-amd64\n")
		if err := verifySHA256(content, sums, "mailx-admin-linux-amd64"); err == nil {
			t.Fatal("mismatched sums accepted")
		}
	})

	t.Run("missing", func(t *testing.T) {
		sums := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other-file\n")
		if err := verifySHA256(content, sums, "mailx-admin-linux-amd64"); err == nil {
			t.Fatal("missing entry accepted")
		}
	})
}

func TestApplyDownloadsVerifiesAndReplaces(t *testing.T) {
	bin := []byte("#!/bin/sh\necho new\n")
	sum := sha256.Sum256(bin)
	hexSum := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/mailx-admin-linux-amd64", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bin)
	})
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  mailx-admin-linux-amd64\n", hexSum)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient()
	c.http = srv.Client()
	c.downloadBase = srv.URL

	dir := t.TempDir()
	exe := filepath.Join(dir, "mailx-admin")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := c.apply(context.Background(), exe); err != nil {
		t.Fatalf("apply: %v", err)
	}

	got, _ := os.ReadFile(exe)
	if string(got) != string(bin) {
		t.Fatalf("binary not replaced: got %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".mailx-admin.prev")); err != nil {
		t.Errorf("no rollback copy kept: %v", err)
	}
}

func TestApplyRejectsBadChecksum(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/mailx-admin-linux-amd64", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("new"))
	})
	mux.HandleFunc("/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "0000000000000000000000000000000000000000000000000000000000000000  mailx-admin-linux-amd64\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient()
	c.http = srv.Client()
	c.downloadBase = srv.URL

	dir := t.TempDir()
	exe := filepath.Join(dir, "mailx-admin")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := c.apply(context.Background(), exe); err == nil {
		t.Fatal("apply accepted a mismatched checksum")
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old" {
		t.Fatalf("binary was replaced despite checksum mismatch: %q", got)
	}
}

func TestCheckReportsAvailable(t *testing.T) {
	orig := version.Version
	version.Version = "1.2.0"
	defer func() { version.Version = orig }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"v1.3.0","name":"v1.3.0","body":"notes","draft":false,"prerelease":false}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient()
	c.http = srv.Client()
	c.apiBase = srv.URL

	st := c.Check(context.Background())
	if st.Latest != "v1.3.0" {
		t.Errorf("Latest = %q, want v1.3.0", st.Latest)
	}
	if !st.Available {
		t.Error("v1.3.0 should be available over v1.2.0")
	}
	if st.CanUpdate {
		t.Error("CanUpdate should be false for an unstamped build")
	}
}

func TestCheckSkipsPrerelease(t *testing.T) {
	orig := version.Version
	version.Version = "1.2.0"
	defer func() { version.Version = orig }()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name":"v1.3.0-rc1","name":"v1.3.0-rc1","body":"","draft":false,"prerelease":true}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient()
	c.http = srv.Client()
	c.apiBase = srv.URL

	st := c.Check(context.Background())
	if st.Available {
		t.Error("a prerelease must not be offered as an update")
	}
	if !st.UpToDate {
		t.Error("a prerelease should leave the panel reporting up-to-date")
	}
}
