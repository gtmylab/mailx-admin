package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"sort"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
)

// runCapture runs a command for the diagnostics bundle. Both streams are
// captured, because `systemctl status` prints the useful part on stdout while
// its exit code is non-zero whenever a unit is not running.
func runCapture(name string, args ...string) (string, error) {
	out, err := execx.Output(context.Background(), time.Minute, name, args...)
	return string(out), err
}

// writeTarGz writes entries deterministically (sorted names), so two bundles
// from the same state are comparable.
func writeTarGz(path string, entries map[string]string) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		body := []byte(entries[name])
		if err := tw.WriteHeader(&tar.Header{
			Name:    name,
			Mode:    0o600,
			Size:    int64(len(body)),
			ModTime: time.Now(),
		}); err != nil {
			return err
		}
		if _, err := tw.Write(body); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}
