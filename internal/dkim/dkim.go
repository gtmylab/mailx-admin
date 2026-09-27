package dkim

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Result struct {
	PrivateKeyPath string
	PublicRecord   string // the value of the DNS TXT record
	Selector       string
}

// Generate creates a new DKIM key pair for `domain` under `baseDir/keys/<domain>/`.
func Generate(domain, baseDir string) (*Result, error) {
	return GenerateWithSelector(domain, baseDir, "default", false)
}

// GenerateWithSelector allows overriding the selector.
// If `overwrite` is false and the key exists, it's reused (returns the existing record).
func GenerateWithSelector(domain, baseDir, selector string, overwrite bool) (*Result, error) {
	keyDir := filepath.Join(baseDir, "keys", domain)
	privKeyPath := filepath.Join(keyDir, selector+".private")
	txtPath := filepath.Join(keyDir, selector+".txt")

	// Reuse if present and not overwriting
	if !overwrite {
		if _, err := os.Stat(privKeyPath); err == nil {
			pub, err := readPublicRecord(txtPath)
			if err == nil {
				return &Result{
					PrivateKeyPath: privKeyPath,
					PublicRecord:   pub,
					Selector:       selector,
				}, nil
			}
		}
	}

	if err := os.MkdirAll(keyDir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", keyDir, err)
	}

	// opendkim-genkey runs in the current directory
	cmd := exec.Command("opendkim-genkey",
		"-s", selector,
		"-d", domain,
		"-b", "2048",
		"-D", keyDir,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("opendkim-genkey: %w: %s", err, stderr.String())
	}

	// Fix permissions
	if err := os.Chmod(privKeyPath, 0o600); err != nil {
		return nil, err
	}
	_ = os.Chmod(txtPath, 0o644)
	_ = exec.Command("chown", "opendkim:opendkim", privKeyPath, txtPath).Run()

	pub, err := readPublicRecord(txtPath)
	if err != nil {
		return nil, err
	}

	return &Result{
		PrivateKeyPath: privKeyPath,
		PublicRecord:   pub,
		Selector:       selector,
	}, nil
}

// readPublicRecord parses the multi-line .txt file produced by opendkim-genkey
// and returns the full DKIM record value with quotes stripped and whitespace collapsed.
func readPublicRecord(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var parts []string
	for _, line := range strings.Split(string(data), "\n") {
		start := strings.Index(line, `"`)
		end := strings.LastIndex(line, `"`)
		if start >= 0 && end > start {
			parts = append(parts, line[start+1:end])
		}
	}
	return strings.Join(strings.Fields(strings.Join(parts, "")), " "), nil
}
