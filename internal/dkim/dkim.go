package dkim

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
)

// Budgets for the two helpers this package runs. opendkim-genkey had none at
// all before this release, and it runs inside the request that adds (or
// rotates) a domain: a key generation stuck on a starved entropy pool, or a
// `chown` waiting on a hanging NSS lookup, blocked that request forever — no
// error, no log line, a browser that never stops loading. The DKIM key is
// generated outside the transaction on purpose (see mutations.CreateDomain),
// but "outside the transaction" is not the same as "bounded".
const (
	genkeyTimeout = 60 * time.Second
	chownTimeout  = 10 * time.Second
)

type Result struct {
	PrivateKeyPath string
	PublicRecord   string // the value of the DNS TXT record
	Selector       string
}

// Generate creates a new DKIM key pair for `domain` under `baseDir/keys/<domain>/`.
func Generate(ctx context.Context, domain, baseDir string) (*Result, error) {
	return GenerateWithSelector(ctx, domain, baseDir, "default", false)
}

// GenerateWithSelector allows overriding the selector.
// If `overwrite` is false and the key exists, it's reused (returns the existing record).
func GenerateWithSelector(ctx context.Context, domain, baseDir, selector string, overwrite bool) (*Result, error) {
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

	// opendkim-genkey writes into -D; -s/-d name the selector and domain.
	out, err := execx.Output(ctx, genkeyTimeout, "opendkim-genkey",
		"-s", selector,
		"-d", domain,
		"-b", "2048",
		"-D", keyDir,
	)
	if err != nil {
		return nil, fmt.Errorf("opendkim-genkey: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Fix permissions
	if err := os.Chmod(privKeyPath, 0o600); err != nil {
		return nil, err
	}
	_ = os.Chmod(txtPath, 0o644)
	_ = execx.Run(ctx, chownTimeout, "chown", "opendkim:opendkim", privKeyPath, txtPath)

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
