// Package apt lists and applies operating-system package updates on Debian and
// Ubuntu hosts. It shells out to apt-get / apt / dpkg-query, so it is Linux-only
// at runtime; the code itself is portable and compiles everywhere.
package apt

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Package is one upgradable operating-system package.
type Package struct {
	Name        string
	Description string
	Installed   string // current installed version
	Available   string // version the update installs
	Source      string // release pocket / suite (e.g. "stable", "stable-security")
}

const (
	updateTimeout = 120 * time.Second
	listTimeout   = 30 * time.Second
	queryTimeout  = 20 * time.Second
)

// Upgradable refreshes the package lists and returns the upgradable packages.
// The apt-get update step is best-effort: if it fails (offline, no network) the
// existing lists are still read, so a stale list is better than no list.
func Upgradable(ctx context.Context) ([]Package, error) {
	_, _ = runTimeout(ctx, updateTimeout, "apt-get", "update")
	return List(ctx)
}

// List reads the currently-upgradable packages without refreshing the lists.
func List(ctx context.Context) ([]Package, error) {
	out, err := runTimeout(ctx, listTimeout, "apt", "list", "--upgradable")
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, err
	}
	pkgs := parseUpgradable(out)
	descs := descriptions(ctx)
	for i := range pkgs {
		pkgs[i].Description = descs[pkgs[i].Name]
	}
	return pkgs, nil
}

// Upgrade installs the named packages (already-installed versions only) with a
// non-interactive frontend, streaming combined output to w.
func Upgrade(ctx context.Context, names []string, w io.Writer) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"install", "--only-upgrade", "-y"}, names...)
	cmd := exec.CommandContext(ctx, "apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdout = w
	cmd.Stderr = w
	return cmd.Run()
}

// runTimeout runs a command with a bounded deadline and returns its full output.
// It deliberately does not cap output: a package list can be larger than the
// panel's 8 KiB execx cap.
func runTimeout(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// parseUpgradable turns `apt list --upgradable` output into packages. Each line
// looks like "name/suite version arch [upgradable from: old]".
func parseUpgradable(s string) []Package {
	var pkgs []Package
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "upgradable from") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		name, source := splitNameSuite(fields[0])
		pkgs = append(pkgs, Package{
			Name:      name,
			Source:    source,
			Available: fields[1],
			Installed: strings.TrimSuffix(fields[5], "]"),
		})
	}
	return pkgs
}

func splitNameSuite(s string) (name, source string) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// descriptions maps package name to its short description, one dpkg-query call
// for the whole installed set.
func descriptions(ctx context.Context) map[string]string {
	m := map[string]string{}
	out, err := runTimeout(ctx, queryTimeout, "dpkg-query", "-W", "-f=${binary:Package}\t${binary:Summary}\n")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(out, "\n") {
		name, desc, ok := strings.Cut(line, "\t")
		if ok && name != "" {
			m[name] = strings.TrimSpace(desc)
		}
	}
	return m
}
