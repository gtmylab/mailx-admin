// Package version is the single source of truth for build metadata.
//
// The three variables below are overwritten at link time by the Makefile:
//
//	-X github.com/gtmylab/mailx-admin/internal/version.Version=...
//	-X github.com/gtmylab/mailx-admin/internal/version.Commit=...
//	-X github.com/gtmylab/mailx-admin/internal/version.Date=...
//
// They MUST stay package-level string variables with exactly these names, or
// stamping silently stops working (an -X for a missing symbol is ignored, not
// an error). version_test.go guards both the names and the Makefile paths.
//
// The values are baked into the binary at build time, so they are identical on
// every platform: a Linux release build and a Windows dev build each report
// whatever the toolchain stamped into that particular binary (the defaults
// below are only used for a bare "go build" without -ldflags).
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the release/tag this binary was built from.
	// Defaults to "0.1.0-dev" when built without -ldflags.
	Version = "0.1.0-dev"

	// Commit is the short git revision this binary was built from.
	Commit = "unknown"

	// Date is the UTC build timestamp in RFC3339 format.
	Date = "unknown"
)

// Info is a snapshot of the build metadata plus the runtime the binary is
// currently executing on. It is what the metrics collector reports, so a
// running Linux server and a developer's local binary can both be identified
// unambiguously.
type Info struct {
	Version   string
	Commit    string
	Date      string
	GoVersion string
	OS        string
	Arch      string
}

// Get returns the build metadata of the running binary.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns the version alone, e.g. "1.4.2" or "0.1.0-dev".
func String() string { return Version }

// Full returns the version with its provenance, e.g.
//
//	1.4.2 (commit 9f3c1ab, built 2026-09-27T10:11:12Z, go1.24.0 linux/amd64)
//
// This is what `mailx-admin --version` prints and what the `serve` startup log
// line records, so the same string is available from the CLI on any platform
// and from the running server's logs/metrics.
func Full() string {
	i := Get()
	return fmt.Sprintf("%s (commit %s, built %s, %s %s/%s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.OS, i.Arch)
}

// Stamped reports whether this build carries link-time metadata, i.e. it came
// from "make build"/"make release" rather than a bare "go build".
func (i Info) Stamped() bool { return i.Commit != "" && i.Commit != "unknown" }

// Stamped reports whether the running binary carries build metadata.
func Stamped() bool { return Get().Stamped() }

// Fields returns slog key/value pairs, so callers can write
//
//	logger.Info("starting", version.Fields()...)
//
// and get the full provenance in one structured log line.
func Fields() []any {
	i := Get()
	return []any{
		"version", i.Version,
		"commit", i.Commit,
		"built", i.Date,
		"go", i.GoVersion,
		"platform", i.OS + "/" + i.Arch,
	}
}
