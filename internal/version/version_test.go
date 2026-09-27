package version

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoFile reads a file relative to the repository root. This package lives in
// internal/version, so the root is two levels up. Tests run with the package
// directory as their working directory (the same approach as
// internal/server/templates_test.go, which reads router.go).
func repoFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s from repo root: %v", name, err)
	}
	return string(data)
}

func TestGetReportsBuildAndRuntime(t *testing.T) {
	info := Get()

	if info.Version != Version {
		t.Errorf("Get().Version = %q, want %q", info.Version, Version)
	}
	if info.Commit != Commit {
		t.Errorf("Get().Commit = %q, want %q", info.Commit, Commit)
	}
	if info.Date != Date {
		t.Errorf("Get().Date = %q, want %q", info.Date, Date)
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("Get().GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
	if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
		t.Errorf("Get() platform = %s/%s, want %s/%s",
			info.OS, info.Arch, runtime.GOOS, runtime.GOARCH)
	}
}

// TestFullCarriesEveryField — Full() is what `mailx-admin --version` prints and
// what the `serve` startup log line records. Every field must really be in it,
// otherwise a Linux host cannot tell which release it is running.
func TestFullCarriesEveryField(t *testing.T) {
	full := Full()
	for _, want := range []string{
		Version, Commit, Date,
		runtime.Version(), runtime.GOOS, runtime.GOARCH,
	} {
		if !strings.Contains(full, want) {
			t.Errorf("Full() = %q, missing %q", full, want)
		}
	}
}

func TestFieldsAreSlogPairs(t *testing.T) {
	fields := Fields()
	if len(fields)%2 != 0 {
		t.Fatalf("Fields() has %d entries, want key/value pairs", len(fields))
	}

	got := make(map[string]string, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			t.Fatalf("Fields()[%d] = %v, want a string key", i, fields[i])
		}
		val, ok := fields[i+1].(string)
		if !ok {
			t.Fatalf("Fields()[%d] = %v, want a string value", i+1, fields[i+1])
		}
		got[key] = val
	}

	for _, key := range []string{"version", "commit", "built", "go", "platform"} {
		if got[key] == "" {
			t.Errorf("Fields() is missing %q", key)
		}
	}
	if want := runtime.GOOS + "/" + runtime.GOARCH; got["platform"] != want {
		t.Errorf("Fields() platform = %q, want %q", got["platform"], want)
	}
}

func TestStampedMatchesCommit(t *testing.T) {
	want := Commit != "" && Commit != "unknown"

	if got := Get().Stamped(); got != want {
		t.Errorf("Get().Stamped() = %v, want %v (commit %q)", got, want, Commit)
	}
	if got := Stamped(); got != want {
		t.Errorf("Stamped() = %v, want %v", got, want)
	}
}

// TestMakefileStampsVersionSymbols guards the build-time contract. "go build
// -ldflags -X" silently ignores a symbol that does not exist, so renaming this
// package or one of the three variables would not break any build — every
// binary would just claim "0.1.0-dev" forever. Fail loudly instead.
func TestMakefileStampsVersionSymbols(t *testing.T) {
	mk := repoFile(t, "Makefile")

	for _, symbol := range []string{
		"internal/version.Version=",
		"internal/version.Commit=",
		"internal/version.Date=",
	} {
		if !strings.Contains(mk, symbol) {
			t.Errorf("Makefile no longer stamps -X ...%s: ldflags for missing symbols are ignored, so version stamping would stop silently", symbol)
		}
	}
}

// TestMakefileHasUnixLineEndings — this Makefile is consumed by GNU make on
// Linux. With CRLF endings the stray CR is passed to the shell as part of the
// last argument, so "go build -o bin/mailx-admin" would create a file named
// "mailx-admin\r" and the Linux build would carry no usable version. Keep the
// file LF-only.
func TestMakefileHasUnixLineEndings(t *testing.T) {
	if strings.Contains(repoFile(t, "Makefile"), "\r\n") {
		t.Error("Makefile contains CRLF line endings; GNU make on Linux passes the CR to the shell")
	}
}

// TestLinuxArtifactNameMatchesInstaller — Mailx-Installer downloads a release
// artifact by hard-coded name. If the Makefile emits a different name, the
// Linux host keeps installing a binary without the current version stamped in,
// which is exactly the bug this test exists to prevent.
func TestLinuxArtifactNameMatchesInstaller(t *testing.T) {
	const artifact = "mailx-admin-linux-amd64"

	mk := repoFile(t, "Makefile")
	if !strings.Contains(mk, artifact) {
		t.Errorf("Makefile does not build %s, which is the artifact the installer downloads", artifact)
	}
	if !strings.Contains(mk, "build-linux") {
		t.Error(`Makefile has no "build-linux" target, so there is no Linux artifact with a stamped version`)
	}

	installer := repoFile(t, "Mailx-Installer")
	if !strings.Contains(installer, artifact) {
		t.Errorf("installer no longer references %s", artifact)
	}
	if !strings.Contains(installer, "--version") {
		t.Error("installer never runs --version, so the installed build version is never logged")
	}
}

// TestReleaseWorkflowPublishesArtifactSet is the third link in the same
// contract. The Makefile decides the artifact name, the installer downloads it,
// and the release workflow is what actually puts it on GitHub. If the workflow
// stops building through "make release", or publishes a different file name,
// the installer's download URL goes dead again while everything looks fine.
func TestReleaseWorkflowPublishesArtifactSet(t *testing.T) {
	workflow := repoFile(t, filepath.Join(".github", "workflows", "release.yml"))

	for _, want := range []string{
		"make release",            // one build path: the Makefile owns the names
		"mailx-admin-linux-amd64", // the asset the installer downloads
		"SHA256SUMS",              // provenance for what is installed
		"gh release",              // official CLI, no third-party release action
		"VERSION=",                // tag must be stamped into the binary
	} {
		if !strings.Contains(workflow, want) {
			t.Errorf("release workflow no longer contains %q", want)
		}
	}
}
