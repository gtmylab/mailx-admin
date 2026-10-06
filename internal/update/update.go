// Package update checks for, and applies, a newer mailx-admin release.
//
// It mirrors what Mailx-Installer's update_mailx_admin does on the host, but
// from inside the running panel: query the GitHub release, download the
// linux-amd64 asset and its SHA256SUMS, verify the checksum, and atomically
// replace the running binary. Restarting the service is left to the caller so
// the browser can receive the result first.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/version"
)

const (
	// Repo is the GitHub repository the panel is published from.
	Repo = "gtmylab/mailx-admin"

	// Asset is the release artifact the panel runs on Linux. It has to match
	// the Makefile's LINUX_ARTIFACT and the release workflow's published name.
	Asset = "mailx-admin-linux-amd64"

	// SHAFile is the checksum file published next to the asset.
	SHAFile = "SHA256SUMS"

	// ServiceName is the systemd unit that runs the panel. Restarting it is the
	// last step of an update, after the binary has been replaced.
	ServiceName = "mailx-admin"

	// CheckInterval is how often the running panel re-checks for a release.
	CheckInterval = 6 * time.Hour

	// maxDownload bounds a single asset read, so a misbehaving upstream cannot
	// grow the process without limit.
	maxDownload = 512 << 20
)

// Release is the subset of a GitHub release the checker needs.
type Release struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// Status is what the panel shows about a version check.
type Status struct {
	Current   string
	Latest    string
	Available bool
	UpToDate  bool
	Notes     string
	CheckedAt string // RFC3339 UTC; empty when never checked
	Error     string
	CanUpdate bool // a stamped build and a newer release
}

// Client checks for and applies releases. Use NewClient; apiBase and
// downloadBase are test seams.
type Client struct {
	http         *http.Client
	repo         string
	asset        string
	shaFile      string
	apiBase      string
	downloadBase string
}

// NewClient returns a Client pointed at the public repository.
func NewClient() *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		repo:    Repo,
		asset:   Asset,
		shaFile: SHAFile,
	}
}

func (c *Client) apiURL() string {
	if c.apiBase != "" {
		return c.apiBase
	}
	return "https://api.github.com/repos/" + c.repo + "/releases/latest"
}

func (c *Client) downloadURL(name string) string {
	if c.downloadBase != "" {
		return c.downloadBase + "/" + name
	}
	return "https://github.com/" + c.repo + "/releases/latest/download/" + name
}

// Check queries the latest release and compares it to the running version. It
// never returns an error: a failure (offline, rate-limited, no release yet)
// lands in Status.Error so the UI can say "could not check" instead of looking
// stuck.
func (c *Client) Check(ctx context.Context) Status {
	st := Status{
		Current:   version.String(),
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}

	rel, err := c.fetchLatest(ctx)
	if err != nil {
		st.Error = err.Error()
		return st
	}

	st.Latest = rel.TagName
	st.Notes = rel.Body
	if rel.Draft || rel.Prerelease {
		st.UpToDate = true
		return st
	}
	if Compare(rel.TagName, st.Current) > 0 {
		st.Available = true
	} else {
		st.UpToDate = true
	}
	st.CanUpdate = version.Stamped() && st.Available
	return st
}

// Apply downloads, verifies and installs the latest release over the running
// binary. It deliberately does not restart the service: the caller responds to
// the operator first and then restarts.
func (c *Client) Apply(ctx context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running binary: %w", err)
	}
	return c.apply(ctx, exe)
}

func (c *Client) apply(ctx context.Context, exe string) error {
	bin, err := c.download(ctx, c.asset)
	if err != nil {
		return err
	}
	sums, err := c.download(ctx, c.shaFile)
	if err != nil {
		return err
	}
	if err := verifySHA256(bin, sums, c.asset); err != nil {
		return err
	}
	return replaceBinary(exe, bin)
}

func (c *Client) fetchLatest(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mailx-admin")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach GitHub: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("no release published yet")
	default:
		return nil, fmt.Errorf("GitHub API answered %s", resp.Status)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &rel, nil
}

func (c *Client) download(ctx context.Context, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.downloadURL(name), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mailx-admin")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", name, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return b, nil
}

// verifySHA256 checks content against the asset's entry in a SHA256SUMS file.
func verifySHA256(content, sums []byte, asset string) error {
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])

	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == asset || filepath.Base(fields[1]) == asset {
			if !strings.EqualFold(fields[0], hexSum) {
				return fmt.Errorf("checksum mismatch for %s: downloaded %s, published %s", asset, hexSum, fields[0])
			}
			return nil
		}
	}
	return fmt.Errorf("%s not found in %s", asset, SHAFile)
}

// replaceBinary writes content over dst atomically, keeping the previous binary
// as a rollback copy. The temp file lives in dst's directory so the final
// rename cannot cross a filesystem boundary.
func replaceBinary(dst string, content []byte) error {
	dir := filepath.Dir(dst)
	tmp := filepath.Join(dir, ".mailx-admin.new")
	if err := os.WriteFile(tmp, content, 0o755); err != nil {
		return fmt.Errorf("write new binary: %w", err)
	}

	bak := filepath.Join(dir, ".mailx-admin.prev")
	_ = os.Remove(bak)
	_ = os.Rename(dst, bak) // ignore: dst is the running binary and is expected to exist

	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Rename(bak, dst) // best-effort rollback
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// Compare orders two dotted version strings, tolerating a leading "v" and a
// pre-release/build suffix. It returns -1, 0 or 1 as a<b, a==b, a>b.
func Compare(a, b string) int {
	pa, preA := numericParts(a)
	pb, preB := numericParts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	// Numeric parts equal: a pre-release is older than the release it precedes.
	switch {
	case preA && !preB:
		return -1
	case !preA && preB:
		return 1
	}
	return 0
}

// numericParts turns "v1.2.3-beta1" into [1 2 3] plus whether it carried a
// pre-release ("-") suffix. A leading "v" is dropped, a build ("+") suffix is
// ignored, and each numeric segment is parsed (a non-numeric segment reads 0).
func numericParts(v string) ([]int, bool) {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	pre := false
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = true
		s = s[:i]
	} else if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	fields := strings.Split(s, ".")
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out, pre
}
