package reconciler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileChange describes a single file mutation.
type FileChange struct {
	Path       string `json:"path"`
	Action     string `json:"action"`      // "create", "update", "delete", "unchanged"
	BeforeHash string `json:"before_hash"` // "" if file didn't exist
	AfterHash  string `json:"after_hash"`  // "" if file is being deleted
	Before     []byte `json:"-"`           // only populated in dry-run for diff
	After      []byte `json:"-"`
}

func hash(b []byte) string {
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Ownership is the uid/gid a managed file has to be given.
//
// It exists for one file: Dovecot's passwd-file, which is read by a process that
// is not the one that writes it — the auth process, which has dropped to the
// unprivileged `dovecot` user (see dovecotPasswdOwner in owner.go).
type Ownership struct {
	UID int
	GID int
}

// ErrOwnership reports that a file was written with the right content but could
// not be given the requested owner.
//
// It is deliberately not a plain error, and callers must keep going: the content
// is on disk, the daemons read that content, and a panel that is not running as
// root can do nothing about the ownership however loudly it fails. Refusing the
// sync would only replace a permissions problem with a server whose
// configuration never lands.
var ErrOwnership = errors.New("file ownership was not applied")

// WriteFile writes `content` to `path` atomically, leaving ownership alone.
// Returns a FileChange.
// If `dryRun`, does not touch the filesystem.
func WriteFile(path string, content []byte, mode os.FileMode, dryRun bool) (FileChange, error) {
	return WriteFileOwned(path, content, mode, nil, dryRun)
}

// WriteFileOwned is WriteFile with an owner to apply.
//
// The order matters: the temporary file is chowned and *then* renamed, so the
// file at `path` never exists for an instant with the right bytes and an owner
// that cannot read them — the state that refuses a login. A chown that fails is
// reported as ErrOwnership, after the content is in place.
func WriteFileOwned(path string, content []byte, mode os.FileMode, owner *Ownership, dryRun bool) (FileChange, error) {
	before, err := os.ReadFile(path)
	var beforeExists bool
	if err == nil {
		beforeExists = true
	} else if !os.IsNotExist(err) {
		return FileChange{}, fmt.Errorf("read %s: %w", path, err)
	}

	beforeHash := ""
	if beforeExists {
		beforeHash = hash(before)
	}
	afterHash := hash(content)

	// An existing file whose bytes are identical is left alone. The early
	// return below is what keeps a no-op reconcile from rewriting every managed
	// file on every sync.
	unchanged := beforeExists && beforeHash == afterHash

	change := FileChange{
		Path:       path,
		BeforeHash: beforeHash,
		AfterHash:  afterHash,
	}

	switch {
	case !beforeExists:
		change.Action = "create"
	case unchanged:
		change.Action = "unchanged"
	default:
		change.Action = "update"
	}

	// A dry run carries the content of everything it reports, unchanged entries
	// included. The preview modal renders its diff from Before/After (see
	// internal/server/diff.go), and the reconciler lists every managed file it
	// rendered, not only the ones it would rewrite. Returning early for an
	// unchanged file -- the obvious optimisation, and what v1.0.5 shipped --
	// left those entries with no content at all, so previewing a change that
	// does not touch this file showed the operator an empty box where "no
	// change here" belonged, which is indistinguishable from a broken diff.
	if dryRun {
		change.Before = before
		change.After = content
		return change, nil
	}

	if unchanged {
		return change, nil // don't touch disk
	}

	// Atomic write: temp file in same dir, fsync, rename
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return change, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".mailx-*")
	if err != nil {
		return change, fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if rename succeeded

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return change, fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return change, fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return change, fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return change, fmt.Errorf("chmod: %w", err)
	}

	// Ownership before the rename: see WriteFileOwned.
	var ownErr error
	if owner != nil {
		if err := os.Chown(tmpName, owner.UID, owner.GID); err != nil {
			ownErr = fmt.Errorf("%w: chown %s to %d:%d: %v",
				ErrOwnership, path, owner.UID, owner.GID, err)
		}
	}

	if err := os.Rename(tmpName, path); err != nil {
		return change, fmt.Errorf("rename: %w", err)
	}

	// fsync the directory so the rename is durable
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return change, ownErr
}

// BackupFile copies a file to `<path>.bak-<timestamp>`.
func BackupFile(path string) (string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", nil
	}
	ts := time.Now().Format("20060102_150405")
	backup := fmt.Sprintf("%s.pre-reconcile_%s", path, ts)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		return "", err
	}
	return backup, nil
}
