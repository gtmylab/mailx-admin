package reconciler

import (
	"crypto/sha256"
	"encoding/hex"
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

// WriteFile writes `content` to `path` atomically. Returns a FileChange.
// If `dryRun`, does not touch the filesystem.
func WriteFile(path string, content []byte, mode os.FileMode, dryRun bool) (FileChange, error) {
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

	change := FileChange{
		Path:       path,
		BeforeHash: beforeHash,
		AfterHash:  afterHash,
	}

	switch {
	case !beforeExists:
		change.Action = "create"
	case beforeHash == afterHash:
		change.Action = "unchanged"
		return change, nil // don't touch disk
	default:
		change.Action = "update"
	}

	if dryRun {
		change.Before = before
		change.After = content
		return change, nil
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
	if err := os.Rename(tmpName, path); err != nil {
		return change, fmt.Errorf("rename: %w", err)
	}

	// fsync the directory so the rename is durable
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return change, nil
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
