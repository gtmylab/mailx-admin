package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	// Where to write the backup tarball
	OutputDir string

	// What to include
	IncludeDatabase    bool
	IncludeConfigs     bool
	IncludeMaildirs    bool
	IncludeDKIM        bool
	IncludeLetsEncrypt bool

	// If empty, a timestamped name is generated
	Name string
}

type Result struct {
	Name      string
	Path      string
	SizeBytes int64
	Duration  time.Duration
	Manifest  []string // list of included paths
}

// Create runs a full backup.
func Create(ctx context.Context, db *sql.DB, dbDriver string, opts Options) (*Result, error) {
	if opts.OutputDir == "" {
		opts.OutputDir = "/var/backups/mailx"
	}
	if err := os.MkdirAll(opts.OutputDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	name := opts.Name
	if name == "" {
		name = fmt.Sprintf("mailx-backup-%s", time.Now().Format("20060102-150405"))
	}
	path := filepath.Join(opts.OutputDir, name+".tar.gz")

	start := time.Now()
	res := &Result{Name: name, Path: path}

	// Create tarball
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create tarball: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	// ---- Database ----
	if opts.IncludeDatabase {
		if err := writeDatabase(ctx, tw, db, dbDriver, res); err != nil {
			return nil, fmt.Errorf("database: %w", err)
		}
	}

	// ---- Config directories ----
	if opts.IncludeConfigs {
		for _, dir := range []string{
			"/etc/postfix",
			"/etc/dovecot",
			"/etc/opendkim",
			"/etc/mailx",
			"/etc/apache2/sites-available",
		} {
			if err := writeDir(tw, dir, res); err != nil {
				return nil, fmt.Errorf("config %s: %w", dir, err)
			}
		}
	}

	// ---- DKIM keys ----
	if opts.IncludeDKIM {
		if err := writeDir(tw, "/etc/opendkim/keys", res); err != nil {
			return nil, fmt.Errorf("dkim: %w", err)
		}
	}

	// ---- Let's Encrypt ----
	if opts.IncludeLetsEncrypt {
		if err := writeDir(tw, "/etc/letsencrypt", res); err != nil {
			return nil, fmt.Errorf("letsencrypt: %w", err)
		}
	}

	// ---- Maildirs ----
	if opts.IncludeMaildirs {
		if err := writeDir(tw, "/var/mail/vhosts", res); err != nil {
			return nil, fmt.Errorf("maildirs: %w", err)
		}
	}

	// Write manifest
	manifestJSON, _ := json.Marshal(res.Manifest)
	hdr := &tar.Header{
		Name:    "manifest.json",
		Mode:    0o600,
		Size:    int64(len(manifestJSON)),
		ModTime: time.Now(),
	}
	tw.WriteHeader(hdr)
	tw.Write(manifestJSON)

	tw.Close()
	gz.Close()
	f.Close()

	// Record size
	info, err := os.Stat(path)
	if err == nil {
		res.SizeBytes = info.Size()
	}
	res.Duration = time.Since(start)

	// Verify the archive is readable
	if err := verifyTarball(path); err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return res, nil
}

func writeDatabase(ctx context.Context, tw *tar.Writer, db *sql.DB, driver string, res *Result) error {
	var dump []byte
	var err error

	switch driver {
	case "sqlite":
		// For SQLite, just VACUUM INTO a temp file and add it.
		// Simpler: copy the file directly. But we want consistent backups,
		// so use the SQLite backup API via VACUUM INTO.
		tmp, ferr := os.CreateTemp("", "mailx-backup-*.db")
		if ferr != nil {
			return ferr
		}
		tmpPath := tmp.Name()
		tmp.Close()
		defer os.Remove(tmpPath)

		if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, tmpPath); err != nil {
			return fmt.Errorf("vacuum: %w", err)
		}
		dump, err = os.ReadFile(tmpPath)
		if err != nil {
			return err
		}

	case "postgres":
		// Use pg_dump
		cmd := exec.CommandContext(ctx, "pg_dump",
			"-h", "127.0.0.1",
			"-U", "mailx_admin",
			"--clean", "--if-exists",
			"mailx_admin")
		cmd.Env = append(os.Environ(), "PGPASSWORD="+os.Getenv("MAILX_DB_PASSWORD"))
		out, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("pg_dump: %w", err)
		}
		dump = out

	default:
		return fmt.Errorf("unsupported driver: %s", driver)
	}

	hdr := &tar.Header{
		Name:    fmt.Sprintf("database/state.%s", driver),
		Mode:    0o600,
		Size:    int64(len(dump)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(dump); err != nil {
		return err
	}

	res.Manifest = append(res.Manifest, "database/state."+driver)
	return nil
}

func writeDir(tw *tar.Writer, dir string, res *Result) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // skip missing dirs silently
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip files we can't read
		}
		rel, _ := filepath.Rel("/", path)

		// Skip sockets and other special files
		if info.Mode()&os.ModeSocket != 0 {
			return nil
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil
		}
		hdr.Name = rel

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		res.Manifest = append(res.Manifest, rel)

		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			_, _ = io.Copy(tw, f)
		}
		return nil
	})
}

func verifyTarball(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		_, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// List returns all backup tarballs on disk.
type Entry struct {
	Name       string
	Path       string
	SizeBytes  int64
	ModifiedAt time.Time
}

func List(dir string) ([]Entry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var out []Entry
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Entry{
			Name:       strings.TrimSuffix(e.Name(), ".tar.gz"),
			Path:       filepath.Join(dir, e.Name()),
			SizeBytes:  info.Size(),
			ModifiedAt: info.ModTime(),
		})
	}
	return out, nil
}

// Delete removes a backup tarball.
func Delete(dir, name string) error {
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		return fmt.Errorf("invalid backup name")
	}
	path := filepath.Join(dir, name+".tar.gz")
	return os.Remove(path)
}

// Restore extracts a backup tarball. This is a dangerous operation — the caller
// must confirm. We restore to a staging directory first, then the operator
// applies the configs manually (safer than auto-applying).
func Restore(ctx context.Context, tarballPath, targetDir string) (*Result, error) {
	if targetDir == "" {
		return nil, fmt.Errorf("target directory required")
	}
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return nil, err
	}

	f, err := os.Open(tarballPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var count int

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Reject absolute paths and traversal
		if filepath.IsAbs(hdr.Name) || strings.Contains(hdr.Name, "..") {
			return nil, fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}

		target := filepath.Join(targetDir, hdr.Name)
		if !strings.HasPrefix(target, targetDir) {
			return nil, fmt.Errorf("path escapes target: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return nil, err
			}
			out.Close()
		}
		count++
	}

	return &Result{Path: targetDir, Manifest: []string{fmt.Sprintf("%d entries", count)}}, nil
}
