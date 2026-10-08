package reconciler

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// dkimKeySpec is one path the OpenDKIM daemon needs owned by opendkim:opendkim:
// the private key file (mode 0600) or a directory on the way to it (mode 0750).
type dkimKeySpec struct {
	path string
	mode os.FileMode
	file bool
}

// planDKIMKeyOwnership lists the key files and the directory chain above them
// that must be owned by opendkim:opendkim. The daemon runs as that user and has
// to traverse into <opendkim>/keys/<domain> and read the private key; a 0750
// root:root directory is untraversable for it, which makes signing fail with
// "Permission denied" loading the key.
//
// The paths are in the server's namespace ("/etc/opendkim/keys/..."), never the
// build host's, so they use the slash-only `path` package rather than filepath
// (the same reason planMaildirs does).
func planDKIMKeyOwnership(snap *models.Snapshot) []dkimKeySpec {
	seen := map[string]bool{}
	var out []dkimKeySpec

	add := func(spec dkimKeySpec) {
		if spec.path == "" || seen[spec.path] {
			return
		}
		seen[spec.path] = true
		out = append(out, spec)
	}

	for _, d := range snap.Domains {
		if d.DKIMPrivateKeyPath == "" {
			continue
		}
		keyDir := path.Dir(d.DKIMPrivateKeyPath)
		// Shallowest first so a parent is fixed before its child.
		add(dkimKeySpec{path: path.Dir(keyDir), mode: 0o750})
		add(dkimKeySpec{path: keyDir, mode: 0o750})
		add(dkimKeySpec{path: d.DKIMPrivateKeyPath, mode: 0o600, file: true})
	}
	return out
}

// ensureDKIMKeyOwnership materialises the plan. Failures are warnings, never
// errors: by the time this runs the config files are already written and valid,
// and a panel that cannot chown must not roll the whole sync back.
func ensureDKIMKeyOwnership(ctx context.Context, snap *models.Snapshot) []string {
	owner := opendkimOwner()
	if owner == nil {
		return nil
	}

	var warnings []string
	for _, spec := range planDKIMKeyOwnership(snap) {
		if ctx.Err() != nil {
			return warnings
		}
		fi, err := os.Stat(spec.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("stat %s: %v", spec.path, err))
			continue
		}
		if fi.IsDir() == spec.file {
			// Wrong type for this entry (a file where a directory was expected
			// or vice versa); leave it alone.
			continue
		}
		if err := os.Chmod(spec.path, spec.mode); err != nil {
			warnings = append(warnings, fmt.Sprintf("chmod %s: %v", spec.path, err))
			continue
		}
		if err := os.Chown(spec.path, owner.UID, owner.GID); err != nil {
			warnings = append(warnings, fmt.Sprintf("chown %s: %v", spec.path, err))
		}
	}
	return warnings
}
