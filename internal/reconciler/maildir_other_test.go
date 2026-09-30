//go:build !unix

package reconciler

import (
	"strings"
	"testing"
)

// The panel's tests run on workstations; the maildir pass must not pretend to
// have created a directory it cannot own there.
func TestCreateDirRefusesWithoutOwnershipControl(t *testing.T) {
	err := createDir(maildirSpec{path: "/var/mail/vhosts/example.com/alice/Maildir", uid: 5000, gid: 5000, mode: 0o700})
	if err == nil {
		t.Fatal("createDir succeeded on a platform without chown; a directory nobody owns delivers nowhere")
	}
	if !strings.Contains(err.Error(), "ownership") {
		t.Errorf("error should say why: %v", err)
	}
}

// claimDir has no ownership to re-apply here, so an existing directory is
// accepted as it is instead of producing a warning on every sync.
func TestClaimDirIsNoOpWithoutOwnershipControl(t *testing.T) {
	if err := claimDir(maildirSpec{path: t.TempDir(), uid: 5000, gid: 5000}); err != nil {
		t.Fatalf("claimDir: %v", err)
	}
}
