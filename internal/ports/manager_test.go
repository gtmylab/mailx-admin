package ports

import (
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// TestRenderListenerChecksSuppressionsBeforePermit locks in the Postfix
// restriction ordering: check_recipient_access must run before
// permit_sasl_authenticated. If permit_sasl_authenticated came first, any
// authenticated sender would be accepted before the suppression map is
// consulted, silently defeating the outbound suppression feature.
func TestRenderListenerChecksSuppressionsBeforePermit(t *testing.T) {
	out := renderListener(models.PortListener{
		Port:        2525,
		TLSMode:     "may",
		RequireSASL: true,
	})

	// The value contains a space ("check_recipient_access <map>"), which the
	// short -o form cannot express and double quotes do NOT protect in master.cf.
	// It must use the { } long form, and check_recipient_access must come before
	// permit_sasl_authenticated for the suppression check to actually run.
	const want = "  -o { smtpd_recipient_restrictions = check_recipient_access hash:/etc/postfix/suppressions,permit_sasl_authenticated,reject }"
	if !strings.Contains(out, want) {
		t.Fatalf("rendered listener missing { } recipient_restrictions:\n%s", out)
	}
}
