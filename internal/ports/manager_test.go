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

	const prefix = "smtpd_recipient_restrictions="
	i := strings.Index(out, prefix)
	if i < 0 {
		t.Fatalf("no recipient_restrictions line rendered:\n%s", out)
	}
	rest := out[i+len(prefix):]
	if end := strings.Index(rest, "\n"); end >= 0 {
		rest = rest[:end]
	}

	const want = "check_recipient_access hash:/etc/postfix/suppressions,permit_sasl_authenticated,reject"
	if rest != want {
		t.Fatalf("recipient_restrictions = %q, want %q", rest, want)
	}
}
