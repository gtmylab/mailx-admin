package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gtmylab/mailx-admin/internal/auth"
)

// permissionCatalog is the fixed set of granular permissions the group editor
// can toggle. Roles map to a default subset (roleGrants); a group layers extra
// grants on top of its own base role.
type permissionDef struct {
	Key   string
	Label string
}

var permissionCatalog = []permissionDef{
	{"admin.manage", "Manage admin users"},
	{"group.manage", "Manage groups"},
	{"sessions.manage", "Manage sessions"},
	{"settings.write", "Change system settings"},
	{"mail.manage", "Manage domains & users"},
	{"cron.manage", "Manage scheduled tasks"},
}

func allPermissionKeys() map[string]bool {
	m := make(map[string]bool, len(permissionCatalog))
	for _, p := range permissionCatalog {
		m[p.Key] = true
	}
	return m
}

// roleGrants returns the default permission set for a preset role. "admin" is
// full access today; "operator" gets the operational set; "readonly" (and
// anything unrecognised) gets none.
func roleGrants(role string) map[string]bool {
	switch role {
	case "superadmin", "admin":
		return allPermissionKeys()
	case "operator":
		return map[string]bool{"mail.manage": true, "cron.manage": true}
	default:
		return map[string]bool{}
	}
}

func parsePermissionJSON(raw string) []string {
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// hasPermission resolves a permission for a signed-in admin. Superadmins always
// pass; everyone else gets their own role defaults plus any extra grants from
// their assigned group (group base role + its explicit permission list).
func (s *Server) hasPermission(ctx context.Context, sess *auth.Session, perm string) bool {
	if sess == nil {
		return false
	}
	if sess.Role == "superadmin" {
		return true
	}
	grants := roleGrants(sess.Role)
	if u, err := s.store.GetAdminUser(ctx, sess.AdminUserID); err == nil && u != nil && u.GroupID > 0 {
		if g, err := s.store.GetAdminGroup(ctx, u.GroupID); err == nil && g != nil {
			for k, v := range roleGrants(g.Role) {
				if v {
					grants[k] = true
				}
			}
			for _, p := range parsePermissionJSON(g.Permissions) {
				grants[p] = true
			}
		}
	}
	return grants[perm]
}

// requirePermission guards a handler. On denial it answers a 403 page for a
// normal navigation and a form error for an HTMX fragment request, so callers
// can `if !s.requirePermission(w, r, "...") { return }`.
func (s *Server) requirePermission(w http.ResponseWriter, r *http.Request, perm string) bool {
	sess := auth.SessionFromContext(r.Context())
	if sess != nil && s.hasPermission(r.Context(), sess, perm) {
		return true
	}
	if r.Header.Get("HX-Request") != "" {
		s.renderFormError(w, "You do not have permission to do that")
		return false
	}
	s.renderError(w, http.StatusForbidden, "You do not have permission to do that")
	return false
}
