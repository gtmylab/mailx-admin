package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
)

func (s *Server) handleGroupsPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "group.manage") {
		return
	}
	groups, err := s.store.ListAdminGroups(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load groups")
		return
	}
	s.render(w, 200, "groups.html", s.newPageData(w, r, "Groups", "groups", map[string]any{
		"Groups": groups,
	}))
}

func (s *Server) handleGroupNew(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "group.manage") {
		return
	}
	s.renderGroupForm(w, r, models.AdminGroup{Role: "readonly", Permissions: "[]"})
}

func (s *Server) handleGroupEdit(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "group.manage") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid group ID")
		return
	}
	g, err := s.store.GetAdminGroup(r.Context(), id)
	if err != nil || g == nil {
		s.renderError(w, 404, "Group not found")
		return
	}
	s.renderGroupForm(w, r, *g)
}

func (s *Server) renderGroupForm(w http.ResponseWriter, r *http.Request, g models.AdminGroup) {
	permSet := map[string]bool{}
	for _, p := range parsePermissionJSON(g.Permissions) {
		permSet[p] = true
	}
	s.renderPartial(w, "group_form", map[string]any{
		"Group":       g,
		"Roles":       adminRoles,
		"Permissions": permissionCatalog,
		"PermSet":     permSet,
	})
}

func (s *Server) handleGroupSave(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "group.manage") {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	role := r.FormValue("role")
	if name == "" {
		s.renderFormError(w, "Group name is required")
		return
	}
	if !containsStr(adminRoles, role) {
		role = "readonly"
	}

	perms := []string{}
	for _, p := range permissionCatalog {
		if r.FormValue("perm_"+p.Key) == "1" {
			perms = append(perms, p.Key)
		}
	}
	permsJSON, _ := json.Marshal(perms)

	ctx := r.Context()
	sess := auth.SessionFromContext(ctx)
	action := "group.create"

	if idStr := r.FormValue("id"); idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.renderFormError(w, "Invalid group ID")
			return
		}
		if err := s.store.UpdateAdminGroup(ctx, models.AdminGroup{
			ID: id, Name: name, Role: role, Permissions: string(permsJSON),
		}); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				s.renderFormError(w, "Group name already exists")
				return
			}
			s.renderFormError(w, err.Error())
			return
		}
		action = "group.update"
	} else {
		if _, err := s.store.InsertAdminGroup(ctx, models.AdminGroup{
			Name: name, Role: role, Permissions: string(permsJSON),
		}); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				s.renderFormError(w, "Group name already exists")
				return
			}
			s.renderFormError(w, err.Error())
			return
		}
	}

	_ = s.auditor.Log(ctx, audit.Entry{
		Actor: "admin:" + sess.Username, Action: action, TargetType: "admin_group",
		TargetID: name, Result: "ok", RemoteIP: clientIP(r),
	})
	w.Header().Set("HX-Redirect", "/system/groups?flash="+encodeFlash("Saved \""+name+"\""))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "group.manage") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid group ID")
		return
	}
	if err := s.store.DeleteAdminGroup(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/system/groups?flash="+encodeFlash("Group removed"))
	w.WriteHeader(http.StatusOK)
}
