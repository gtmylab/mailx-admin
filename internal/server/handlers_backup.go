package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/backup"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultBackupDir = "/var/backups/mailx"

func (s *Server) handleBackupPage(w http.ResponseWriter, r *http.Request) {
	entries, err := backup.List(defaultBackupDir)
	if err != nil {
		s.renderError(w, 500, "Failed to list backups")
		return
	}

	// Sort newest first
	var recent []backup.Entry
	for i := len(entries) - 1; i >= 0; i-- {
		recent = append(recent, entries[i])
	}

	s.render(w, 200, "backup.html", s.newPageData(w, r, "Backups", "backup",
		map[string]any{
			"Backups": recent,
			"Dir":     defaultBackupDir,
		},
	))
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	opts := backup.Options{
		OutputDir:          defaultBackupDir,
		IncludeDatabase:    r.FormValue("include_database") == "on",
		IncludeConfigs:     r.FormValue("include_configs") == "on",
		IncludeDKIM:        r.FormValue("include_dkim") == "on",
		IncludeLetsEncrypt: r.FormValue("include_letsencrypt") == "on",
		IncludeMaildirs:    r.FormValue("include_maildirs") == "on",
	}

	if !opts.IncludeDatabase && !opts.IncludeConfigs && !opts.IncludeDKIM &&
		!opts.IncludeLetsEncrypt && !opts.IncludeMaildirs {
		s.renderFormError(w, "Select at least one item to back up")
		return
	}

	session := auth.SessionFromContext(r.Context())
	ctx := r.Context()

	// Insert a "running" row so the UI can show progress
	res, err := s.db.ExecContext(ctx, `
        INSERT INTO backups (name, path, kind, status)
        VALUES ('pending', '', 'manual', 'running')
    `)
	if err != nil {
		s.renderFormError(w, "Failed to start backup: "+err.Error())
		return
	}
	backupID, _ := res.LastInsertId()

	// Run synchronously (could be slow for Maildirs). For now, blocking is fine;
	// a background worker is a Phase 6 improvement.
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
		defer cancel()

		result, err := backup.Create(bgCtx, s.db, string(s.dbDriver), opts)
		if err != nil {
			s.db.Exec(`
                UPDATE backups SET status = 'error', error = ?, finished_at = ?
                WHERE id = ?
            `, err.Error(), time.Now(), backupID)
			s.auditor.Log(bgCtx, audit.Entry{
				Actor:  "admin:" + session.Username,
				Action: "backup.create",
				Result: "error",
				Detail: map[string]any{"error": err.Error()},
			})
			return
		}

		manifestJSON, _ := json.Marshal(result.Manifest)
		s.db.Exec(`
            UPDATE backups SET name = ?, path = ?, size_bytes = ?, status = 'ok',
                               finished_at = ?, manifest = ?
            WHERE id = ?
        `, result.Name, result.Path, result.SizeBytes, time.Now(), string(manifestJSON), backupID)

		s.auditor.Log(bgCtx, audit.Entry{
			Actor:  "admin:" + session.Username,
			Action: "backup.create",
			Result: "ok",
			Detail: map[string]any{
				"name": result.Name,
				"size": result.SizeBytes,
			},
		})
	}()

	w.Header().Set("HX-Redirect", "/backup?flash="+encodeFlash("Backup started"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		s.renderError(w, 400, "Invalid backup name")
		return
	}

	path := filepath.Join(defaultBackupDir, name+".tar.gz")
	f, err := os.Open(path)
	if err != nil {
		s.renderError(w, 404, "Backup not found")
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.tar.gz"`, name))
	if info != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	}
	http.ServeContent(w, r, name+".tar.gz", info.ModTime(), f)
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	session := auth.SessionFromContext(r.Context())

	if err := backup.Delete(defaultBackupDir, name); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	s.auditor.Log(r.Context(), audit.Entry{
		Actor:      "admin:" + session.Username,
		Action:     "backup.delete",
		TargetType: "backup",
		TargetID:   name,
		Result:     "ok",
		RemoteIP:   clientIP(r),
	})

	w.Header().Set("HX-Redirect", "/backup?flash="+encodeFlash("Backup deleted"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		s.renderError(w, 400, "Invalid backup name")
		return
	}

	src := filepath.Join(defaultBackupDir, name+".tar.gz")
	stagingDir := fmt.Sprintf("/var/backups/mailx/restore-%s", time.Now().Format("20060102-150405"))

	session := auth.SessionFromContext(r.Context())
	result, err := backup.Restore(r.Context(), src, stagingDir)
	if err != nil {
		s.auditor.Log(r.Context(), audit.Entry{
			Actor:      "admin:" + session.Username,
			Action:     "backup.restore",
			TargetType: "backup",
			TargetID:   name,
			Result:     "error",
			Detail:     map[string]any{"error": err.Error()},
			RemoteIP:   clientIP(r),
		})
		s.renderFormError(w, err.Error())
		return
	}

	s.auditor.Log(r.Context(), audit.Entry{
		Actor:      "admin:" + session.Username,
		Action:     "backup.restore",
		TargetType: "backup",
		TargetID:   name,
		Result:     "ok",
		Detail: map[string]any{
			"staging_dir": stagingDir,
		},
		RemoteIP: clientIP(r),
	})

	s.renderPartial(w, "backup_restore_result", map[string]any{
		"Name":       name,
		"StagingDir": stagingDir,
		"Result":     result,
	})
}
