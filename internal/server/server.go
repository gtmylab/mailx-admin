package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/config"
	"github.com/gtmylab/mailx-admin/internal/importer"
	"github.com/gtmylab/mailx-admin/internal/metrics"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/mutations"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/store"
	"github.com/gtmylab/mailx-admin/internal/syncer"
	"github.com/gtmylab/mailx-admin/internal/system"
	"github.com/gtmylab/mailx-admin/internal/update"
	"github.com/gtmylab/mailx-admin/internal/version"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html templates/partials/*.html static/* static/vendor/*
var assets embed.FS

type Server struct {
	cfg        *config.Config
	configPath string
	db         *sql.DB
	dbDriver   string
	store      *store.Store
	mutations  *mutations.Service
	rec        *reconciler.Reconciler
	syncer     *syncer.Syncer
	sessions   *auth.SessionStore
	csrf       *auth.CSRFManager
	auditor    *audit.Logger
	templates  *templateSet
	logger     *slog.Logger
	metrics    *metrics.Collector

	// updater checks for and applies releases. The cached status feeds the
	// update banner and the Updates page; updateMu guards updateState.
	updater     *update.Client
	updateMu    sync.RWMutex
	updateState update.Status

	// dbMigrateMu guards the state of an in-flight SQLite -> Postgres migration,
	// which runs in the background because a large mail_events table can take
	// minutes to copy.
	dbMigrateMu     sync.Mutex
	dbMigrateState  string // "running", "done", "error"
	dbMigrateErr    string
	dbMigrateTotal  int64
	dbMigrateTables int

	// importQueue runs background mail-import jobs, one at a time, and keeps
	// their live status for the Mail import page. Jobs live in memory for the
	// lifetime of the process.
	importQueue *importer.Queue

	// system samples host metrics (CPU/memory/disk/load) for the dashboard's
	// system-information panel.
	system *system.Sampler

	// packages caches the upgradable-package list and runs one apt update at a
	// time for the Software updates page.
	packages *packageUpdater

	// terminals holds the interactive SSH terminal sessions, keyed by admin.
	terminals *TerminalManager

	// startedAt and timeouts feed /healthz and /healthz/stacks: how long this
	// process has been serving, and the requests that ran out of budget (see
	// timeout.go) — the two facts needed to tell "the service is down" apart
	// from "every request is waiting for the same resource".
	startedAt time.Time
	timeouts  *timeoutLog

	// budgetOverride replaces the per-route request budget. Only the timeout
	// tests set it: they exercise the real middleware, and waiting 15s for a
	// read timeout would make the suite unusable.
	budgetOverride time.Duration
}

func New(cfg *config.Config, database *sql.DB, st *store.Store, rec *reconciler.Reconciler, logger *slog.Logger, configPath string) (*Server, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	// Load (or generate) CSRF key from settings
	var csrfKey []byte
	var stored string
	err = database.QueryRow(`SELECT value FROM settings WHERE key = 'csrf_key'`).Scan(&stored)
	if err == sql.ErrNoRows {
		csrfKey = make([]byte, 32)
		_, _ = rand.Read(csrfKey)
		_, _ = database.Exec(`INSERT INTO settings (key, value) VALUES ('csrf_key', ?)`,
			base64.StdEncoding.EncodeToString(csrfKey))
	} else if err == nil {
		csrfKey, _ = base64.StdEncoding.DecodeString(stored)
	}

	aud := audit.New(database)
	// The syncer owns the config sync. It never touches disk inside a request:
	// mutations queue a run, and the run reports back through reconcile_runs.
	sync := syncer.New(database, st, rec, logger)
	mut := mutations.New(database, st, rec, aud, cfg.Server.Hostname, sync,
		mutations.NewRoundcubeSeeder(cfg.Roundcube))

	sys := system.NewSampler()
	sys.Start()

	return &Server{
		cfg:         cfg,
		configPath:  configPath,
		db:          database,
		dbDriver:    cfg.DB.Driver,
		store:       st,
		mutations:   mut,
		rec:         rec,
		syncer:      sync,
		sessions:    auth.NewSessionStore(database),
		csrf:        auth.NewCSRFManager(csrfKey),
		auditor:     aud,
		templates:   tmpl,
		logger:      logger,
		metrics:     metrics.New(database, cfg.Server.Hostname, version.Get()),
		updater:     update.NewClient(),
		importQueue: importer.NewQueue(),
		system:      sys,
		packages:    newPackageUpdater(),
		terminals:   NewTerminalManager(),
		startedAt:   time.Now(),
		timeouts:    newTimeoutLog(timeoutHistory),
	}, nil
}

// templateSet holds the parsed templates.
//
// Every layout page gets its own *template.Template containing layout.html,
// the shared partials and that one page. That is required because all pages
// define "content": inside a single shared set the last parsed page would win
// and every page would render the same body (which is exactly the bug this
// type fixes -- previously pages rendered as empty output).
//
// HTMX fragments share one set. It also contains the page files, because some
// fragments (user_table, audit_table, queue_table, ...) are defined inside them.
type templateSet struct {
	pages     map[string]*template.Template
	fragments *template.Template
}

// execute renders a page (wrapped in layout.html) or a bare HTMX fragment.
// layout.html is executed through its "layout" define: the file itself only
// contains {{define}} blocks, so its file-level body is empty.
func (t *templateSet) execute(w io.Writer, name string, data any) error {
	if set, ok := t.pages[name]; ok {
		return set.ExecuteTemplate(w, "layout", data)
	}
	return t.fragments.ExecuteTemplate(w, name, data)
}

// has reports whether name can be rendered, either as a page or a fragment.
func (t *templateSet) has(name string) bool {
	if _, ok := t.pages[name]; ok {
		return true
	}
	return t.fragments.Lookup(name) != nil
}

// pageNames returns the registered page template names, sorted.
func (t *templateSet) pageNames() []string {
	names := make([]string, 0, len(t.pages))
	for name := range t.pages {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// asTime converts the time-ish values templates hand to humanTime.
func asTime(v any) (time.Time, bool) {
	switch tv := v.(type) {
	case time.Time:
		return tv, true
	case *time.Time:
		if tv == nil {
			return time.Time{}, false
		}
		return *tv, true
	case sql.NullTime:
		if !tv.Valid {
			return time.Time{}, false
		}
		return tv.Time, true
	}
	return time.Time{}, false
}

// isEmptyValue reports whether v is empty, mirroring sprig's default helper:
// nil, zero numbers, empty strings/slices/maps and nil pointers/interfaces.
func isEmptyValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return rv.Len() == 0
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return rv.IsNil()
	}
	return false
}

func parseTemplates() (*templateSet, error) {
	const (
		layoutFile  = "templates/layout.html"
		partialGlob = "templates/partials/*.html"
	)

	funcs := template.FuncMap{
		// humanTime accepts both time.Time and *time.Time, because model fields
		// like models.User.LastLogin are pointers (nil = never logged in).
		"humanTime": func(v any) string {
			t, ok := asTime(v)
			if !ok {
				return "never"
			}
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return fmt.Sprintf("%dm ago", int(d.Minutes()))
			case d < 24*time.Hour:
				return fmt.Sprintf("%dh ago", int(d.Hours()))
			default:
				return fmt.Sprintf("%dd ago", int(d.Hours()/24))
			}
		},
		"percent": func(n, d int) int {
			if d == 0 {
				return 0
			}
			return n * 100 / d
		},
		"statusClass": func(s string) string {
			switch s {
			case "ok", "active", "running":
				return "ok"
			case "error", "failed", "inactive":
				return "err"
			default:
				return "warn"
			}
		},
		"dict": func(values ...any) map[string]any {
			if len(values)%2 != 0 {
				panic("dict requires even number of args")
			}
			m := make(map[string]any, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				k, ok := values[i].(string)
				if !ok {
					panic("dict keys must be strings")
				}
				m[k] = values[i+1]
			}
			return m
		},

		// default mirrors sprig's helper: `{{ .X | default "fallback" }}`.
		// The fallback comes first so it works as the last pipeline argument.
		"default": func(fallback any, values ...any) any {
			for _, v := range values {
				if !isEmptyValue(v) {
					return v
				}
			}
			return fallback
		},

		"slice": func(s string, start, end int) string {
			if start < 0 {
				start = 0
			}
			if end > len(s) {
				end = len(s)
			}
			if start > end {
				return ""
			}
			return s[start:end]
		},

		"humanBytes": func(n int64) string {
			const unit = 1024
			if n < unit {
				return fmt.Sprintf("%d B", n)
			}
			div, exp := int64(unit), 0
			for x := n / unit; x >= unit; x /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
		},

		"sieveRuleSummary": func(r models.SieveRule) string {
			var cfg map[string]any
			_ = json.Unmarshal(r.Config, &cfg)
			switch r.RuleType {
			case "vacation":
				return fmt.Sprintf("Reply: %q for %v days", cfg["subject"], cfg["days"])
			case "forward":
				keep := ""
				if cfg["keep_copy"] == true {
					keep = " (keep copy)"
				}
				return fmt.Sprintf("Forward to %v%s", cfg["address"], keep)
			case "move_folder":
				return fmt.Sprintf("If %v contains %q → %v",
					cfg["match_header"], cfg["match_contains"], cfg["folder"])
			case "discard":
				return fmt.Sprintf("Discard if %v contains %q",
					cfg["match_header"], cfg["match_contains"])
			case "mark_read":
				return fmt.Sprintf("Mark read if %v contains %q",
					cfg["match_header"], cfg["match_contains"])
			}
			return r.RuleType
		},
	}

	// Walk the embedded FS, splitting page files from partials.
	var pageFiles, partialFiles []string
	err := fs.WalkDir(assets, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		if strings.Contains(p, "/partials/") {
			partialFiles = append(partialFiles, p)
			return nil
		}
		pageFiles = append(pageFiles, p)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Fragment set: the partials plus the page files (which also define the
	// inline fragments handlers swap in over HTMX).
	fragmentFiles := make([]string, 0, len(partialFiles)+len(pageFiles))
	fragmentFiles = append(fragmentFiles, partialFiles...)
	fragmentFiles = append(fragmentFiles, pageFiles...)

	fragments, err := template.New("fragments").Funcs(funcs).ParseFS(assets, fragmentFiles...)
	if err != nil {
		return nil, fmt.Errorf("parse fragments: %w", err)
	}

	// One set per layout page: layout.html + partials + that page, so the
	// {{template "content" .}} call in layout.html resolves to this page.
	pages := make(map[string]*template.Template, len(pageFiles))
	for _, file := range pageFiles {
		name := path.Base(file)
		switch name {
		case "layout.html", // shell, included in every page set below
			"login.html": // standalone document, rendered without the shell
			continue
		}

		set, err := template.New(name).Funcs(funcs).
			ParseFS(assets, layoutFile, partialGlob, file)
		if err != nil {
			return nil, fmt.Errorf("parse page %s: %w", name, err)
		}
		if set.Lookup("content") == nil {
			continue // not a layout page
		}
		pages[name] = set
	}

	return &templateSet{pages: pages, fragments: fragments}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	mux := s.buildRouter()

	// The config sync runs in the background: every mutation only queues a run,
	// so no request ever waits for postmap or a service reload again.
	s.syncer.Start(ctx)
	go s.periodicUpdateCheck(ctx)
	// Converge once at startup. After an upgrade or a hand-edited file the
	// panel's files and the database can disagree, and a run at boot is what
	// makes the dashboard's very first status honest.
	s.syncer.Request("system:startup")

	srv := &http.Server{
		Addr:              s.cfg.Server.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// No WriteTimeout on purpose. It used to be 60s "because SSE needs
		// longer", which is backwards twice over: the SSE pings are 5s apart so
		// they fit in any budget, while a 5 GB backup download from the Backups
		// page was cut off mid-transfer after a minute. Long-lived routes are
		// bounded by their own context instead (see timeout.go: streams and
		// downloads are exempt from the request budget, and Apache still has a
		// 60s upstream timeout for the requests that matter).
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server listening", "addr", s.cfg.Server.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Periodic session cleanup
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return srv.Shutdown(shutdownCtx)

		case err := <-errCh:
			return err

		case <-ticker.C:
			if n, err := s.sessions.CleanupExpired(ctx); err != nil {
				s.logger.Warn("session cleanup failed", "err", err)
			} else if n > 0 {
				s.logger.Info("cleaned up expired sessions", "count", n)
			}
		}
	}
}
