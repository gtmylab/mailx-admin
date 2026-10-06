package server

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"text/template/parse"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// pageTemplateNames are the layout pages referenced by handlers via render().
var pageTemplateNames = []string{
	"error.html",
	"dashboard.html",
	"users.html",
	"user_detail.html",
	"domains.html",
	"domain_detail.html",
	"domain_dns.html",
	"audit.html",
	"logs.html",
	"ssl.html",
	"ports.html",
	"queue.html",
	"backup.html",
	"testsend.html",
	"updates.html",
	"database.html",
	"mail_import.html",
	"user_sieve.html",
}

// fragmentTemplateNames are the HTMX fragments referenced by handlers via
// renderPartial().
var fragmentTemplateNames = []string{
	"user_table",
	"user_form",
	"password_form",
	"password_reveal",
	"domain_form",
	"preview_diff",
	"form_error",
	"audit_table",
	"log_rows",
	"log_queue_detail",
	"service_health",
	"dns_check_results",
	"ssl_details",
	"ssl_renew_result",
	"ssl_settings_saved",
	"port_form",
	"port_preview",
	"queue_table",
	"backup_restore_result",
	"testsend_result",
	"testsend_history",
	"sieve_rule_form",
	"update_status",
	"update_result",
	"database_test_result",
	"database_migrate_result",
	"mail_import_result",
}

func newTestServer(t *testing.T, tmpl *templateSet) *Server {
	t.Helper()
	return &Server{
		templates: tmpl,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestTemplatesParseAndDefineEveryName(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	for _, name := range pageTemplateNames {
		if _, ok := tmpl.pages[name]; !ok {
			t.Errorf("page template %q is not registered; a handler rendering it would 500 (registered: %v)",
				name, tmpl.pageNames())
		}
	}

	for _, name := range append(append([]string{}, fragmentTemplateNames...), "login.html") {
		if !tmpl.has(name) {
			t.Errorf("template %q is not defined; a handler rendering it would 500", name)
		}
	}
}

// TestEveryPageSetWrapsItsOwnContent guards the layout wiring: each page needs
// its own template set, otherwise the last "content" defined wins the name and
// every page renders the same (or an empty) body.
func TestEveryPageSetWrapsItsOwnContent(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	for name, set := range tmpl.pages {
		for _, required := range []string{"layout", "content", "sidebar", "nav-item"} {
			if set.Lookup(required) == nil {
				t.Errorf("page set %q is missing template %q", name, required)
			}
		}
	}
}

type templateCall struct{ from, name string }

// TestEveryTemplateCallResolves catches dangling {{template "..."}} references
// such as the sidebar's nav-item. html/template only reports those when the
// template is executed, so nothing else fails the build over them.
func TestEveryTemplateCallResolves(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	sets := map[string]*template.Template{"fragment set": tmpl.fragments}
	for name, set := range tmpl.pages {
		sets["page set "+name] = set
	}
	if len(sets) < 2 {
		t.Fatal("no page template sets were built")
	}

	for label, set := range sets {
		for _, call := range templateCalls(set) {
			if set.Lookup(call.name) == nil {
				t.Errorf("%s: %s references undefined template %q", label, call.from, call.name)
			}
		}
	}
}

// templateCalls returns every {{template "name"}} call found in the set.
func templateCalls(set *template.Template) []templateCall {
	var calls []templateCall
	for _, tmpl := range set.Templates() {
		if tmpl.Tree == nil || tmpl.Tree.Root == nil {
			continue
		}
		for _, node := range walkNodes(tmpl.Tree.Root) {
			if tn, ok := node.(*parse.TemplateNode); ok {
				calls = append(calls, templateCall{from: tmpl.Name(), name: tn.Name})
			}
		}
	}
	return calls
}

func walkNodes(n parse.Node) []parse.Node {
	out := []parse.Node{n}
	switch node := n.(type) {
	case *parse.ListNode:
		for _, child := range node.Nodes {
			out = append(out, walkNodes(child)...)
		}
	case *parse.IfNode:
		out = append(out, walkBranch(&node.BranchNode)...)
	case *parse.RangeNode:
		out = append(out, walkBranch(&node.BranchNode)...)
	case *parse.WithNode:
		out = append(out, walkBranch(&node.BranchNode)...)
	}
	return out
}

func walkBranch(b *parse.BranchNode) []parse.Node {
	var out []parse.Node
	if b.List != nil {
		out = append(out, walkNodes(b.List)...)
	}
	if b.ElseList != nil {
		out = append(out, walkNodes(b.ElseList)...)
	}
	return out
}

// logRow mirrors the anonymous struct handleLogQueueDetail builds for the
// log_queue_detail template.
type logRow struct {
	ID                                         int64
	Ts                                         time.Time
	Service, Action, Status, From, To, Message string
}

// TestPagesRenderThroughLayout executes pages from static data end to end, so
// layout.html, the sidebar and the nav items are exercised too.
func TestPagesRenderThroughLayout(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)

	lastLogin := time.Now().Add(-2 * time.Hour)

	cases := []struct {
		name     string
		status   int
		page     string
		data     any
		wants    []string
		notWants []string
	}{
		{
			name:   "error page without session",
			status: http.StatusNotFound,
			page:   "error.html",
			data: pageData{
				Title: "Error 404",
				Data:  map[string]any{"Status": 404, "Message": "User not found"},
			},
			wants: []string{
				"<!DOCTYPE html>",
				"User not found",
				"404",
				"Dashboard", // sidebar rendered
				`href="/users"`,
			},
		},
		{
			name:   "login page is standalone",
			status: http.StatusOK,
			page:   "login.html",
			data:   map[string]any{"Error": "Invalid credentials", "TOTPRequired": false},
			wants:  []string{"<!DOCTYPE html>", "Sign in", `name="username"`, `name="password"`, "Invalid credentials"},
			// login.html must not be wrapped in the admin shell
			notWants: []string{`id="toast-host"`, `action="/logout"`},
		},
		{
			name:   "users page",
			status: http.StatusOK,
			page:   "users.html",
			data: pageData{
				Title:     "Users",
				ActiveNav: "users",
				Data: map[string]any{
					"Total": 2,
					"Query": "",
					"Users": []models.User{
						{
							ID: 7, DomainID: 1, Username: "admin", Email: "admin@example.com",
							DomainName: "example.com", QuotaMB: 1024, Active: true,
							IsAdmin: true, LastLogin: &lastLogin,
						},
						{
							ID: 8, DomainID: 1, Username: "sales", Email: "sales@example.com",
							DomainName: "example.com", QuotaMB: 256, Active: false,
						},
					},
				},
			},
			wants: []string{
				"<!DOCTYPE html>",
				"2 user(s)",
				"admin@example.com",
				"sales@example.com",
				"1024 MB",
				"2h ago", // humanTime with a *time.Time LastLogin
				"never",  // user without a LastLogin
				"disabled",
				`href="/users/7"`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.render(rec, tc.status, tc.page, tc.data)

			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.status, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", ct)
			}

			body := rec.Body.String()
			if body == "" {
				t.Fatal("rendered no output")
			}
			for _, want := range tc.wants {
				if !strings.Contains(body, want) {
					t.Errorf("output does not contain %q\n---\n%s", want, body)
				}
			}
			for _, unwanted := range tc.notWants {
				if strings.Contains(body, unwanted) {
					t.Errorf("output unexpectedly contains %q", unwanted)
				}
			}
		})
	}
}

func TestTemplatesExecuteWithHandlerData(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	now := time.Now()

	cases := []struct {
		name string
		data any
	}{
		{"domain_form", map[string]any{"Domain": nil}},
		{"ssl_settings_saved", map[string]any{"Message": "Test notification sent to admin@example.com"}},
		{"form_error", map[string]any{"Error": "boom"}},
		{"nav-item", map[string]any{"Href": "/users", "Label": "Users", "Active": true}},
		{"modal", map[string]any{"Title": "Confirm"}}, // exercises `default` + modal_body
		{"log_queue_detail", map[string]any{
			"QueueID": "ABC123",
			"Events": []logRow{{
				ID: 1, Ts: now, Service: "postfix/smtp", Action: "sent",
				Status: "sent", From: "a@example.com", To: "b@example.org",
				Message: "250 2.0.0 Ok: queued as ABC123",
			}},
		}},
	}

	for _, tc := range cases {
		var buf bytes.Buffer
		if err := tmpl.execute(&buf, tc.name, tc.data); err != nil {
			t.Errorf("execute %q: %v", tc.name, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("execute %q: produced no output", tc.name)
		}
	}

	// The modal shell must fall back to its default width class when the
	// caller does not pass one.
	var buf bytes.Buffer
	if err := tmpl.execute(&buf, "modal", map[string]any{"Title": "Confirm"}); err != nil {
		t.Fatalf("execute modal: %v", err)
	}
	if !strings.Contains(buf.String(), "max-w-md") {
		t.Errorf("modal default width missing:\n%s", buf.String())
	}
}

var (
	// templateURLRe finds every URL templates ask the browser or HTMX to fetch,
	// together with the attribute that determines the request method.
	templateURLRe = regexp.MustCompile(`(hx-get|hx-post|hx-put|hx-patch|hx-delete|href|action)="(/[^"]*)"`)
	// templateExprRe matches a {{...}} action so it can stand in for a wildcard.
	templateExprRe = regexp.MustCompile(`\{\{[^}]*\}\}`)
	// routeDeclRe extracts the ServeMux patterns registered in router.go.
	routeDeclRe = regexp.MustCompile(`(?:HandleFunc|Handle)\(\s*"(?:([A-Z]+) )?([^"\s]*)"`)
)

// httpMethod maps a template attribute to the method the request will use.
// Forms in this app always post, so action= means POST.
func httpMethod(attr string) string {
	switch attr {
	case "hx-get", "href":
		return http.MethodGet
	case "hx-post", "action":
		return http.MethodPost
	case "hx-put":
		return http.MethodPut
	case "hx-patch":
		return http.MethodPatch
	case "hx-delete":
		return http.MethodDelete
	}
	return ""
}

// registeredRoutes parses router.go for the patterns buildRouter registers.
// Method-less patterns (the /static/ file server) match any method; the bare
// "/" pattern is skipped because it is just the auth wrapper around the
// protected mux and would match everything.
func registeredRoutes(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	var routes []string
	for _, m := range routeDeclRe.FindAllStringSubmatch(string(src), -1) {
		method, pattern := m[1], m[2]
		if pattern == "/" && method == "" {
			// mux.Handle("/", auth.RequireAuth(protected)) is the auth wrapper
			// around the protected mux; matching it would accept anything.
			continue
		}
		if method == "" {
			method = "*"
		}
		routes = append(routes, method+" "+pattern)
	}
	if len(routes) == 0 {
		t.Fatal("no routes parsed out of router.go; the extractor regex is stale")
	}
	return routes
}

// routePatternRe converts a ServeMux pattern into a regexp: {name} matches one
// path segment and a trailing slash makes the pattern a subtree match, exactly
// like net/http's ServeMux.
func routePatternRe(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); {
		if pattern[i] == '{' {
			if j := strings.IndexByte(pattern[i:], '}'); j >= 0 {
				b.WriteString("[^/]+")
				i += j + 1
				continue
			}
		}
		b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		i++
	}
	if strings.HasSuffix(pattern, "/") {
		b.WriteString(".*$")
	} else {
		b.WriteString("$")
	}
	return regexp.MustCompile(b.String())
}

func anyRouteMatches(routes []string, method, path string) bool {
	for _, route := range routes {
		m, pattern, _ := strings.Cut(route, " ")
		if m != "*" && m != method {
			continue
		}
		if routePatternRe(pattern).MatchString(path) {
			return true
		}
	}
	return false
}

// TestTemplateRoutesAreRegistered catches links and HTMX requests pointing at
// URLs the router does not serve. Such a typo does not 404: it falls through
// to the catch-all "GET /" pattern, which swaps a whole dashboard page into the
// fragment slot it targeted (that is how hx-get="/toast" in layout.html and
// hx-get="/health/services" in dashboard.html were both broken).
func TestTemplateRoutesAreRegistered(t *testing.T) {
	routes := registeredRoutes(t)

	type target struct{ method, url string }
	var targets []target
	err := fs.WalkDir(assets, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		src, err := fs.ReadFile(assets, p)
		if err != nil {
			return err
		}
		for _, m := range templateURLRe.FindAllStringSubmatch(string(src), -1) {
			targets = append(targets, target{httpMethod(m[1]), m[2]})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
	if len(targets) == 0 {
		t.Fatal("no template URLs found; the extractor regex is stale")
	}

	var problems []string
	for _, tg := range targets {
		path := tg.url
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		// A {{...}} segment is as good as a wildcard segment: the handler is
		// free to build any ID into it.
		path = templateExprRe.ReplaceAllString(path, "x")
		if !anyRouteMatches(routes, tg.method, path) {
			problems = append(problems, fmt.Sprintf("%s %s", tg.method, tg.url))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		for _, p := range problems {
			t.Errorf("no route registered for %s", p)
		}
	}
}
