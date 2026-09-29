package server

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/queue"
	"github.com/gtmylab/mailx-admin/internal/smtp"
)

// The panel must work on a host without outbound internet access: servers in
// this product's target environments (mail relays, firewalled VPSes) routinely
// block the CDN that layout.html used to load htmx from, and every hx-*
// attribute silently stops working when that fetch fails. Everything a page
// needs therefore ships in the binary.
//
// The test walks every <script src> and <link href> of the standalone
// documents, requires them to point into /static/, and checks that the file
// they name is actually embedded (a typo would 404 at runtime, and the mini
// app.css that shipped in v1.0.3 is exactly what made the UI look broken).
func TestLayoutUsesOnlyLocalAssets(t *testing.T) {
	documents := []string{"templates/layout.html", "templates/login.html"}

	assetRefRe := regexp.MustCompile(`<(?:script|link)\b[^>]*\b(?:src|href)="([^"]*)"`)
	// Go's regexp (RE2) has no lookahead, so inline scripts are found by
	// matching every <script ...> tag and checking it for a src attribute.
	scriptTagRe := regexp.MustCompile(`<script\b[^>]*>`)

	seen := 0
	for _, doc := range documents {
		src, err := fs.ReadFile(assets, doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		body := string(src)

		for _, m := range assetRefRe.FindAllStringSubmatch(body, -1) {
			ref := m[1]
			seen++
			switch {
			case strings.HasPrefix(ref, "http://"), strings.HasPrefix(ref, "https://"), strings.HasPrefix(ref, "//"):
				t.Errorf("%s loads %q from a remote host; vendor it into static/ instead", doc, ref)
				continue
			case !strings.HasPrefix(ref, "/static/"):
				t.Errorf("%s references %q, which is not served from /static/", doc, ref)
				continue
			}
			path := strings.TrimPrefix(strings.SplitN(ref, "?", 2)[0], "/")
			if _, err := fs.Stat(assets, path); err != nil {
				t.Errorf("%s references %q but %q is not embedded: %v", doc, ref, path, err)
			}
		}

		// Inline <script> bodies cannot be cached, tested or reused, and they
		// were how the CSRF fix-up and the flash-to-toast bridge drifted apart
		// per page. Everything lives in /static/app.js.
		for _, tag := range scriptTagRe.FindAllString(body, -1) {
			if !strings.Contains(tag, "src=") {
				t.Errorf("%s has an inline <script> tag (%s); move the code into /static/app.js", doc, tag)
			}
		}
	}

	if seen == 0 {
		t.Fatalf("no asset references found in %v; the extractor regex is stale", documents)
	}

	// The assets the shell cannot work without.
	for _, path := range []string{
		"static/app.css",
		"static/app.js",
		"static/vendor/htmx.min.js",
	} {
		info, err := fs.Stat(assets, path)
		if err != nil {
			t.Errorf("%s is missing from the embedded assets: %v", path, err)
			continue
		}
		if info.Size() < 512 {
			t.Errorf("%s is suspiciously small (%d bytes); the vendor download probably failed", path, info.Size())
		}
	}
	// The icon is small by nature, so only its presence is checked.
	if _, err := fs.Stat(assets, "static/favicon.svg"); err != nil {
		t.Errorf("static/favicon.svg is missing from the embedded assets: %v", err)
	}
}

// TestStaticAssetsAreServed wires the same file server router.go installs and
// fetches the assets the browser asks for. Unit tests above prove the files
// exist in the embed; this proves the /static/ route actually hands them out
// with a sensible content type, which is what made the v1.0.3 panel render
// unstyled (a 200 with an empty or truncated stylesheet looks exactly like a
// broken CSS file in the browser).
func TestStaticAssetsAreServed(t *testing.T) {
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cases := []struct {
		path        string
		contentType string
		minBytes    int
		wants       []string
	}{
		{"/static/app.css", "text/css", 20000, []string{
			"--brand:", ".sidebar", ".nav-link", ".modal-panel", ".btn-primary",
			".table-stack", ".badge", "@media (max-width: 1023px)", "@media print",
		}},
		{"/static/app.js", "javascript", 10000, []string{
			"mailx_csrf", "htmx:configRequest", "closeModal", "data-live-tail",
		}},
		{"/static/vendor/htmx.min.js", "javascript", 10000, nil},
		{"/static/favicon.svg", "image/svg", 100, nil},
	}

	for _, tc := range cases {
		resp, err := http.Get(srv.URL + tc.path)
		if err != nil {
			t.Errorf("GET %s: %v", tc.path, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", tc.path, resp.StatusCode)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, tc.contentType) {
			t.Errorf("GET %s Content-Type = %q, want %q", tc.path, ct, tc.contentType)
		}
		if len(body) < tc.minBytes {
			t.Errorf("GET %s returned %d bytes, want at least %d (truncated asset?)",
				tc.path, len(body), tc.minBytes)
			continue
		}
		for _, want := range tc.wants {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s does not contain %q", tc.path, want)
			}
		}
	}
}

var (
	// templateActionRe matches a {{...}} action, quotes included.
	templateActionRe = regexp.MustCompile(`\{\{(?:[^"}]|"[^"]*")*\}\}`)
	// classAttrRe extracts the value of a class attribute.
	classAttrRe = regexp.MustCompile(`class="([^"]*)"`)
	// classTokenRe matches a plausible CSS class name.
	classTokenRe = regexp.MustCompile(`^[A-Za-z0-9_:.\-\\\[\]/]+$`)
	// cssClassRe matches a class selector in app.css, including escaped
	// characters such as ".py-0\.5" and ".max-w-\[200px\]".
	cssClassRe = regexp.MustCompile(`\.([A-Za-z_][A-Za-z0-9_-]*(?:\\.[A-Za-z0-9_-]*)*)`)
)

// TestTemplateClassesAreStyled is the regression guard for the v1.0.3 UI
// breakage: app.css defined ~92 of the ~202 class names the templates use, so
// the sidebar rendered as plain inline links, dialogs appeared unstyled at the
// bottom of the page and buttons looked inert. Any class name a template uses
// now has to resolve to a rule in app.css.
func TestTemplateClassesAreStyled(t *testing.T) {
	css, err := fs.ReadFile(assets, "static/app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}

	defined := map[string]bool{}
	for _, m := range cssClassRe.FindAllSubmatch(css, -1) {
		defined[strings.ReplaceAll(string(m[1]), `\`, "")] = true
	}
	if len(defined) < 100 {
		t.Fatalf("only %d class rules parsed out of app.css; the extractor regex is stale", len(defined))
	}

	used := map[string][]string{} // class -> files using it
	err = fs.WalkDir(assets, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		src, err := fs.ReadFile(assets, p)
		if err != nil {
			return err
		}
		// Strip {{...}} actions first, including the ones containing quoted
		// strings ({{if eq .Kind "x"}}), so a class attribute cannot be cut in
		// half by a quote inside a template action. The replacement is a NUL
		// marker, not a space: a name assembled from static text and an action
		// (class="text-{{if ...}}emerald{{end}}-400") must stay one token so it
		// can be recognised as dynamic and skipped instead of being reported
		// as three bogus classes.
		stripped := templateActionRe.ReplaceAll(src, []byte("\x00"))
		for _, m := range classAttrRe.FindAllSubmatch(stripped, -1) {
			for _, tok := range strings.Fields(string(m[1])) {
				if strings.ContainsRune(tok, '\x00') {
					continue // dynamic name: only the browser knows the result
				}
				if !classTokenRe.MatchString(tok) {
					continue // e.g. a leftover "{{if" from a malformed attribute
				}
				used[tok] = append(used[tok], p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
	if len(used) < 50 {
		t.Fatalf("only %d class names found in templates; the extractor regex is stale", len(used))
	}

	var missing []string
	for name := range used {
		if defined[name] {
			continue
		}
		sort.Strings(used[name])
		missing = append(missing, name+" ("+used[name][0]+")")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d class name(s) used by templates have no rule in app.css:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// TestPageTemplatesAreDistinct catches the v1.0.3 domain detail bug, where
// domain_detail.html was a byte-for-byte copy of domains.html: the handler
// passed {"Domain", "Users"} while the page ranged over .Data.Domains, so
// /domains/{id} rendered an empty list forever.
func TestPageTemplatesAreDistinct(t *testing.T) {
	byContent := map[string]string{}
	for _, name := range pageTemplateNames {
		src, err := fs.ReadFile(assets, "templates/"+name)
		if err != nil {
			continue
		}
		key := string(src)
		if other, dup := byContent[key]; dup {
			t.Errorf("templates/%s is identical to templates/%s; one of them was copy-pasted without editing",
				name, other)
			continue
		}
		byContent[key] = name
	}
}

// TestQueuePageAndFragmentAgreeOnTheDataShape is the unit test for the v1.0.3
// queue 500: queue.html passed the pageData envelope to queue_table while
// /queue/refresh passed a flat map, so the page could not resolve .Messages.
// Both entry points must now produce the same rows from the same data.
func TestQueuePageAndFragmentAgreeOnTheDataShape(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)

	messages := []queue.Message{{
		QueueID: "8F3A1B2C3D",
		Size:    4096,
		Arrival: time.Now(),
		Active:  true,
		Sender:  "sender@example.com",
		Recipients: []queue.Recipient{
			{Address: "rcpt@example.org", Status: "deferred", Reason: "connection timed out"},
		},
	}}
	flat := map[string]any{"Messages": messages, "TotalSize": int64(4096)}

	// The page: handler data wrapped in the envelope.
	rec := httptest.NewRecorder()
	s.render(rec, http.StatusOK, "queue.html", pageData{
		Title: "Mail Queue", ActiveNav: "queue", Data: flat,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("queue.html answered %d (want 200): %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	for _, want := range []string{"8F3A1B2C3D", "rcpt@example.org", "deferred", "sender@example.com"} {
		if !strings.Contains(page, want) {
			t.Errorf("queue page does not contain %q; the message rows are missing", want)
		}
	}

	// The refresh endpoint: the same fragment, flat data.
	rec = httptest.NewRecorder()
	s.renderPartial(rec, "queue_table", map[string]any{"Messages": messages})
	if body := rec.Body.String(); !strings.Contains(body, "8F3A1B2C3D") {
		t.Errorf("/queue/refresh renders no rows:\n%s", body)
	}
}

// TestDomainDetailPageRendersHandlerData covers the other half of the v1.0.3
// breakage: /domains/{id} served domains.html's body (an empty range over
// .Data.Domains) instead of the domain that was asked for.
func TestDomainDetailPageRendersHandlerData(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)

	now := time.Now()
	domain := &models.Domain{
		ID: 7, Name: "example.com", IsPrimary: true, Active: true,
		DKIMSelector: "default", DKIMPrivateKeyPath: "/etc/opendkim/keys/example.com/default.private",
		CreatedAt: now, UpdatedAt: now,
	}
	data := map[string]any{
		"Domain": domain,
		"Users": []models.User{{
			ID: 3, DomainID: 7, Username: "alice", Email: "alice@example.com",
			QuotaMB: 512, Active: true, DomainName: "example.com",
		}},
		"Aliases": []models.Alias{{
			ID: 9, DomainID: 7, Source: "sales", Destination: "alice@example.com", DomainName: "example.com",
		}},
	}

	rec := httptest.NewRecorder()
	s.render(rec, http.StatusOK, "domain_detail.html", pageData{
		Title: "example.com", ActiveNav: "domains", Data: data,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("domain_detail.html answered %d (want 200): %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	for _, want := range []string{"example.com", "alice@example.com", "sales", "alice", "512 MB"} {
		if !strings.Contains(body, want) {
			t.Errorf("domain page does not contain %q; the handler data never reached the template", want)
		}
	}
	// Links that exist only on this page, i.e. proof it is not the list page.
	for _, want := range []string{`href="/domains/7/dns"`, `href="/users/3"`, "/domains/7/preview-delete"} {
		if !strings.Contains(body, want) {
			t.Errorf("domain page is missing %q", want)
		}
	}
	if strings.Contains(body, "No domains yet") {
		t.Error("domain page rendered the domain *list* empty state")
	}
}

// TestDNSPageAndFragmentAgreeOnTheDataShape covers the third contract bug:
// domain_dns.html passed the pageData envelope to the fragment, which expects the
// page data directly, so the second load of that page answered 500. The page and
// the check endpoint now render the *same* row list (plan + status), so a check
// cannot change which records are listed.
func TestDNSPageAndFragmentAgreeOnTheDataShape(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)

	data := &dnsPage{
		Domain:   &models.Domain{ID: 7, Name: "example.com"},
		ServerIP: "203.0.113.10",
		MailHost: "mail.example.com",
		Rows: []dnsRow{
			{
				Purpose: "Inbound mail", Type: "MX", Name: "example.com",
				Value: "mail.example.com", Priority: 10, Required: true,
				Status: "mismatch", Message: "example.com does not list mail.example.com",
				Observed: []string{"20 other.example.net"},
			},
			{
				Purpose: "PTR / reverse DNS (203.0.113.10)", Type: "PTR",
				Name: "10.113.0.203.in-addr.arpa", Value: "mail.example.com",
				Required: true, Manual: true, Status: "manual",
			},
		},
		Verdict: "err",
		Summary: "Inbound mail is missing or wrong.",
	}

	rec := httptest.NewRecorder()
	s.render(rec, http.StatusOK, "domain_dns.html", pageData{
		Title: "DNS · example.com", ActiveNav: "domains", Data: data,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("domain_dns.html answered %d (want 200): %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"203.0.113.10",                 // the server address, so the A records can be filled in
		"Inbound mail",                 // the record's purpose
		"mail.example.com",             // its value
		"not ready to send or receive", // the verdict
		"10.113.0.203.in-addr.arpa",    // the PTR row
	} {
		if !strings.Contains(body, want) {
			t.Errorf("DNS page does not contain %q:\n%s", want, body)
		}
	}

	// The check endpoint's fragment must render the same rows from the same data.
	rec = httptest.NewRecorder()
	s.renderPartial(rec, "dns_check_results", data)
	if frag := rec.Body.String(); !strings.Contains(frag, "Inbound mail") {
		t.Errorf("dns_check_results rendered no rows:\n%s", frag)
	}
}

// TestLogsPageAndFragmentAgreeOnTheDataShape keeps the logs page and its list
// fragment on one contract: the page embeds the fragment, so a change to either
// side that drops a key (total, pagination window, counts) breaks this test
// instead of silently emptying the table in the browser.
func TestLogsPageAndFragmentAgreeOnTheDataShape(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)

	data := map[string]any{
		"Events": []logEvent{{
			ID: 1, Ts: time.Now(), QueueID: "ABCD1234EF", Service: "postfix/smtp",
			Action: "sent", Status: "sent", FromAddr: "sender@example.com",
			ToAddr: "rcpt@example.org", Message: "250 2.0.0 Ok: queued",
		}},
		"Filter":     logFilter{Limit: 100, Status: "sent", Since: "24h"},
		"Total":      1,
		"Counts":     []logStatusCount{{Status: "sent", Count: 1, Class: "ok"}},
		"First":      1,
		"Last":       1,
		"HasMore":    false,
		"PrevOffset": 0,
		"NextOffset": 100,
		"Limit":      100,
	}

	rec := httptest.NewRecorder()
	s.render(rec, http.StatusOK, "logs.html", pageData{Title: "Logs", ActiveNav: "logs", Data: data})
	if rec.Code != http.StatusOK {
		t.Fatalf("logs.html answered %d (want 200): %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	for _, want := range []string{"ABCD1234", "sender@example.com", "Showing 1–1 of 1", "sent · 1"} {
		if !strings.Contains(page, want) {
			t.Errorf("logs page does not contain %q", want)
		}
	}

	rec = httptest.NewRecorder()
	s.renderPartial(rec, "log_rows", data)
	fragment := rec.Body.String()
	if !strings.Contains(fragment, "ABCD1234") || !strings.Contains(fragment, "Showing 1–1 of 1") {
		t.Errorf("/logs/list fragment is missing rows or the pager:\n%s", fragment)
	}

	// The Log source panel renders from its own struct and must never panic on a
	// host where the log file is missing.
	rec = httptest.NewRecorder()
	s.renderPartial(rec, "log_source", logSourceInfo{
		Path: "/var/log/mail.log", Exists: false, Hints: []string{"missing file hint"},
	})
	if body := rec.Body.String(); !strings.Contains(body, "missing file hint") {
		t.Errorf("log_source did not render its hints:\n%s", body)
	}
}

// TestTestSendResultRendersTranscriptAndFriendlyError guards the test-send UX:
// the result panel has to show the raw error, the plain-language explanation and
// the SMTP transcript, because that transcript is the only evidence the admin
// has of what the mail server answered.
func TestTestSendResultRendersTranscriptAndFriendlyError(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)

	res := &smtp.Result{
		Success: false,
		Error:   "dial tcp 127.0.0.1:587: connect: connection refused",
		Transcript: []smtp.TranscriptLine{
			{Dir: "I", Text: "Connecting to 127.0.0.1:587 (TLS mode: starttls)"},
			{Dir: "C", Text: "EHLO mail.example.com"},
			{Dir: "S", Text: "220 mail.example.com ESMTP"},
		},
	}
	opts := smtp.SendOptions{
		Host: "127.0.0.1", Port: 587, TLSMode: smtp.TLSStartTLS,
		From: "postmaster@example.com", To: "admin@example.org",
	}

	rec := httptest.NewRecorder()
	s.renderPartial(rec, "testsend_result", map[string]any{
		"Result":   res,
		"Opts":     opts,
		"Friendly": friendlySMTPError(res.Error, opts),
	})
	body := rec.Body.String()
	for _, want := range []string{
		"connection refused",
		"Nothing is answering on 127.0.0.1:587",
		"EHLO mail.example.com",
		"220 mail.example.com ESMTP",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("test-send result does not contain %q", want)
		}
	}
}
