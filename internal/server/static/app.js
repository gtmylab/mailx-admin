/* MailX Admin - UI behaviour.
 *
 * Loaded with `defer` from layout.html. Everything here used to live in inline
 * <script> blocks, which meant the CSRF fix-ups and the flash-to-toast bridge
 * were duplicated per page and could never be tested. Keep this file free of
 * template syntax: it only reads data-* attributes and the mailx_csrf cookie.
 *
 * Contents:
 *   1. theme       - dark (default) / light, persisted, honours the OS setting
 *   2. sidebar     - desktop collapse + mobile drawer
 *   3. toasts      - window.mailx.toast(...) and the ?flash= bridge
 *   4. csrf        - cookie is the source of truth for every form and htmx call
 *   5. htmx glue   - busy buttons, friendly error toasts, modal cleanup
 *   6. helpers     - copy to clipboard, auto-dismiss, focus trap
 */
(function () {
  "use strict";

  var STORE = {
    theme: "mailx.theme",
    sidebar: "mailx.sidebar"
  };

  function read(key, fallback) {
    try {
      var v = window.localStorage.getItem(key);
      return v === null ? fallback : v;
    } catch (e) {
      return fallback;
    }
  }

  function write(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (e) {
      /* private mode: the setting simply does not survive a reload */
    }
  }

  /* ------------------------------------------------------------- 1. theme -- */

  function applyTheme(theme) {
    var root = document.documentElement;
    root.setAttribute("data-theme", theme);
    root.classList.toggle("dark", theme !== "light");
    root.classList.toggle("light", theme === "light");
    var btn = document.querySelector("[data-theme-toggle]");
    if (btn) {
      btn.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
      btn.setAttribute("title", theme === "light" ? "Switch to dark theme" : "Switch to light theme");
      btn.setAttribute("aria-label", btn.getAttribute("title"));
    }
  }

  function initTheme() {
    var stored = read(STORE.theme, null);
    var theme = stored;
    if (!theme) {
      theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    }
    applyTheme(theme);

    document.addEventListener("click", function (evt) {
      var btn = evt.target.closest && evt.target.closest("[data-theme-toggle]");
      if (!btn) return;
      var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      write(STORE.theme, next);
      applyTheme(next);
    });
  }

  /* ----------------------------------------------------------- 2. sidebar -- */

  function isMobile() {
    return window.matchMedia("(max-width: 1023px)").matches;
  }

  function initSidebar() {
    var shell = document.querySelector(".app-shell");
    if (!shell) return;

    // Desktop: collapsed rail. Mobile: is-collapsed is a no-op (see app.css),
    // so the drawer always shows full labels.
    if (read(STORE.sidebar, "open") === "collapsed") {
      shell.classList.add("is-collapsed");
    }

    document.addEventListener("click", function (evt) {
      var target = evt.target;
      if (target.closest && target.closest("[data-sidebar-toggle]")) {
        if (isMobile()) {
          shell.classList.add("is-drawer-open");
          var first = shell.querySelector(".sidebar a");
          if (first) first.focus();
        } else {
          var collapsed = shell.classList.toggle("is-collapsed");
          write(STORE.sidebar, collapsed ? "collapsed" : "open");
        }
        return;
      }

      var drawerBtn = target.closest && target.closest("[data-drawer-toggle]");
      if (drawerBtn) {
        var open = shell.classList.toggle("is-drawer-open");
        document.querySelectorAll("[data-drawer-toggle]").forEach(function (b) {
          b.setAttribute("aria-expanded", open ? "true" : "false");
        });
        return;
      }

      // Any navigation from inside the drawer closes it.
      if (target.closest && target.closest(".sidebar a") && isMobile()) {
        shell.classList.remove("is-drawer-open");
        return;
      }

      if (target.closest && target.closest(".drawer-backdrop")) {
        shell.classList.remove("is-drawer-open");
      }
    });

    // Escape closes the drawer, and a viewport that grows past the breakpoint
    // must not keep a stale open state around.
    document.addEventListener("keydown", function (evt) {
      if (evt.key === "Escape") shell.classList.remove("is-drawer-open");
    });
    window.addEventListener("resize", function () {
      if (!isMobile()) shell.classList.remove("is-drawer-open");
    });

    // Mark the active nav entry if the server did not.
    var path = window.location.pathname;
    shell.querySelectorAll(".sidebar .nav-link").forEach(function (link) {
      var href = link.getAttribute("href");
      if (!href) return;
      var active = href === "/" ? path === "/" : path === href || path.indexOf(href + "/") === 0;
      if (active) link.classList.add("is-active");
    });
  }
  /* ------------------------------------------------------------ 3. toasts -- */

  var TOAST_KINDS = { ok: "toast-ok", err: "toast-err", warn: "toast-warn", info: "" };

  function toastHost() {
    var host = document.getElementById("toast-host");
    if (!host) {
      host = document.createElement("div");
      host.id = "toast-host";
      // The layout ships one; this is the fallback for standalone pages.
      document.body.appendChild(host);
    }
    if (!host.classList.contains("toast-stack")) host.classList.add("toast-stack");
    return host;
  }

  function escapeHTML(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // toast accepts either pre-rendered HTML (htmx fragments that are already
  // escaped server side) or a plain string, which is escaped here.
  function toast(messageOrHTML, kind, timeout) {
    var host = toastHost();
    var el = document.createElement("div");
    el.className = "toast " + (TOAST_KINDS[kind] || "");
    el.setAttribute("role", kind === "err" ? "alert" : "status");
    if (typeof messageOrHTML === "string" && messageOrHTML.indexOf("<") === -1) {
      el.innerHTML = '<span class="dot" aria-hidden="true"></span><span>' + escapeHTML(messageOrHTML) + "</span>";
    } else {
      el.innerHTML = messageOrHTML;
    }
    host.appendChild(el);

    var ms = typeof timeout === "number" ? timeout : kind === "err" ? 9000 : 4200;
    var remove = function () {
      el.classList.add("htmx-swapping");
      window.setTimeout(function () {
        if (el.parentNode) el.parentNode.removeChild(el);
      }, 140);
    };
    el.addEventListener("click", remove);
    window.setTimeout(remove, ms);
    return el;
  }

  /* Connection-level failures reach the page through several htmx events:
   * htmx:sendError, htmx:timeout, and htmx:afterRequest with status 0. They
   * overlap, so they share one message and a rate limit — three identical
   * toasts stacked on top of each other is worse than none. */
  var CANNOT_REACH = "Cannot reach the panel. Check that the service is running.";
  var CONN_TOAST_MS = 2000;
  var lastConnToastAt = 0;

  /* Kept in step with the server's mutation budget
   * (internal/server/timeout.go: mutationTimeout = 30s). */
  var HTMX_TIMEOUT_MS = 30000;

  function connErrorToast(message) {
    var now = Date.now();
    if (now - lastConnToastAt < CONN_TOAST_MS) return;
    lastConnToastAt = now;
    toast(message, "err");
  }

  function initFlash() {
    // Inline .alert blocks rendered by a full page load fade out on their own.
    document.querySelectorAll("[data-autodismiss]").forEach(function (el) {
      window.setTimeout(function () {
        el.classList.add("htmx-swapping");
        window.setTimeout(function () {
          if (el.parentNode) el.parentNode.removeChild(el);
        }, 160);
      }, parseInt(el.getAttribute("data-autodismiss"), 10) || 5000);
    });

    // Server-side redirects append ?flash=...; turn it into a toast and clean
    // the URL so a reload does not replay the message.
    var url = new URL(window.location.href);
    var flash = url.searchParams.get("flash");
    if (!flash) return;
    var kind = url.searchParams.get("flash_kind") || "ok";
    toast(flash, kind);
    url.searchParams.delete("flash");
    url.searchParams.delete("flash_kind");
    window.history.replaceState({}, "", url.toString());
  }

  /* -------------------------------------------------------------- 4. csrf -- */

  // The mailx_csrf cookie is the single source of truth: it is minted once per
  // browser session and reused, so a token baked into an old page (or restored
  // from the back/forward cache) is never the reason a POST fails.
  function csrfToken() {
    var m = document.cookie.match(/(?:^|;\s*)mailx_csrf=([^;]*)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  function initCSRF() {
    var t = csrfToken();
    if (t) {
      document.querySelectorAll('input[name="_csrf"]').forEach(function (input) {
        if (!input.value) input.value = t;
      });
    }
    document.body.addEventListener("htmx:configRequest", function (evt) {
      var live = csrfToken();
      if (live) evt.detail.headers["X-CSRF-Token"] = live;
    });
  }
  /* ---------------------------------------------------------- 5. htmx glue -- */

  var ERROR_TEXT = {
    400: "The server rejected that request (400). Check the values and try again.",
    401: "Your session has expired. Reload to sign in again.",
    403: "Security token rejected (403). Reload the page and retry.",
    404: "That endpoint no longer exists (404).",
    405: "That action is not allowed (405).",
    409: "Conflicting change (409). Reload the page and retry.",
    500: "The server hit an internal error (500). See the service log for details.",
    502: "The panel is restarting or unreachable (502).",
    503: "The panel is unavailable (503). Try again in a moment."
  };

  function requestButtons(elt) {
    var form = elt.closest ? elt.closest("form") : null;
    if (!form) return [];
    return Array.prototype.slice.call(form.querySelectorAll('button[type="submit"], button:not([type])'));
  }

  function setBusy(elt, busy) {
    if (!elt) return;
    requestButtons(elt).forEach(function (btn) {
      if (busy) {
        btn.setAttribute("data-was-enabled", btn.disabled ? "0" : "1");
        btn.disabled = true;
        btn.setAttribute("aria-busy", "true");
      } else {
        btn.disabled = btn.getAttribute("data-was-enabled") === "0";
        btn.removeAttribute("data-was-enabled");
        btn.removeAttribute("aria-busy");
      }
    });
    if (busy) {
      elt.setAttribute("aria-busy", "true");
    } else {
      elt.removeAttribute("aria-busy");
    }
  }

  function responseMessage(xhr) {
    var status = xhr ? xhr.status : 0;
    if (status === 401) {
      window.setTimeout(function () {
        window.location.assign("/login");
      }, 800);
    }
    var text = ERROR_TEXT[status];
    if (!text) {
      text = status >= 500 ? "Server error (" + status + ")." : "Request failed (" + status + ").";
    }
    // The server answers JSON for fetch-style endpoints and plain text for the
    // rest; only surface a short server message, never a whole HTML page.
    var body = xhr && xhr.responseText ? xhr.responseText.trim() : "";
    if (body && body.length <= 200 && body.indexOf("<") === -1 && status >= 500) {
      text = body;
    }
    return text;
  }

  function closeModal(force) {
    var host = document.getElementById("modal-host");
    if (!host) return;
    // Some dialogs (the password reveal) show a value that exists exactly once,
    // so Escape, a backdrop click and the ✕ must not dismiss them until the
    // admin explicitly acknowledges it. Those buttons pass "force".
    if (!force && host.querySelector("[data-modal-locked]")) {
      toast("Save the value shown here first", "warn");
      return;
    }
    host.innerHTML = "";
    document.body.classList.remove("overflow-hidden");
  }

  function modalIsOpen() {
    var host = document.getElementById("modal-host");
    return !!(host && host.firstElementChild);
  }

  function trapFocus(evt) {
    if (evt.key !== "Tab" || !modalIsOpen()) return;
    var host = document.getElementById("modal-host");
    var focusable = host.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    if (!focusable.length) return;
    var first = focusable[0];
    var last = focusable[focusable.length - 1];
    if (evt.shiftKey && document.activeElement === first) {
      evt.preventDefault();
      last.focus();
    } else if (!evt.shiftKey && document.activeElement === last) {
      evt.preventDefault();
      first.focus();
    }
  }

  function initHTMX() {
    if (!window.htmx) {
      // htmx did not load (missing vendor file): make the page degrade loudly
      // instead of pretending hx-* attributes work.
      if (document.querySelector("[hx-get], [hx-post], [hx-put], [hx-patch], [hx-delete]")) {
        console.error("htmx is not loaded; interactive controls are inert");
      }
      return;
    }

    // Abort a stalled request instead of spinning forever. 30s matches the
    // server's mutation budget (internal/server/timeout.go); anything the
    // server itself can detect is answered with an error well before that.
    window.htmx.config.timeout = HTMX_TIMEOUT_MS;

    document.body.addEventListener("htmx:beforeRequest", function (evt) {
      setBusy(evt.detail.elt, true);
    });

    document.body.addEventListener("htmx:afterRequest", function (evt) {
      setBusy(evt.detail.elt, false);
      var xhr = evt.detail.xhr;
      var failed = evt.detail.failed;
      // htmx does not swap an error body into the page, so without a toast the
      // user sees "nothing happen" - the exact symptom this fixes.
      if (failed || !xhr) {
        if (xhr && xhr.status) {
          toast(responseMessage(xhr), "err");
        } else {
          // Status 0: the request never got an answer (offline, or aborted by
          // the timeout below). connErrorToast de-duplicates the overlap with
          // htmx:sendError / htmx:timeout.
          connErrorToast(CANNOT_REACH);
        }
      }
    });

    // htmx aborts a request that exceeds htmx.config.timeout. Unlike "the panel
    // is down", the change may already have been applied before the server went
    // quiet, so the message says so instead of inviting a blind retry.
    document.body.addEventListener("htmx:timeout", function () {
      connErrorToast(
        "The panel did not answer within " +
          HTMX_TIMEOUT_MS / 1000 +
          "s. Reload the page to see whether the change was applied."
      );
    });

    document.body.addEventListener("htmx:sendError", function () {
      connErrorToast(CANNOT_REACH);
    });

    document.body.addEventListener("htmx:afterSwap", function (evt) {
      var target = evt.detail.target;
      if (!target) return;

      // renderFormError answers with HX-Retarget: #form-error, and the layout
      // owns exactly one such container. With a dialog open the message has to
      // show up inside the dialog instead of behind its overlay.
      if (target.id === "form-error") {
        var slot = document.querySelector("#modal-host [data-modal-error]");
        if (slot && modalIsOpen()) {
          slot.innerHTML = target.innerHTML;
          target.innerHTML = "";
        } else if (target.innerHTML && target.scrollIntoView) {
          target.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }
        return;
      }

      if (target.id !== "modal-host") return;
      if (modalIsOpen()) {
        document.body.classList.add("overflow-hidden");
        var focusable = target.querySelector(
          'input:not([type="hidden"]):not([disabled]), select, textarea, button'
        );
        if (focusable) focusable.focus();
      } else {
        document.body.classList.remove("overflow-hidden");
      }
    });

    // Toast fragments use hx-swap="none" + this hook so a rendered toast_partial
    // is not inserted into the page body.
    document.body.addEventListener("mailx:toast", function (evt) {
      toast(evt.detail.html, evt.detail.kind);
    });
  }
  /* ------------------------------------------------------------ 6. helpers -- */

  function initHelpers() {
    /* Live tail: a checkbox with data-live-tail="#tbody" opens an EventSource
       and prepends the rows it receives, capping the table so a long session
       cannot grow without bound. This used to be an inline <script> in
       logs.html, which is why nothing happened when CSP or a CDN failure
       blocked it. */
    document.addEventListener("change", function (evt) {
      var box = evt.target;
      if (!box || !box.matches || !box.matches("[data-live-tail]")) return;
      var tbody = document.querySelector(box.getAttribute("data-live-tail"));
      var dot = document.querySelector("[data-live-dot]");
      if (!tbody) return;

      if (box.__liveSource) {
        box.__liveSource.close();
        box.__liveSource = null;
      }
      if (dot) dot.classList.toggle("ok-text", box.checked);
      if (!box.checked) return;

      var url = box.getAttribute("data-live-url") || "/logs/live";
      var source = new EventSource(url);
      box.__liveSource = source;
      source.addEventListener("log", function (e) {
        tbody.insertAdjacentHTML("afterbegin", e.data);
        while (tbody.children.length > 500) tbody.lastElementChild.remove();
      });
      source.onerror = function () {
        if (dot) {
          dot.classList.remove("ok-text");
          dot.classList.add("err-text");
        }
        if (window.mailx) {
          window.mailx.toast("Live tail disconnected", "warn");
        }
        source.close();
        box.__liveSource = null;
        box.checked = false;
      };
    });

    // Dialog closing: the explicit close button, a click on the backdrop, and
    // the close-modal event Alpine dialogs dispatch all funnel into closeModal.
    document.addEventListener("click", function (evt) {
      var t = evt.target;
      if (!t || !t.closest) return;

      var btn = t.closest("[data-close-modal]");
      var onBackdrop = t.classList && t.classList.contains("modal");
      if (btn || onBackdrop) {
        closeModal(!!btn && btn.getAttribute("data-close-modal") === "force");
      }
      if (t.closest("[data-reload]")) {
        window.location.reload();
      }
      // A <details> dropdown (the "Add rule" menu) closes on selection.
      var menuItem = t.closest(".dropdown-menu a, .dropdown-menu button");
      if (menuItem) {
        var dd = menuItem.closest("details.dropdown");
        if (dd) dd.open = false;
      }
    });

    // The password reveal keeps its Done button disabled until the admin ticks
    // "I have saved this password".
    document.addEventListener("change", function (evt) {
      var box = evt.target;
      if (!box || !box.matches || !box.matches("[data-ack-toggle]")) return;
      var btn = document.querySelector(box.getAttribute("data-ack-toggle"));
      if (btn) btn.disabled = !box.checked;
    });

    // [data-generate-password="#input"] fills the field with a random password
    // (crypto.getRandomValues, no Math.random) and reveals it, so the admin can
    // copy it before submitting.
    document.addEventListener("click", function (evt) {
      var btn = evt.target.closest && evt.target.closest("[data-generate-password]");
      if (!btn) return;
      evt.preventDefault();
      var input = document.querySelector(btn.getAttribute("data-generate-password"));
      if (!input) return;

      var alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*-_+=";
      var bytes = new Uint8Array(20);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(bytes);
      } else {
        for (var i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
      }
      var out = "";
      for (var j = 0; j < bytes.length; j++) out += alphabet[bytes[j] % alphabet.length];

      input.value = out;
      input.type = "text";
      var toggle = document.querySelector('[data-toggle-password="#' + input.id + '"]');
      if (toggle) toggle.textContent = "hide";
      toast("Password generated — copy it before saving", "ok");
    });

    // Password reveal: [data-toggle-password="#input-id"] flips the input type.
    // Replaces the Alpine x-data/x-text pair the forms used to carry, so a form
    // still works when a vendor script fails to load.
    document.addEventListener("click", function (evt) {
      var btn = evt.target.closest && evt.target.closest("[data-toggle-password]");
      if (!btn) return;
      evt.preventDefault();
      var input = document.querySelector(btn.getAttribute("data-toggle-password"));
      if (!input) return;
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "hide" : "show";
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      input.focus();
    });

    // Copy-to-clipboard for [data-copy="#selector"] / [data-copy-value="..."]
    document.addEventListener("click", function (evt) {
      var btn = evt.target.closest && evt.target.closest("[data-copy], [data-copy-value]");
      if (!btn) return;
      evt.preventDefault();
      var value = btn.getAttribute("data-copy-value") || "";
      var sel = btn.getAttribute("data-copy");
      if (!value && sel) {
        var src = document.querySelector(sel);
        value = src ? (src.value || src.textContent) : "";
      }
      if (!value) {
        toast("Nothing to copy", "warn");
        return;
      }
      var done = function () {
        toast("Copied to clipboard", "ok", 2200);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(value).then(done, function () {
          toast("Clipboard blocked by the browser", "warn");
        });
        return;
      }
      // Fallback for plain-HTTP installs, where navigator.clipboard is absent.
      var ta = document.createElement("textarea");
      ta.value = value;
      ta.setAttribute("readonly", "readonly");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        done();
      } catch (e) {
        toast("Clipboard unavailable", "warn");
      }
      document.body.removeChild(ta);
    });

    // Native (non-htmx) forms: disable the submit button so a slow request
    // cannot be fired twice. The button is re-enabled if the browser stays on
    // the page (validation error, backing out).
    document.addEventListener("submit", function (evt) {
      var form = evt.target;
      if (!form || form.hasAttribute("hx-post") || form.hasAttribute("hx-get")) return;
      var btn = form.querySelector('button[type="submit"], button:not([type])');
      if (!btn) return;
      window.setTimeout(function () {
        btn.disabled = true;
        var spin = btn.querySelector(".spinner");
        if (!spin) {
          spin = document.createElement("span");
          spin.className = "spinner";
          spin.setAttribute("aria-hidden", "true");
          btn.appendChild(spin);
        }
      }, 0);
    });

    // Modal closing: Alpine dispatches close-modal, buttons can too, and the
    // host must be emptied so the focus trap below sees a closed dialog.
    document.addEventListener("close-modal", closeModal);
    document.addEventListener("keydown", function (evt) {
      if (evt.key === "Escape" && modalIsOpen()) closeModal();
      trapFocus(evt);
    });
    // A modal rendered into the host after a full page load (back/forward
    // restore) should lock scrolling too.
    if (modalIsOpen()) document.body.classList.add("overflow-hidden");
  }

  /* --------------------------------------------------------------- start -- */

  window.mailx = {
    toast: toast,
    closeModal: closeModal,
    theme: function (name) {
      if (name !== "dark" && name !== "light") return document.documentElement.getAttribute("data-theme");
      write(STORE.theme, name);
      applyTheme(name);
      return name;
    },
    csrfToken: csrfToken
  };

  // Theme first and synchronously: waiting for DOMContentLoaded paints the
  // default theme for one frame and flashes on every navigation.
  initTheme();

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      initSidebar();
      initFlash();
      initCSRF();
      initHTMX();
      initHelpers();
    });
  } else {
    initSidebar();
    initFlash();
    initCSRF();
    initHTMX();
    initHelpers();
  }
})();
