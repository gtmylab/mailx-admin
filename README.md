# MailX Admin

A control plane for [MailX](https://github.com/gtmylab/mailx) self-hosted mail servers: a
web panel and a command-line tool that manage Postfix, Dovecot, OpenDKIM, Roundcube
webmail and phpMyAdmin from a single SQLite (or PostgreSQL) database, plus an
idempotent, resumable bash installer that stands the whole stack up on a fresh
Debian/Ubuntu host.

The panel and the installer ship together in every GitHub release: the installer
downloads the version-stamped `mailx-admin-linux-amd64` binary from
`releases/latest/download`, verifies its SHA-256, and wires it into systemd behind an
Apache reverse proxy.

---

## Table of contents

- [What it does](#what-it-does)
- [Features](#features)
- [How it is put together](#how-it-is-put-together)
- [Requirements](#requirements)
- [Installation](#installation)
- [Updating](#updating)
- [Configuration](#configuration)
- [Command-line reference](#command-line-reference)
- [Building from source](#building-from-source)
- [Project layout](#project-layout)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

MailX Admin is the single pane of glass for a mail server you already own. You point it
at a host that has Postfix, Dovecot and OpenDKIM (or let `Mailx-Installer` install them
for you), and it:

- stores domains, mailboxes, aliases and settings in a local database,
- **reconciles** that state into the live daemon configs (`main.cf`, `master.cf`,
  `vmailbox`, Dovecot passdb/userdb, OpenDKIM key/signing tables, sieve, …) and reloads
  the affected services,
- adopts state that already exists on disk (mailboxes created by `useradd`, configs
  written by hand) so nothing is orphaned,
- and gives you the day-to-day operations UI: DNS, certificates, queues, logs, backups,
  imports, package updates and a live terminal.

The installer is what turns an empty VPS into a working mail server: Postfix (SMTP),
Dovecot (IMAP/POP3/LMTP + sieve), OpenDKIM (signing), MySQL, Roundcube (webmail),
phpMyAdmin, Let's Encrypt certificates, and finally the panel itself.

---

## Features

### Dashboard & monitoring
- Traffic and system-info dashboards, with live updates over Server-Sent Events.
- Service health (systemd units) and configuration-sync status at a glance.
- Prometheus metrics at `/metrics`, liveness at `/healthz`, goroutine dump at
  `/healthz/stacks`.

### Domains & DNS
- Domain create/edit/delete (with a delete-preview that shows what would be removed).
- Primary-domain selection and per-domain DKIM key regeneration.
- DNS records and live checks for MX, A/AAAA, PTR, SPF, DKIM and DMARC, with copy/export.

### Mailboxes, users & aliases
- Virtual and system mailboxes, quota, per-user usage and per-user mail logs.
- Password reset and server-side sieve filtering rules (create/reorder/toggle/delete).
- Aliases: forwarders, catch-all (`@domain`) and comma-separated distribution lists.

### TLS / certificates
- Let's Encrypt issuance and renewal, per-certificate detail, expiry warnings and
  renewal-failure notifications.

### Delivery & reputation
- SMTP test-send with transcript history.
- Postfix queue viewer with per-queue message detail, flush/delete (one or all).
- Outbound relay (smarthost) configuration.
- Outbound IP registry with per-IP routing rules.
- Deliverability dashboard: blocklist checks and suppression list management.

### Ports & services
- SMTP/submission/SMTPS/IMAP/POP3 listener management (port, TLS mode, SASL).
- systemd service control (start/stop/restart/status) from the UI.

### Logs
- `mail.log` + journald ingestion, live tail, per-source filtering and per-message queue
  detail.

### Imports, backups & system
- Mail import from IMAP, mbox or a source maildir, queued and resumable.
- Backups (create/download/delete/restore) covering config, database, maildirs and
  Let's Encrypt.
- Software package updates (apt), server settings, a Postfix config editor, SQLite →
  PostgreSQL migration, and an in-browser terminal (WebSocket).

### API, automation & security
- API keys and webhooks; a bearer-authenticated public API (suppressions, message send).
- Session + CSRF protection, admin panel users with roles, and a full audit log.

---

## How it is put together

```
Mailx-Installer        bash installer (idempotent, resumable) — installs & upgrades the
                       whole stack, including this panel
cmd/mailx-admin        the `mailx-admin` CLI + HTTP server
internal/…             the application: config, db, store, reconciler, web server, …
```

Two layers work together:

1. **Installer** (`Mailx-Installer`) — runs numbered stages with checkpoints in
   `/usr/local/mailx_state`, so a failed run resumes where it left off. Stage 13
   downloads the panel binary, stage 14 writes the Apache vhost. Re-running it with
   `MAILX_ADMIN_FORCE_REINSTALL=1` re-fetches and re-installs the panel.
2. **Panel** (`mailx-admin`) — reads `/etc/mailx/admin.toml`, migrates its database on
   startup, and serves the web UI on `127.0.0.1:9090` (reverse-proxied by Apache at
   `https://admin.<domain>:9443`). Every change you make is written to the database and
   then **reconciled** into the daemon configs.

---

## Requirements

- Debian or Ubuntu (the installer uses `apt`).
- Root access (the installer configures system services).
- A domain name whose DNS you control, plus a public IPv4 for the mail host.
- For the panel binary: a Linux `amd64` host (the release asset is `linux-amd64`; the
  SQLite driver requires cgo, so the release build runs in CI on Linux).

---

## Installation

On a fresh Debian/Ubuntu server:

```bash
curl -fsSLO https://github.com/gtmylab/mailx-admin/releases/latest/download/Mailx-Installer
chmod +x Mailx-Installer
./Mailx-Installer
```

The installer asks for:

- your **email domain** (e.g. `example.com`),
- the **system hostname** (e.g. `mail.example.com`),
- an optional **mail hostname / MX target** (leave blank to reuse the system hostname —
  this is what the Let's Encrypt certificate and the MX/A DNS records use, so you are
  never forced to create a `mail.` subdomain you do not want),
- an **admin email** for SSL/abuse notifications.

It then installs the stack, obtains certificates, and prints the DNS records you still
need to publish (MX, A, SPF, DKIM, DMARC). The panel database defaults to **SQLite**
(no prompt); PostgreSQL is a later, optional migration done from the panel, not the
installer.

The panel is served at `https://admin.<your-domain>:9443`. The initial admin password
is written to `/root/.mailx-admin-initial-password`.

---

## Updating

There are three ways to update the panel.

**1. From the panel (recommended)** — *System → Updates* checks GitHub releases and
applies the newest binary, verifying its SHA-256 before replacing it.

**2. Re-run the installer** — re-fetch the installer and force a reinstall:

```bash
curl -fsSLO https://github.com/gtmylab/mailx-admin/releases/latest/download/Mailx-Installer
chmod +x Mailx-Installer
MAILX_ADMIN_FORCE_REINSTALL=1 ./Mailx-Installer
```

**3. Manually** — download the binary and its checksums, verify, replace and restart:

```bash
curl -fsSLO https://github.com/gtmylab/mailx-admin/releases/latest/download/mailx-admin-linux-amd64
curl -fsSLO https://github.com/gtmylab/mailx-admin/releases/latest/download/SHA256SUMS
sha256sum -c <(grep mailx-admin-linux-amd64 SHA256SUMS)
install -m 0755 mailx-admin-linux-amd64 /usr/local/bin/mailx-admin
systemctl restart mailx-admin
```

Verify the running version with:

```bash
/usr/local/bin/mailx-admin --version
```

---

## Configuration

The panel reads `/etc/mailx/admin.toml` (TOML). The installer writes it; edit it
carefully — the panel reads it on every start.

```toml
[server]
listen_addr = "127.0.0.1:9090"     # where the Go HTTP server listens
base_url    = "https://admin.example.com"
hostname    = "mail.example.com"

[database]
driver = "sqlite"                  # "sqlite" or "postgres"

[database.sqlite]
path = "/var/lib/mailx/state.db"

[database.postgres]                # used only when driver = "postgres"
host     = "127.0.0.1"
port     = 5432
user     = "mailx_admin"
password = ""
dbname   = "mailx_admin"
sslmode  = "disable"

[mail]
postfix_conf_dir    = "/etc/postfix"
dovecot_conf_dir    = "/etc/dovecot"
opendkim_dir        = "/etc/opendkim"
primary_domain_file = "/usr/local/roundcube_mail_domain.txt"
passwd_scheme       = "auto"       # "auto" asks Dovecot (ARGON2ID / SSHA512)

[roundcube]
enabled   = true
database  = "roundcubemail"
binary    = "mysql"
args      = ["--defaults-file=/etc/mailx/roundcube.my.cnf"]
mail_host = "localhost"
language  = "en_GB"

[dns]
resolver = "1.1.1.1:53"

[logs]
mail_log_path  = "/var/log/mail.log"
retention_days = 30
```

---

## Command-line reference

The same binary that serves the web UI is also a CLI. It reads the config from
`/etc/mailx/admin.toml` unless `--config` is given.

```
mailx-admin serve              Run the admin HTTP server
                               --auto-seed     adopt existing server state on an empty DB
                               --require-seed  refuse to start if the DB is empty

mailx-admin migrate            Apply database migrations

mailx-admin reconcile          Render and apply daemon configs from DB state
                               --dry-run  show what would change without applying
                               --json     print the result as JSON

mailx-admin status             Show a summary of the current DB state

mailx-admin seed               Adopt existing server state into the admin database

mailx-admin adopt              Import domains/mailboxes/aliases that exist on the
                               server but are not yet in the panel

mailx-admin doctor             Read-only check that the panel, DB and daemons agree

mailx-admin user create <name> Create an admin panel user
mailx-admin user passwd <name> Change an admin user's password
mailx-admin user list          List admin panel users

mailx-admin mailbox add <local>@<domain>     Create a mailbox and apply it
mailx-admin mailbox list                     List known mailboxes
mailx-admin mailbox remove <local>@<domain>  Remove a mailbox

mailx-admin roundcube sync     Create the Roundcube account for every mailbox missing one
```

---

## Building from source

You need Go **1.25** or newer.

```bash
git clone https://github.com/gtmylab/mailx-admin.git
cd mailx-admin

# native build (cgo + SQLite) — on Linux this is the production binary
make build

# Linux release artifact (the file the installer downloads)
make build-linux            # runs on Linux only: go-sqlite3 needs cgo

# Windows dev build (cgo off; uses the SQLite stub — for UI work, not a live DB)
make build-windows

# tests
make test                   # go test ./... -race -count=1
```

`make build`/`make build-linux` stamp the version, commit and build date into
`internal/version` via linker flags, so `mailx-admin --version` reports the exact build
on every platform.

---

## Project layout

```
cmd/mailx-admin/       the CLI entry point and subcommands
internal/auth/         sessions, passwords, CSRF
internal/config/       admin.toml loading and defaults
internal/db/           SQLite / PostgreSQL driver + migrations
internal/dbmigrate/    SQLite → PostgreSQL migration
internal/reconciler/   renders DB state into Postfix/Dovecot/OpenDKIM configs
internal/store/        typed access to the database
internal/server/       HTTP handlers, router, templates, static assets
internal/importer/     IMAP / mbox / maildir import
internal/logs/         mail.log + journald ingestion
internal/jobs/         scheduled monitoring (blocklist, quota, PTR, outbound IPs)
internal/update/       self-update (check/apply GitHub releases)
internal/…             apt, backup, dkim, dns, doctor, dovecot, maildir, metrics,
                       models, ports, queue, roundcube, seed, sieve, smtp, ssl,
                       system, syncer, webhooks, …
Mailx-Installer        the bash installer/upgrader
.github/workflows/     CI (tests on every push) and Release (builds+publishes per tag)
```

---

## Contributing

Contributors are welcome — bug reports, fixes, documentation and feature ideas all
help. Please:

1. Open an issue first for anything non-trivial, so the approach can be agreed before
   you write code.
2. Follow the existing conventions (the code is `gofmt`-formatted; `make lint` runs
   `gofmt -l -w .` and `go vet ./...`).
3. Add or update tests, and run `make test` before submitting — the SQLite tests
   require cgo, so run them on Linux (or in the CI workflow, which does).
4. Keep changes to the installer idempotent: a re-run must not break an existing
   install.

CI runs `make test` on every push to `main` and every pull request.

---

## License

This repository does not currently ship a `LICENSE` file. Contact the maintainer
(`gtmylab`) for terms before redistributing.


