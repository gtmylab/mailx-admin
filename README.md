# MailX Admin

A control plane for [MailX](https://github.com/gtmylab/mailx) self-hosted mail servers: a
web panel and a command-line tool that manage Postfix, Dovecot, OpenDKIM, postfwd,
Roundcube webmail and phpMyAdmin from a single SQLite (or PostgreSQL) database, plus an
idempotent, resumable bash installer that stands the whole stack up on a fresh
Debian/Ubuntu host.

The panel and the installer ship together in every GitHub release: the installer
downloads the version-stamped `mailx-admin-linux-amd64` binary from
`releases/latest/download`, verifies its SHA-256, and wires it into systemd behind an
Apache reverse proxy. Nothing the panel does is an unrecorded shell one-liner: every
change is written to the database and rendered into the daemon configuration by one
reconciler, so the panel, `mailx-admin doctor` and the files on disk cannot disagree
without saying so.

---

## Table of contents

- [What it does](#what-it-does)
- [Features](#features)
- [How it is put together](#how-it-is-put-together)
- [Requirements](#requirements)
- [Installation](#installation)
- [The installer menu](#the-installer-menu)
- [Updating](#updating)
- [Configuration](#configuration)
- [Command-line reference](#command-line-reference)
- [Public API](#public-api)
- [Building from source](#building-from-source)
- [Project layout](#project-layout)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

MailX Admin is the single pane of glass for a mail server you already own. You point it
at a host that has Postfix, Dovecot and OpenDKIM (or let `Mailx-Installer` install them
for you), and it:

- stores domains, mailboxes, aliases, ports, suppressions, outbound IPs and settings in a
  local database,
- **reconciles** that state into the live daemon configs (`main.cf`, `master.cf`,
  `virtual`, `vmailbox`, Dovecot passdb/userdb, OpenDKIM key/signing tables, postfwd
  rate limits, sieve, …), validates them, and reloads only the services that changed,
- adopts state that already exists on disk (mailboxes created by `useradd`, configs
  written by hand) so nothing is orphaned, and removes entries from those files that the
  panel does not manage — reporting them as *drift* rather than deleting them silently,
- tells you when the three views disagree: `mailx-admin doctor` (and the panel's
  diagnostics dialog) compares the database, the rendered files, the daemons' own
  validators, systemd and the mail log, and exits non-zero when something is wrong,
- and gives you the day-to-day operations UI: DNS, certificates, queues, logs,
  deliverability, imports, backups, scheduled tasks, package updates and a live terminal.

The installer is what turns an empty VPS into a working mail server: Postfix (SMTP),
Dovecot (IMAP/POP3/LMTP + sieve + ManageSieve), OpenDKIM (signing), MySQL, Roundcube
(webmail), phpMyAdmin, Let's Encrypt certificates, and finally the panel itself.

---

## Features

### Dashboard & diagnostics
- Traffic analytics from the mail-event log: sent and received today, this week and this
  month, bounces and deferrals for 30 days, the five busiest outbound domains, and a
  7/30-day volume chart.
- Host health: CPU, memory and disk gauges with sparkline history, uptime, load average
  and the number of pending OS package updates.
- Service health for `postfix`, `dovecot`, `opendkim`, `mysql` and `apache2`, refreshed
  as an HTMX fragment, plus live updates over Server-Sent Events (`/events`).
- A config-sync banner on every page: the last reconcile, what triggered it, how many
  files changed, its warnings and drift, with *sync now*, run history and an
  *import from server* preview that makes shell-created mailboxes visible.
- A diagnostics dialog that runs exactly the same checks as `mailx-admin doctor`.
- Prometheus metrics at `/metrics` (`mailx_admin_info`, `mailx_admin_uptime_seconds`,
  `mailx_service_up`, `mailx_domains_total`, `mailx_users_total`, `mailx_aliases_total`,
  `mailx_mail_events_5m`, `mailx_queue_messages`, `mailx_suppressions_total`,
  `mailx_outbound_ips_active`, `mailx_api_keys_active`, `mailx_webhooks_active`,
  `mailx_blocklist_listed_24h`, `mailx_ssl_days_left`).
- Liveness at `/healthz` — deliberately unauthenticated and cheap, so it answers while the
  login page is still spinning — and an authenticated goroutine dump at `/healthz/stacks`.
- An update banner whenever a newer release exists (GitHub is polled every six hours).

### Domains & DNS
- Create, rename (rewrites the address of every mailbox on the domain in one transaction)
  and delete domains, with a delete preview that lists exactly what would be removed
  before anything happens.
- Primary-domain selection and per-domain DKIM key generation/regeneration with OpenDKIM.
- A `postmaster@<domain>` mailbox with every new domain, so the address the DMARC and
  TLS-RPT records name actually exists.
- A DNS plan built from the panel's own view of the domain — MX, A, AAAA, SPF, DKIM,
  DMARC and TLS-RPT, with PTR flagged as a provider-side action and explained — plus live
  checks against public DNS, copy buttons and a plain-text export.
- Optional per-domain outgoing caps per hour, per day and per month, plus a burst
  allowance, enforced by **postfwd** and answered with a temporary failure (`4.7.1`). All
  windows are rolling (60 minutes / 24 hours / 30 days) and counted per envelope sender
  domain, so webmail submissions and authenticated relay clients count alike while
  inbound mail cannot spend a customer's quota. The domain page shows what the mail log
  says the domain has actually sent in each window.

### Mailboxes, users & aliases
- Virtual mailboxes and system accounts, with quota, per-user usage (used vs. limit) and a
  per-user message history retained for up to 365 days.
- Address filter and a hide/show-disabled switch on the users list.
- Password reset, optionally mailing the new password to an alternate address, and a login
  probe that proves the new hash is one this Dovecot can verify before the page reports
  success.
- A welcome mail sent only *after* the sync that renders the mailbox, so Postfix does not
  bounce it as an unknown user.
- Server-side sieve rules: create, reorder, toggle and delete. A user without rules gets
  no managed script at all, so a script uploaded through ManageSieve is never clobbered.
- Aliases: forwarders, catch-all (`@domain`) and comma-separated distribution lists.
- Create/edit/delete previews that show the resulting configuration diff before saving.

### Webmail (Roundcube)
- New mailboxes are pre-seeded in Roundcube's own `users` and `identities` tables, so the
  account has the right From: address, language and preferences the first time it is
  opened — not just a login that happens to work.
- `mailx-admin roundcube sync` back-fills the mailboxes that already existed (imported by
  `seed`/`adopt`, or created while MySQL was unreachable), with `--dry-run` and JSON
  output.

### TLS / certificates
- Let's Encrypt issuance and renewal through certbot, per-certificate detail (subject,
  issuer, SANs, expiry), expiry warnings and renewal-failure notifications.
- A self-signed certificate generator (common name + SANs) for hosts without a public A
  record yet, and a *test renewal* dry run for every certificate.
- SSL settings in the panel: the admin address for notifications, how many days before
  expiry to warn, a test mail, and installation of the renewal wrapper
  (`/usr/local/bin/ssl_renewal.sh`) with its twice-daily cron entries.
- Enabling HTTPS on the Roundcube webmail vhost from the installer menu.

### Delivery & reputation
- SMTP test-send that runs a real conversation against this server and keeps the full
  transcript, with history.
- Postfix queue viewer with per-message detail and flush/delete for one message or all of
  them.
- Outbound relay (smarthost) configuration with a test button; credentials are rendered
  into `sasl_passwd` with mode `0600`.
- Outbound IP registry: per-IP mode and priority, plus per-sender routing rules rendered
  into `sender_transport` and extra `master.cf` transports, so a domain can leave from the
  address it is supposed to.
- Deliverability dashboard: sent, bounced and deferred totals with bounce and deferral
  rates, broken down by domain and by sending account, over a selectable window.
- Blocklists: hourly DNSBL checks of every active outbound IP against Spamhaus ZEN,
  Barracuda, SpamCop, SORBS, UCEPROTECT L1–L3, DroneBL and JustSpam, with a notification
  when an address is listed.
- Suppressions in both directions — refuse outbound recipients and reject inbound senders,
  by exact address or whole domain, with a reason and an optional expiry — rendered into
  the `suppressions` and `suppressions_in` hash maps so Postfix actually enforces them.

### Ports & services
- Listener management for SMTP, submission, SMTPS, IMAP and POP3, each with its port, TLS
  mode and SASL requirement — previewed as a `master.cf` diff before it is saved.
- A service-ports page for the core stack ports (including moving submission to a
  non-standard port).
- systemd control (start, stop, restart, enable, disable) with per-unit status, plus a
  Postfix config editor with `postfix check`, reload and restart.
- A service health monitor that polls systemd and notifies on up/down transitions.

### Logs
- `mail.log` and journald ingestion into a searchable mail-event log, with per-source
  filtering, live tail, and per-message queue detail (sender, recipients, status, delays,
  the Postfix lines that explain them).
- Per-user message history built from the same events, and a background prune that follows
  `logs.retention_days` (365 by default).

### Mail import
- Import into any local mailbox from IMAP (Google Workspace, Microsoft 365, Mailcow, Mailu,
  iRedMail or any IMAP server, with SSL/TLS, STARTTLS or plain), from an mbox file or
  directory (cPanel exports), or from a Maildir on the filesystem.
- Folders, flags, read state and sent dates are preserved; jobs run one at a time in the
  background with progress, a per-job log, and stop/retry/remove.

### Backups
- Create, list, download, delete and restore `.tar.gz` archives in `/var/backups/mailx`.
- Choose what goes in: the panel database, Postfix/Dovecot/OpenDKIM configuration, maildirs,
  DKIM keys and Let's Encrypt certificates. A restore reports what it replaced.

### Scheduled tasks
- Cron jobs managed from the panel and written to `/etc/cron.d/mailx-admin`. Each enabled
  job invokes `mailx-admin cron run <id>`, so the system cron daemon runs it and the panel
  records the result (status, output, duration) on the Scheduled tasks page.
- Five-field schedule validation, a run-as user, optional stdin input, an optional
  start/end date range (the job is skipped outside it), enable/disable, run-now and a
  per-job log.

### Server & network
- Server settings: hostname, mail identity, the DNS resolver used for checks, and the
  webmail host Roundcube is told about.
- Time and timezone, with an NTP sync button.
- Networking: interfaces and addresses, adding an IP to an interface, and an outbound
  connectivity test.
- Firewall: list and manage `ufw` (or `firewalld`) rules from the panel.

### Database
- SQLite by default; when one server outgrows it, the panel can install PostgreSQL,
  provision a dedicated role and database, test the connection, and migrate the data in
  the background with progress — rewriting `admin.toml` to point at Postgres.
- PostgreSQL status and a service restart on the same page.

### Access control & security
- Panel accounts with roles: `superadmin`, `admin`, `operator` and `readonly`.
- Groups that layer granular permissions (`admin.manage`, `group.manage`,
  `sessions.manage`, `settings.write`, `mail.manage`, `cron.manage`) on top of a base role.
- TOTP two-factor authentication (QR setup, single-use pending login, five code attempts),
  a per-user session TTL, and a list of active sign-ins with revoke-one and
  revoke-all-others.
- Brute-force lockout: five failed sign-ins per username within 15 minutes, with a
  notification and an audit entry.
- Session cookies plus CSRF double-submit protection on every non-GET request; API keys are
  stored only as SHA-256 digests.
- A full audit log — actor, action, target, IP and details — for every change made through
  the panel.

### API, webhooks & notifications
- API keys with `read`, `write` (which implies read) and `admin` scopes.
- A bearer-authenticated REST API under `/api/v1`: suppressions, transactional message
  send and history, and reusable message templates (see [Public API](#public-api)).
- Outbound webhooks signed with HMAC-SHA256 (`X-MailX-Event`, `X-MailX-Signature`) and
  wrapped as `{event, timestamp, data}`, with a delivery log of every attempt and its
  response.
- Per-admin notification handles on Slack, Discord, Telegram, a generic webhook or email,
  each subscribed to a subset of events: `auth.lockout`, `auth.login_failed`, `ssl.failed`,
  `ssl.renewed`, `backup.completed`, `backup.failed`, `blocklist.listed`, `service.down`,
  `service.up`, `user.created`, `user.deleted` (and `outbound.ip_discovered` for webhooks).

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
   `/usr/local/mailx_state`, so a failed run resumes where it left off. Stage 13 downloads
   the panel binary, stage 14 writes the Apache vhost. Re-running it with
   `MAILX_ADMIN_FORCE_REINSTALL=1` re-fetches and re-installs the panel; `./Mailx-Installer
   update` only updates the panel.
2. **Panel** (`mailx-admin`) — reads `/etc/mailx/admin.toml`, migrates its database on
   startup, and serves the web UI on `127.0.0.1:9090` (reverse-proxied by Apache at
   `https://admin.<domain>:9443`). Every change you make is written to the database and
   then **reconciled** into the daemon configs.

Everything the panel manages is the database projected onto the filesystem, and exactly
one code path writes it:

| Area | Files |
| --- | --- |
| Postfix | `main.cf` (merged, not replaced), `master.cf`, `virtual`, `vmailbox`, `vuidmaps`, `vgidmaps`, `helo_access`, `header_checks`, `sender_transport`, `suppressions`, `suppressions_in`, `sasl_passwd` (`0600`) |
| Dovecot | `users` (`0640 root:dovecot`), `conf.d/10-auth-mailx.conf`, `conf.d/90-quota.conf` |
| OpenDKIM | `opendkim.conf`, `KeyTable`, `SigningTable`, `TrustedHosts` |
| postfwd | `/etc/postfwd.cf` — one rate rule per cap and domain, plus marker rules, or a single `DEFAULT` rule when no cap exists |
| Sieve | `<maildir>/sieve/mailx.sieve`, only for users that have rules |
| Cron | `/etc/cron.d/mailx-admin` |
| Roundcube | its own `users` / `identities` rows (a separate database the panel never migrates) |

A reconcile:

1. snapshots the database,
2. decides the password scheme by probing the local Dovecot — `ARGON2ID` where libsodium
   is available, `SSHA512` where it is not, and a hard failure (instead of writing hashes
   nothing can verify) when an explicit scheme is configured that this Dovecot cannot
   check,
3. renders every file in memory first, and only then applies them, copying the previous
   version into `/var/backups/mailx/<timestamp>/`,
4. compiles the Postfix hash maps with `postmap`, checks the result with `postfix check`
   and `doveconf -n`, and reloads only the services whose files changed,
5. removes entries from those files that the panel does not manage (*drift*) and reports
   them rather than dropping them silently,
6. and creates the maildirs it has just told the daemons about — because a mailbox that
   exists in `vmailbox` but not on disk bounces the first delivery.

The HTTP request never runs that loop. Mutations write the database and queue a sync
(`internal/syncer`): requests coalesce into a single run that always renders the latest
state, every run is recorded in `reconcile_runs` (trigger, status, changed files, drift,
error), and a slow helper can no longer turn a click into a 502. The dashboard, the sync
banner and `mailx-admin doctor` all read those records.

`mailx-admin doctor` is the read-only counterpart: fifteen checks covering the schema and
its version, panel state, whether the managed files match a dry-run render (with the first
differing line called out), whether `postfix check` and `doveconf -n` accept them, entries
in Postfix/Dovecot that the panel does not know about (and that the next sync would drop),
the mail services, postfwd rate limits (the rule set *and* live probes through the daemon),
the passdb file's ownership and the password scheme, ManageSieve, the last sync, Roundcube,
DNSBL listings and outbound-IP PTRs. It exits non-zero on failure, can emit JSON, and can
write a `.tar.gz` diagnostics bundle with a redacted `admin.toml`.

---

## Requirements

- Debian or Ubuntu (the installer uses `apt`).
- Root access (the installer configures system services).
- A domain name whose DNS you control, plus a public IPv4 for the mail host.
- For the panel binary: a Linux `amd64` host (the release asset is `linux-amd64`; the
  SQLite driver requires cgo, so the release build runs in CI on Linux).
- postfwd is only needed if you configure outgoing rate limits; the panel writes its
  configuration but never installs the daemon for you.

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
need to publish (MX, A, SPF, DKIM, DMARC, TLS-RPT). The panel database defaults to
**SQLite** (no prompt); PostgreSQL is a later, optional migration done from the panel, not
the installer.

The panel is served at `https://admin.<your-domain>:9443`. The initial admin password is
written to `/root/.mailx-admin-initial-password`.

---

## The installer menu

`./Mailx-Installer` with no arguments opens the menu; every action is safe to re-run.

```
 1) Install MailX                        14) Resend DKIM / DNS records to email
 2) Show installation status             15) View SSL certificate details
 3) Cleanup state (reset stages)         16) Renew SSL certificates now
 4) Full uninstall (MailX + stack)       17) Configure SSL auto-renewal & notifications
 5) Uninstall Roundcube only             18) Enable SSL on webmail (Roundcube)
 6) Add MailX user (mailbox)             19) Show admin panel URL & credentials
 7) Send a test mail                     20) Restart admin panel
 8) Change domain / hostname             21) Repair admin panel web access
 9) Add email domain                     22) Update mailx-admin to latest release
10) Remove email domain                  23) Setup Composer & Roundcube user
11) Change SMTP port (add custom)        24) Install Roundcube plugins
12) Repair Postfix configuration         25) Manage UFW ports (list/add/remove/ranges)
13) View DKIM / DNS records              26) Repair webmail filters (ManageSieve)
```

Non-interactive entry points and environment variables:

```bash
./Mailx-Installer update        # update the panel only (alias: --update)
MAILX_ADMIN_FORCE_REINSTALL=1 ./Mailx-Installer
MAILX_ADMIN_BINARY_URL=… MAILX_ADMIN_SHA_URL=… ./Mailx-Installer   # mirror / offline
MAILX_ADMIN_BINARY_LOCAL=/tmp/mailx-admin ./Mailx-Installer       # self-built binary
```

`MAILX_ADMIN_BINARY_URL` and `MAILX_ADMIN_BINARY_LOCAL` are how a non-`amd64` host, an
air-gapped server, or a modified build gets installed: the default is the published
`linux-amd64` asset plus `SHA256SUMS`.

---

## Updating

There are four ways to update the panel.

**1. From the panel (recommended)** — *System → Updates* checks GitHub releases and
applies the newest binary, verifying its SHA-256 before replacing it. The panel re-checks
every six hours and shows a banner when a release is available.

**2. From the installer** — `./Mailx-Installer update` (or menu option 22) does the same
thing from a shell: download, verify, run `mailx-admin migrate`, then `mailx-admin
reconcile`, then restart the service.

**3. Re-run the installer** — re-fetch it and force a reinstall:

```bash
curl -fsSLO https://github.com/gtmylab/mailx-admin/releases/latest/download/Mailx-Installer
chmod +x Mailx-Installer
MAILX_ADMIN_FORCE_REINSTALL=1 ./Mailx-Installer
```

**4. Manually** — download the binary and its checksums, verify, replace and restart:

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
carefully — the panel reads it on every start, and the database page rewrites the
`[database]` section when you migrate to PostgreSQL.

```toml
[server]
listen_addr = "127.0.0.1:9090"     # where the Go HTTP server listens
base_url    = "https://admin.example.com"
hostname    = "mail.example.com"   # also myhostname / HELO identity

[database]
driver = "sqlite"                  # "sqlite" or "postgres"

[database.sqlite]
path = "/var/lib/mailx/state.db"

[database.postgres]                # used only when driver = "postgres"
host     = "127.0.0.1"
port     = 5432
user     = "mailx_admin"
password = ""                      # MAILX_DB_PASSWORD overrides this
dbname   = "mailx_admin"
sslmode  = "disable"

[mail]
postfix_conf_dir    = "/etc/postfix"
dovecot_conf_dir    = "/etc/dovecot"
opendkim_dir        = "/etc/opendkim"
primary_domain_file = "/usr/local/roundcube_mail_domain.txt"
passwd_scheme       = "auto"       # "auto" asks Dovecot (ARGON2ID / SSHA512)

[roundcube]
enabled         = true             # pre-seed users/identities for new mailboxes
database        = "roundcubemail"
binary          = "mysql"
args            = ["--defaults-file=/etc/mailx/roundcube.my.cnf"]
mail_host       = "localhost"
language        = "en_GB"
name            = ""               # display name of the default identity
timeout_seconds = 0                # 0 = the client's own default

[dns]
resolver = "1.1.1.1:53"            # used by DNS checks, DNSBL checks and PTR lookups

[logs]
mail_log_path  = "/var/log/mail.log"
retention_days = 365               # mail events kept for the per-user history
```

Every section has a working default (`dns.resolver` → `1.1.1.1:53`,
`logs.mail_log_path` → `/var/log/mail.log`, `logs.retention_days` → `365`), and
`MAILX_DB_PASSWORD` overrides `database.postgres.password` so the password does not have
to live in the file.

Most of what the panel renders is configured in the database rather than in this file:
hostname, DNS resolver and webmail host are editable from *System → Server*, ports and rate
limits belong to the domain, and the PostgreSQL migration rewrites `[database]` for you.

---

## Command-line reference

The same binary that serves the web UI is also a CLI. It reads the config from
`/etc/mailx/admin.toml` unless `--config` is given.

```
mailx-admin serve              Run the admin HTTP server
                               --auto-seed     adopt existing server state on an empty DB
                               --require-seed  refuse to start if the DB is empty

mailx-admin migrate            Apply database migrations

mailx-admin reconcile          Render, apply and validate daemon configs from DB state
   (alias: sync)               --dry-run  show what would change without applying
                               --json     print the result as JSON

mailx-admin status             Show a summary of the current DB state

mailx-admin doctor             Read-only check that the panel, DB and daemons agree
                               --json           machine-readable report
                               --bundle <file>  also write a diagnostics .tar.gz
                               --skip-services  skip the systemctl checks

mailx-admin seed               One-time adoption of an existing install into the DB
                               --dry-run / --yes

mailx-admin adopt              Import domains, mailboxes and aliases that exist on the
                               server but are not in the panel (safe to re-run)
                               --dry-run / --yes / --json

mailx-admin user create <name> Create an admin panel user     (--role admin|readonly)
mailx-admin user passwd <name> Change an admin user's password
mailx-admin user list          List admin panel users

mailx-admin mailbox add <local>@<domain>     Create a mailbox and apply it
                               --quota <MB>          quota in megabytes (default 1024)
                               --password / --password-stdin
                               --kind virtual|system --passwd-file / --shadow-file
                               --json
mailx-admin mailbox list                     List known mailboxes        (--all, --json)
mailx-admin mailbox remove <local>@<domain>  Remove a mailbox from the panel      (--yes)

mailx-admin roundcube sync     Create the Roundcube account of every mailbox missing one
                               --dry-run / --json

mailx-admin cron run <id>      Run a scheduled job and record its result — what the
                               rendered /etc/cron.d/mailx-admin invokes
```

`mailx-admin sync` is an alias for `mailx-admin reconcile`: the panel calls this a *sync*
everywhere an operator can see it (the banner, the dashboard, "the last sync"), so both
spellings work and do exactly the same thing.

`mailbox add` and `mailbox remove` go through the same path the panel uses — the database
row, the rendered configuration, the maildir and the reload — which is why the installer's
*Add MailX User* action creates a mailbox the panel can see and the next sync keeps.
`--kind system` records a mailbox that belongs to an existing Unix account: its uid, gid
and home are read from `/etc/passwd` and, unless you set a password, the account's own
password from `/etc/shadow` is reused, so the account itself is untouched.
`mailbox remove` deliberately leaves the maildir and the Unix account alone: it stops the
address from receiving mail, it does not destroy the mail.

---

## Public API

The panel exposes a small REST API for automation, authenticated with a key from
*Settings → API & Webhooks*:

```bash
curl -H "Authorization: Bearer $MAILX_API_KEY" https://admin.example.com:9443/api/v1/...
```

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/suppressions` | List suppressions |
| `POST` | `/api/v1/suppressions` | Add one (`email`, `reason`, `source`) |
| `DELETE` | `/api/v1/suppressions/{email}` | Remove a suppression |
| `POST` | `/api/v1/messages` | Send a transactional message (inline or from a template) |
| `GET` | `/api/v1/messages` | Message history (`days`, `limit`, `tag`) |
| `GET` | `/api/v1/messages/{id}` | One message's status |
| `GET` | `/api/v1/templates` | List templates |
| `POST` | `/api/v1/templates` | Create or replace a template |
| `GET` | `/api/v1/templates/{name}` | Read one template |
| `DELETE` | `/api/v1/templates/{name}` | Delete a template |

A transactional send takes `from`, `to` (string or array), `cc`, `bcc`, `reply_to`,
`subject`, `text`, `html`, `headers`, `attachments` (base64, inline or not), `tag`,
`idempotency_key` and either the inline body or `template` + `variables`:

```json
{
  "from": "noreply@example.com",
  "to": ["customer@example.net"],
  "template": "receipt",
  "variables": {"name": "Ada", "total": "42.00"},
  "tag": "billing",
  "idempotency_key": "receipt-1041"
}
```

Template placeholders are `{{name}}`; explicit fields override what the template renders.
Repeating a request with the same `idempotency_key` does not send twice.

Keys carry a scope: `read` can fetch, `write` can also send and mutate, `admin` can do
everything the API offers. The key itself is shown once when it is created and only its
SHA-256 digest is stored, and the API is served from the same listener as the panel, so it
is reachable through the Apache vhost too.

Outbound webhooks live on the same page. Each delivery is signed with HMAC-SHA256 over the
request body (`X-MailX-Signature`, with the event in `X-MailX-Event`) and every attempt is
recorded with its response, so a receiver that keeps failing is visible in the panel rather
than in a log nobody reads.

---

## Building from source

You need Go **1.25** or newer. The SQLite driver (`mattn/go-sqlite3`) needs cgo, so a real
build needs a C toolchain; the Windows target deliberately builds without it.

```bash
git clone https://github.com/gtmylab/mailx-admin.git
cd mailx-admin

make build                  # native build (cgo + SQLite) — the production binary on Linux
make build-linux            # release artifact: linux/amd64, must run on Linux (cgo)
make build-windows          # Windows dev build (no cgo: SQLite stub, UI work only)
make build-static           # static smoke-test build, cannot open a SQLite database

make test                   # go test ./... -race -count=1
make lint                   # gofmt -l -w . && go vet ./...
make release                # build-linux + SHA256SUMS in bin/
make install                # install bin/mailx-admin into /usr/local/bin
make version                # print what the next build will stamp
```

`make build`/`make build-linux` stamp the version, commit and build date into
`internal/version` via linker flags, so `mailx-admin --version`, the startup log line and
`/metrics` all report the exact build on every platform. The version is resolved from
`git describe`, then the `VERSION` file, then `dev`.

CI runs `gofmt`, `go vet` and `make test` (with `-race`) on every push and pull request on
a Linux runner, and `release.yml` repeats the same suite for a tag before building the
`linux-amd64` artifact, asserting that the binary reports the tagged version, and
publishing it together with `SHA256SUMS` and `Mailx-Installer`.

---

## Project layout

```
cmd/mailx-admin/       the CLI entry point and subcommands (serve, reconcile, doctor, …)
internal/auth/         sessions, password hashing, CSRF, TOTP
internal/config/       admin.toml loading, defaults and saving
internal/db/           SQLite / PostgreSQL driver + migrations
internal/dbmigrate/    SQLite → PostgreSQL migration
internal/store/        typed access to the database
internal/models/       the rows the store and the reconciler share
internal/mutations/    the panel's write path: DB + reconcile + audit, in that order
internal/reconciler/   renders DB state into Postfix/Dovecot/OpenDKIM/postfwd/sieve configs
internal/syncer/       the background, coalescing reconcile queue + reconcile_runs history
internal/doctor/       the read-only consistency checks behind `doctor` and the panel
internal/server/       HTTP handlers, router, templates, static assets
internal/ports/        listener rendering for master.cf
internal/postfwd/      postfwd probe client used by the doctor
internal/dovecot/      password schemes and login/hash probes
internal/dkim/         OpenDKIM key generation
internal/dns/          record plan, live checks, DNSBL lookups
internal/ssl/          certbot, certificates and renewal notifications
internal/smtp/         the SMTP client behind test-send
internal/importer/     IMAP / mbox / maildir import, queued and resumable
internal/logs/         mail.log + journald ingestion and pruning
internal/jobs/         scheduled monitoring (blocklist, quota, PTR, outbound IPs)
internal/cron/         /etc/cron.d rendering and job execution
internal/backup/       archive creation and restore
internal/apt/          package listing and upgrades
internal/update/       self-update (check/apply GitHub releases)
internal/queue/        Postfix queue inspection and flush/delete
internal/metrics/      Prometheus exposition
internal/seed/         adoption of pre-existing server state
internal/webhooks/     signed outbound event delivery
internal/…             audit, execx, maildir, roundcube, sieve, system, version, …
Mailx-Installer        the bash installer/upgrader
.github/workflows/     CI (gofmt + vet + tests on every push) and Release (per tag)
```

---

## Contributing

Contributors are welcome — bug reports, fixes, documentation and feature ideas all help.
Please:

1. Open an issue first for anything non-trivial, so the approach can be agreed before you
   write code.
2. Follow the existing conventions (the code is `gofmt`-formatted; `make lint` runs
   `gofmt -l -w .` and `go vet ./...`).
3. Add or update tests, and run `make test` before submitting — the SQLite tests require
   cgo, so run them on Linux (or rely on the CI workflow, which does).
4. Keep changes to the installer idempotent: a re-run must not break an existing install.
5. If you add a hint or an error message that tells an operator to run something, use a
   command that exists — `cmd/mailx-admin/commands_test.go` walks the command tree and fails
   when the panel mentions a `mailx-admin …` invocation it cannot resolve.

CI runs `make test` on every push to `main` and every pull request.

---

## License

This repository does not currently ship a `LICENSE` file. Contact the maintainer
(`gtmylab`) for terms before redistributing.
