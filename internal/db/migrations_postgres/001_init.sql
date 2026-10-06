-- +goose Up
-- +goose StatementBegin

-- Postgres translation of 001_init.sql. Only the auto-increment primary keys
-- differ: SQLite's `INTEGER PRIMARY KEY AUTOINCREMENT` becomes BIGSERIAL, so a
-- migrated id (a 64-bit SQLite rowid) is never narrowed to a 32-bit SERIAL.

-- Domains
CREATE TABLE domains (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    is_primary      INTEGER NOT NULL DEFAULT 0,
    dkim_selector   TEXT NOT NULL DEFAULT 'default',
    dkim_private_key_path TEXT,
    dkim_public_record    TEXT,
    dkim_created_at       TIMESTAMP,
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Users (mail accounts)
CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    domain_id       INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    username        TEXT NOT NULL,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    quota_mb        INTEGER NOT NULL DEFAULT 1024,
    active          INTEGER NOT NULL DEFAULT 1,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    last_login      TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, username)
);

CREATE INDEX idx_users_domain ON users(domain_id);
CREATE INDEX idx_users_email  ON users(email);

-- Aliases (includes catch-all and forwarders)
CREATE TABLE aliases (
    id              BIGSERIAL PRIMARY KEY,
    domain_id       INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    source          TEXT NOT NULL,
    destination     TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_aliases_domain ON aliases(domain_id);
CREATE INDEX idx_aliases_source ON aliases(domain_id, source);

-- Per-user policy overrides
CREATE TABLE policies (
    id              BIGSERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key             TEXT NOT NULL,
    value           TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, key)
);

-- Settings (key/value bag for panel-wide config)
CREATE TABLE settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Admin panel users (separate from mail users)
CREATE TABLE admin_users (
    id              BIGSERIAL PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    totp_enabled    INTEGER NOT NULL DEFAULT 0,
    role            TEXT NOT NULL DEFAULT 'admin',
    active          INTEGER NOT NULL DEFAULT 1,
    last_login      TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Sessions (JWT refresh tokens)
CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    admin_user_id   INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    expires_at      TIMESTAMP NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent      TEXT,
    remote_ip       TEXT
);

-- Audit log — APPEND ONLY.
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    result          TEXT NOT NULL,
    detail          TEXT,
    remote_ip       TEXT
);

CREATE INDEX idx_audit_ts     ON audit_log(ts);
CREATE INDEX idx_audit_actor  ON audit_log(actor);
CREATE INDEX idx_audit_action ON audit_log(action);

-- Reconciler run history (for rollback)
CREATE TABLE reconcile_runs (
    id              BIGSERIAL PRIMARY KEY,
    started_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     TIMESTAMP,
    trigger         TEXT NOT NULL,
    dry_run         INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'running',
    files_changed   TEXT,
    error           TEXT
);

-- +goose StatementEnd

-- +goose Down
DROP TABLE reconcile_runs;
DROP TABLE audit_log;
DROP TABLE sessions;
DROP TABLE admin_users;
DROP TABLE settings;
DROP TABLE policies;
DROP TABLE aliases;
DROP TABLE users;
DROP TABLE domains;
