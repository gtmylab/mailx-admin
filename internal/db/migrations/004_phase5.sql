-- +goose Up
-- +goose StatementBegin

-- Per-user Sieve rules (before they're rendered to the user's Sieve script)
CREATE TABLE sieve_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule_type       TEXT NOT NULL,       -- vacation, forward, move_folder, discard, mark_read
    enabled         INTEGER NOT NULL DEFAULT 1,
    position        INTEGER NOT NULL DEFAULT 0,
    config          TEXT NOT NULL,       -- JSON blob, shape depends on rule_type
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sieve_rules_user ON sieve_rules(user_id, position);

-- Custom Postfix ports (additional listeners managed by the panel)
CREATE TABLE port_listeners (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    port            INTEGER NOT NULL UNIQUE,
    service         TEXT NOT NULL DEFAULT 'smtpd',
    tls_mode        TEXT NOT NULL DEFAULT 'may',  -- may, encrypt, none
    require_sasl    INTEGER NOT NULL DEFAULT 1,
    description     TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Queue manipulation history (retry/delete actions)
CREATE TABLE queue_actions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user_id   INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
    queue_id        TEXT NOT NULL,
    action          TEXT NOT NULL,     -- retry, delete, hold, release
    result          TEXT NOT NULL,     -- ok, error
    message         TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_queue_actions_ts ON queue_actions(created_at DESC);
CREATE INDEX idx_queue_actions_qid ON queue_actions(queue_id);

-- Backup history
CREATE TABLE backups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    path            TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    kind            TEXT NOT NULL,     -- manual, scheduled
    status          TEXT NOT NULL DEFAULT 'running',  -- running, ok, error
    started_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     TIMESTAMP,
    error           TEXT,
    manifest        TEXT                -- JSON: what was included
);

CREATE INDEX idx_backups_started ON backups(started_at DESC);

-- +goose StatementEnd

-- +goose Down
DROP TABLE backups;
DROP TABLE queue_actions;
DROP TABLE port_listeners;
DROP TABLE sieve_rules;