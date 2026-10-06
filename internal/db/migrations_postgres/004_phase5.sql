-- +goose Up
-- +goose StatementBegin

-- Per-user Sieve rules
CREATE TABLE sieve_rules (
    id              BIGSERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule_type       TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    position        INTEGER NOT NULL DEFAULT 0,
    config          TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sieve_rules_user ON sieve_rules(user_id, position);

-- Custom Postfix ports
CREATE TABLE port_listeners (
    id              BIGSERIAL PRIMARY KEY,
    port            INTEGER NOT NULL UNIQUE,
    service         TEXT NOT NULL DEFAULT 'smtpd',
    tls_mode        TEXT NOT NULL DEFAULT 'may',
    require_sasl    INTEGER NOT NULL DEFAULT 1,
    description     TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Queue manipulation history
CREATE TABLE queue_actions (
    id              BIGSERIAL PRIMARY KEY,
    admin_user_id   INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
    queue_id        TEXT NOT NULL,
    action          TEXT NOT NULL,
    result          TEXT NOT NULL,
    message         TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_queue_actions_ts ON queue_actions(created_at DESC);
CREATE INDEX idx_queue_actions_qid ON queue_actions(queue_id);

-- Backup history
CREATE TABLE backups (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    path            TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    kind            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running',
    started_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at     TIMESTAMP,
    error           TEXT,
    manifest        TEXT
);

CREATE INDEX idx_backups_started ON backups(started_at DESC);

-- +goose StatementEnd

-- +goose Down
DROP TABLE backups;
DROP TABLE queue_actions;
DROP TABLE port_listeners;
DROP TABLE sieve_rules;
