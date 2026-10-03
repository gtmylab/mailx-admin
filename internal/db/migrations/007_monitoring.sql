-- +goose Up
-- +goose StatementBegin

-- Outbound IP registry. The panel owns the server's outbound addresses: it
-- auto-discovers them, lets the operator add more, and maps each one to
-- Postfix transports (see internal/reconciler RenderSenderTransport).
CREATE TABLE outbound_ips (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL UNIQUE,
    mode       TEXT NOT NULL DEFAULT 'disabled',  -- 'always' | 'rules' | 'disabled'
    priority   INTEGER NOT NULL DEFAULT 0,
    active     INTEGER NOT NULL DEFAULT 1,
    ptr_ok     INTEGER,                          -- NULL=unchecked, 0=fail, 1=pass
    ptr_record TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE outbound_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_id       INTEGER NOT NULL REFERENCES outbound_ips(id) ON DELETE CASCADE,
    match_type  TEXT NOT NULL,                   -- 'domain' | 'user' | 'email'
    match_value TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_outbound_rules_ip ON outbound_rules(ip_id);

-- Blocklist check history. "Current state" is the latest row per (list, ip).
CREATE TABLE blocklist_checks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    list       TEXT NOT NULL,
    zone       TEXT NOT NULL,
    ip         TEXT NOT NULL,
    status     TEXT NOT NULL,                    -- 'listed' | 'clean' | 'error'
    detail     TEXT NOT NULL DEFAULT '',
    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_blocklist_lookup ON blocklist_checks(list, ip, checked_at);

-- Suppression list: recipients the panel must not send to.
CREATE TABLE suppressions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL UNIQUE,
    reason     TEXT NOT NULL,                    -- 'bounce_hard' | 'complaint' | 'manual'
    source     TEXT NOT NULL DEFAULT 'manual',   -- 'admin' | 'bounce' | 'fbl'
    notes      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- Per-user mailbox usage samples (nightly doveadm quota get).
CREATE TABLE quota_samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bytes_used BIGINT NOT NULL,
    messages   INTEGER NOT NULL DEFAULT 0,
    sampled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_quota_user ON quota_samples(user_id, sampled_at);

-- API keys. Only the sha256 of the key is stored; the full key is shown once.
CREATE TABLE api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,                  -- first 8 chars, for display
    key_hash     TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'read',   -- 'read' | 'write' | 'admin'
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    expires_at   TIMESTAMP
);

-- Webhook registrations + a delivery log for retries and audit.
CREATE TABLE webhooks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL,
    events     TEXT NOT NULL,                    -- comma-separated event names
    secret     TEXT NOT NULL DEFAULT '',
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE webhook_deliveries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id   INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event        TEXT NOT NULL,
    payload      TEXT NOT NULL,
    success      INTEGER NOT NULL DEFAULT 0,
    status_code  INTEGER,
    response     TEXT NOT NULL DEFAULT '',
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose StatementEnd

-- +goose Down
DROP TABLE webhook_deliveries;
DROP TABLE webhooks;
DROP TABLE api_keys;
DROP TABLE quota_samples;
DROP TABLE suppressions;
DROP TABLE blocklist_checks;
DROP TABLE outbound_rules;
DROP TABLE outbound_ips;
