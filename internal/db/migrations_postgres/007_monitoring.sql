-- +goose Up
-- +goose StatementBegin

CREATE TABLE outbound_ips (
    id         BIGSERIAL PRIMARY KEY,
    ip         TEXT NOT NULL UNIQUE,
    mode       TEXT NOT NULL DEFAULT 'disabled',
    priority   INTEGER NOT NULL DEFAULT 0,
    active     INTEGER NOT NULL DEFAULT 1,
    ptr_ok     INTEGER,
    ptr_record TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE outbound_rules (
    id          BIGSERIAL PRIMARY KEY,
    ip_id       INTEGER NOT NULL REFERENCES outbound_ips(id) ON DELETE CASCADE,
    match_type  TEXT NOT NULL,
    match_value TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_outbound_rules_ip ON outbound_rules(ip_id);

CREATE TABLE blocklist_checks (
    id         BIGSERIAL PRIMARY KEY,
    list       TEXT NOT NULL,
    zone       TEXT NOT NULL,
    ip         TEXT NOT NULL,
    status     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_blocklist_lookup ON blocklist_checks(list, ip, checked_at);

CREATE TABLE suppressions (
    id         BIGSERIAL PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    reason     TEXT NOT NULL,
    source     TEXT NOT NULL DEFAULT 'manual',
    notes      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE TABLE quota_samples (
    id         BIGSERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bytes_used BIGINT NOT NULL,
    messages   INTEGER NOT NULL DEFAULT 0,
    sampled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_quota_user ON quota_samples(user_id, sampled_at);

CREATE TABLE api_keys (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    key_hash     TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'read',
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    expires_at   TIMESTAMP
);

CREATE TABLE webhooks (
    id         BIGSERIAL PRIMARY KEY,
    url        TEXT NOT NULL,
    events     TEXT NOT NULL,
    secret     TEXT NOT NULL DEFAULT '',
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE webhook_deliveries (
    id           BIGSERIAL PRIMARY KEY,
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
