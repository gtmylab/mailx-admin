-- +goose Up
-- +goose StatementBegin

-- Cached DNS check results, refreshed on demand
CREATE TABLE dns_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id       INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    record_type     TEXT NOT NULL,           -- TXT, MX, A, AAAA, CNAME
    record_name     TEXT NOT NULL,           -- e.g. "default._domainkey.example.com"
    expected_value  TEXT,
    observed_value  TEXT,
    status          TEXT NOT NULL,           -- ok, missing, mismatch, error
    checked_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    message         TEXT
);

CREATE INDEX idx_dns_checks_domain ON dns_checks(domain_id, checked_at DESC);

-- Cached SSL certificate info per domain
CREATE TABLE ssl_certs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id       INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    cert_name       TEXT NOT NULL,           -- certbot cert name (usually domain)
    subject         TEXT,
    issuer          TEXT,
    not_before      TIMESTAMP,
    not_after       TIMESTAMP,
    days_left       INTEGER,
    sans            TEXT,                    -- JSON array
    serial          TEXT,
    sig_alg         TEXT,
    key_bits        INTEGER,
    chain_count     INTEGER,
    status          TEXT,                    -- ok, warning, critical, expired, missing
    last_checked    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, cert_name)
);

-- Test email sends, for audit and history
CREATE TABLE test_sends (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user_id   INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
    from_addr       TEXT NOT NULL,
    to_addr         TEXT NOT NULL,
    subject         TEXT,
    smtp_host       TEXT NOT NULL,
    smtp_port       INTEGER NOT NULL,
    tls_mode        TEXT,                    -- starttls, implicit, none
    auth_used       INTEGER NOT NULL DEFAULT 0,
    success         INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER,
    transcript      TEXT,                    -- full SMTP conversation
    error           TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_test_sends_ts ON test_sends(created_at DESC);

-- Settings used by SSL/notification features
INSERT OR IGNORE INTO settings (key, value) VALUES
    ('ssl_admin_email', ''),
    ('ssl_warn_days', '14'),
    ('ssl_last_notified_warning', ''),
    ('ssl_last_notified_failure', '');

-- +goose StatementEnd

-- +goose Down
DROP TABLE dns_checks;
DROP TABLE ssl_certs;
DROP TABLE test_sends;
DELETE FROM settings WHERE key IN ('ssl_admin_email', 'ssl_warn_days', 'ssl_last_notified_warning', 'ssl_last_notified_failure');