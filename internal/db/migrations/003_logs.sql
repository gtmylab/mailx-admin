-- +goose Up
-- +goose StatementBegin

CREATE TABLE mail_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TIMESTAMP NOT NULL,
    queue_id        TEXT,
    service         TEXT NOT NULL,           -- postfix/smtpd, postfix/qmgr, dovecot, opendkim
    action          TEXT,                    -- connect, disconnect, reject, deliver, bounce, login, ...
    status          TEXT,                    -- sent, deferred, bounced, rejected, ok
    from_addr       TEXT,
    to_addr         TEXT,
    domain          TEXT,                    -- recipient domain, for filtering
    client_ip       TEXT,
    client_hostname TEXT,
    relay           TEXT,
    size_bytes      INTEGER,
    delay_sec       REAL,
    dsn             TEXT,
    message         TEXT NOT NULL,
    raw             TEXT NOT NULL
);

CREATE INDEX idx_mail_events_ts        ON mail_events(ts DESC);
CREATE INDEX idx_mail_events_domain    ON mail_events(domain, ts DESC);
CREATE INDEX idx_mail_events_status    ON mail_events(status, ts DESC);
CREATE INDEX idx_mail_events_queueid   ON mail_events(queue_id);
CREATE INDEX idx_mail_events_from      ON mail_events(from_addr, ts DESC);

-- Log ingestion state — remembers how far we've read
CREATE TABLE log_state (
    path            TEXT PRIMARY KEY,
    inode           INTEGER,
    offset          INTEGER NOT NULL DEFAULT 0,
    last_read_ts    TIMESTAMP,
    last_seen_ts    TIMESTAMP
);

-- +goose StatementEnd

-- +goose Down
DROP TABLE mail_events;
DROP TABLE log_state;