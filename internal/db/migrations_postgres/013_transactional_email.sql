-- +goose Up
CREATE TABLE api_messages (
    id              BIGSERIAL PRIMARY KEY,
    api_key_id      INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
    message_id      TEXT NOT NULL,
    from_addr       TEXT NOT NULL,
    to_addr         TEXT NOT NULL,
    cc              TEXT NOT NULL DEFAULT '',
    bcc             TEXT NOT NULL DEFAULT '',
    reply_to        TEXT NOT NULL DEFAULT '',
    subject         TEXT NOT NULL DEFAULT '',
    tag             TEXT NOT NULL DEFAULT '',
    template        TEXT NOT NULL DEFAULT '',
    headers         TEXT NOT NULL DEFAULT '',
    attachments     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'queued',
    error           TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_messages_ts    ON api_messages(created_at DESC);
CREATE INDEX idx_api_messages_tag   ON api_messages(tag, created_at DESC);
CREATE INDEX idx_api_messages_msgid ON api_messages(message_id);
CREATE UNIQUE INDEX idx_api_messages_idem ON api_messages(api_key_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE api_templates (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    subject    TEXT NOT NULL DEFAULT '',
    text       TEXT NOT NULL DEFAULT '',
    html       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down
DROP TABLE api_templates;
DROP TABLE api_messages;
