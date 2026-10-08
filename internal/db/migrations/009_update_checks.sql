-- +goose Up
CREATE TABLE update_checks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at TIMESTAMP NOT NULL,
    current    TEXT NOT NULL DEFAULT '',
    latest     TEXT NOT NULL DEFAULT '',
    available  INTEGER NOT NULL DEFAULT 0,
    up_to_date INTEGER NOT NULL DEFAULT 0,
    error      TEXT NOT NULL DEFAULT '',
    notes      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_update_checks_ts ON update_checks(checked_at DESC);

-- +goose Down
DROP TABLE update_checks;
