-- +goose Up
ALTER TABLE suppressions ADD COLUMN direction TEXT NOT NULL DEFAULT 'out';
ALTER TABLE suppressions ADD COLUMN match_type TEXT NOT NULL DEFAULT 'email';

-- +goose Down
ALTER TABLE suppressions DROP COLUMN direction;
ALTER TABLE suppressions DROP COLUMN match_type;
