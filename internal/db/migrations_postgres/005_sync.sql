-- +goose Up
-- +goose StatementBegin

ALTER TABLE reconcile_runs ADD COLUMN drift TEXT;

CREATE INDEX idx_reconcile_runs_started ON reconcile_runs(started_at DESC);

-- +goose StatementEnd

-- +goose Down
DROP INDEX idx_reconcile_runs_started;
ALTER TABLE reconcile_runs DROP COLUMN drift;
