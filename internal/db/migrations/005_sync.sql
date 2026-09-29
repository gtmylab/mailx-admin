-- +goose Up
-- +goose StatementBegin

-- reconcile_runs existed since 001 but nothing ever wrote to it, so the panel
-- had no idea whether the last config sync succeeded. v1.0.5 starts recording
-- every run (trigger, status, changed files, error) and uses that table for the
-- dashboard card, the failed-sync banner and 'mailx-admin doctor'.
--
-- drift holds the entries that were present in a managed file but not in the
-- panel (a mailbox created with `useradd`, a hand-written Postfix alias). They
-- are what used to disappear silently on the next sync.
ALTER TABLE reconcile_runs ADD COLUMN drift TEXT;

CREATE INDEX idx_reconcile_runs_started ON reconcile_runs(started_at DESC);

-- +goose StatementEnd

-- +goose Down
DROP INDEX idx_reconcile_runs_started;
-- SQLite cannot drop a column before 3.35; the column is harmless to leave.
