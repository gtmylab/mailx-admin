-- +goose Up
-- Per-domain outgoing rate limits, enforced by postfwd (see
-- internal/reconciler/postfwd.go). 0 means "no limit", which is what every
-- install created before this migration keeps doing.
ALTER TABLE domains ADD COLUMN outbound_rate_limit INTEGER NOT NULL DEFAULT 0;

-- Extra messages allowed in a short (60s) window on top of the hourly limit:
-- a newsletter that is normally well under the limit still needs to be able to
-- send its batch. 0 = no burst allowance.
ALTER TABLE domains ADD COLUMN outbound_rate_burst INTEGER NOT NULL DEFAULT 0;

-- What postfwd answers once the limit is reached: 'defer' (450 4.7.1, the
-- sending server retries later) or 'reject' (554 5.7.1, permanent).
ALTER TABLE domains ADD COLUMN outbound_rate_action TEXT NOT NULL DEFAULT 'defer';

-- +goose Down
ALTER TABLE domains DROP COLUMN outbound_rate_action;
ALTER TABLE domains DROP COLUMN outbound_rate_burst;
ALTER TABLE domains DROP COLUMN outbound_rate_limit;
