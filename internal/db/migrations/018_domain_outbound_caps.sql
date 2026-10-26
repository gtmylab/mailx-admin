-- +goose Up
-- Day and month caps on top of the hourly limit from 017. Same unit (messages,
-- 0 = no cap) and the same enforcement: postfwd renders one rate() rule per
-- window, so a domain can have an hourly limit, a daily one, a monthly one, or
-- any combination.
--
-- The windows are rolling, not calendar: postfwd counts the last 86400 and the
-- last 2592000 seconds. The panel labels them "per day" and "per month" and says
-- so, because a calendar-month cap cannot be expressed in postfwd without a
-- counter reset at midnight, and a reset is a bypass.
ALTER TABLE domains ADD COLUMN outbound_rate_daily INTEGER NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN outbound_rate_monthly INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE domains DROP COLUMN outbound_rate_monthly;
ALTER TABLE domains DROP COLUMN outbound_rate_daily;
