-- +goose Up
-- +goose StatementBegin

-- v1.0.8: a mailbox can be of two kinds, and the panel has to render both.
--
--   virtual  the panel's own model: the maildir lives under /var/mail/vhosts,
--            owned by the vmail account (uid/gid 5000), and Postfix delivers it
--            through virtual_mailbox_maps.
--   system   a mailbox that started life as a real Unix account (`useradd`,
--            the installer's "Add MailX User", an old Roundcube install) with
--            its mail in /home/<user>/Maildir. Postfix delivers it through a
--            virtual_alias to the local user, and Dovecot reads uid/gid/home
--            from the passwd-file line.
--
-- Before this the panel only knew the virtual shape. It rendered every user
-- with uid/gid 5000 and /var/mail/vhosts/... and then overwrote
-- /etc/postfix/virtual wholesale, so a mailbox created with `useradd` was
-- invisible in the panel and the alias the installer wrote for it was deleted
-- by the next sync ("my user disappeared again").
--
-- sys_uid/sys_gid/home are NULL for virtual mailboxes: the renderer falls back
-- to the vmail account and the /var/mail/vhosts layout.
ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'virtual';
ALTER TABLE users ADD COLUMN sys_uid INTEGER;
ALTER TABLE users ADD COLUMN sys_gid INTEGER;
ALTER TABLE users ADD COLUMN home TEXT;

CREATE INDEX idx_users_kind ON users(kind);

-- +goose StatementEnd

-- +goose Down
DROP INDEX idx_users_kind;
-- SQLite cannot drop a column before 3.35; the columns are harmless to leave.
