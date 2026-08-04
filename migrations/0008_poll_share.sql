-- Shareable poll links: a member mints one unguessable token per poll to post
-- in the group chat; the public page shows live info and lets members vote.
-- No expiry column — polls are per-day, so the link dies with the poll.

ALTER TABLE polls ADD COLUMN share_token TEXT UNIQUE;
