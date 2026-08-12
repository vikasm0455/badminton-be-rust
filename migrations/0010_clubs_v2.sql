-- Courts v2: day-pass credentials, club members (permanent username + card
-- member ID), and timed court-closure windows. Additive on 0009.
--
-- Model change: EVERY credential is a day pass — usable only while
-- status='active' AND valid_date = today in the club's timezone. Usernames
-- therefore recycle daily: the v1 UNIQUE(club_id, username) becomes
-- UNIQUE(club_id, username, valid_date).

-- Day passes expire at midnight in the club's own timezone (IANA name,
-- validated by chrono-tz at the API edge).
ALTER TABLE clubs
    ADD COLUMN timezone TEXT NOT NULL DEFAULT 'America/Los_Angeles';

-- Club members: the partner's existing card (member_ref is what the barcode
-- encodes) linked to a permanent kiosk username. Removal is soft
-- (status='removed') so history survives; the partial unique indexes below
-- free a removed member's card + username for reuse.
CREATE TABLE club_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    club_id UUID NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    member_ref TEXT NOT NULL,
    username TEXT NOT NULL,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial (active-only) uniqueness: a removed member must not squat their old
-- card ID or username forever — "remove frees the username from tomorrow"
-- (today's credential row still blocks same-day reuse via the credentials
-- unique index below).
CREATE UNIQUE INDEX club_members_ref_active
    ON club_members (club_id, member_ref) WHERE status = 'active';
CREATE UNIQUE INDEX club_members_username_active
    ON club_members (club_id, username) WHERE status = 'active';

-- Credentials become day passes.
ALTER TABLE club_credentials
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'walkin' CHECK (kind IN ('walkin', 'member')),
    ADD COLUMN member_id UUID REFERENCES club_members(id) ON DELETE SET NULL,
    ADD COLUMN valid_date DATE NOT NULL DEFAULT CURRENT_DATE;

-- Existing v1 rows: all walk-ins, valid on their issue day (so they have
-- already expired naturally by the time this ships). The issue day is
-- computed in the CLUB's timezone — a bare issued_at::date would use the DB
-- server's timezone and could mis-date evening credentials by a day.
UPDATE club_credentials c
SET valid_date = (c.issued_at AT TIME ZONE cl.timezone)::date
FROM clubs cl
WHERE cl.id = c.club_id;

-- All writes set valid_date explicitly in the club's timezone; the lingering
-- server-tz CURRENT_DATE default would silently mis-date any INSERT that
-- forgot the column, so drop it.
ALTER TABLE club_credentials ALTER COLUMN valid_date DROP DEFAULT;

-- Username recycles daily.
ALTER TABLE club_credentials
    DROP CONSTRAINT club_credentials_club_id_username_key;
ALTER TABLE club_credentials
    ADD CONSTRAINT club_credentials_club_username_day UNIQUE (club_id, username, valid_date);

-- Timed closures: closed state is now COMPUTED — legacy closed bool OR
-- (closed_from <= now < closed_until). The bool is kept for v1 rows and as an
-- open-ended manual switch; new closes always write a window.
ALTER TABLE club_courts
    ADD COLUMN closed_from TIMESTAMPTZ,
    ADD COLUMN closed_until TIMESTAMPTZ;

-- Board + validation look credentials up by (club, username, day) constantly.
CREATE INDEX club_credentials_day ON club_credentials (club_id, valid_date);
