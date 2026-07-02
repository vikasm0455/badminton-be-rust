-- Multi-tenancy: RallyUp goes public. Users sign up openly, create groups, and
-- invite others by email. Polls/reservations are scoped per group; court logins
-- belong to their poster and are shared to chosen groups. kCal stays personal.
--
-- The final DO block migrates an existing single-tenant deployment into a
-- default "Bintang Badminton" group (no-op on a fresh database).

-- ---- groups -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(60) NOT NULL,
    created_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Per-group auto-poll scheduler (was global app_config). Off by default for
    -- new groups; the backfill below copies the old global settings for Bintang.
    auto_poll_enabled   BOOLEAN NOT NULL DEFAULT false,
    auto_poll_time      TIME    NOT NULL DEFAULT '10:00',
    auto_poll_note      VARCHAR(120) NOT NULL DEFAULT '',
    final_reminder_time TIME    NOT NULL DEFAULT '17:00'
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id  UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role      VARCHAR(10) NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members (user_id);

-- Email invites: acceptance is by email match after the invitee logs in/signs up.
CREATE TABLE IF NOT EXISTS group_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    email       VARCHAR(254) NOT NULL,
    invited_by  UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    declined_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_group_invites_email ON group_invites (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_group_invites_group ON group_invites (group_id);
-- One live invite per (group, email).
CREATE UNIQUE INDEX IF NOT EXISTS uniq_pending_invite
    ON group_invites (group_id, LOWER(email))
    WHERE accepted_at IS NULL AND declined_at IS NULL AND revoked_at IS NULL;

-- The group a user is currently "playing with" — scopes the whole app UI.
ALTER TABLE users ADD COLUMN IF NOT EXISTS active_group_id UUID REFERENCES groups(id) ON DELETE SET NULL;

-- ---- group scoping on existing tables ----------------------------------------
ALTER TABLE polls ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES groups(id) ON DELETE CASCADE;
ALTER TABLE court_reservations ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES groups(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_polls_group_date ON polls (group_id, game_date);
CREATE INDEX IF NOT EXISTS idx_reservations_group ON court_reservations (group_id, game_date, status);

-- One poll per group per date (was one per date globally).
ALTER TABLE polls DROP CONSTRAINT IF EXISTS unique_poll_per_date;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_poll_group_date ON polls (group_id, game_date);

-- Queue-slot duplicate guard becomes per-group: groups can't see each other's
-- reservations, so a cross-group hard block would be an invisible conflict.
DROP INDEX IF EXISTS uniq_active_court_queue_slot;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_court_queue_slot
    ON court_reservations (group_id, game_date, court_number, queue_number)
    WHERE status = 'active' AND queue_number IS NOT NULL;

-- A court login is owned by its poster and shared to chosen groups; only those
-- groups can see/attach it.
CREATE TABLE IF NOT EXISTS credential_shares (
    credential_id UUID NOT NULL REFERENCES court_credentials(id) ON DELETE CASCADE,
    group_id      UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (credential_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_credential_shares_group ON credential_shares (group_id);

-- ---- single-tenant → default-group backfill -----------------------------------
-- Runs once: creates "Bintang Badminton", moves every existing user in (admins
-- keep admin), points all legacy polls/reservations at it, shares all existing
-- logins with it, and copies the old global auto-poll settings onto it.
DO $$
DECLARE
    gid UUID;
    owner_id UUID;
BEGIN
    IF EXISTS (SELECT 1 FROM groups) THEN
        RETURN; -- already migrated (or fresh multi-tenant install with groups)
    END IF;

    SELECT id INTO owner_id FROM users
    WHERE role = 'admin' AND status = 'active'
    ORDER BY created_at ASC LIMIT 1;
    IF owner_id IS NULL THEN
        SELECT id INTO owner_id FROM users ORDER BY created_at ASC LIMIT 1;
    END IF;
    IF owner_id IS NULL THEN
        RETURN; -- fresh database, nothing to backfill
    END IF;

    INSERT INTO groups (name, created_by, auto_poll_enabled, auto_poll_time, auto_poll_note, final_reminder_time)
    VALUES (
        'Bintang Badminton',
        owner_id,
        COALESCE((SELECT value FROM app_config WHERE key = 'auto_poll_enabled'), 'true') = 'true',
        COALESCE((SELECT value FROM app_config WHERE key = 'auto_poll_time'), '10:00')::time,
        COALESCE((SELECT value FROM app_config WHERE key = 'auto_poll_note'), ''),
        COALESCE((SELECT value FROM app_config WHERE key = 'auto_poll_final_reminder_time'), '17:00')::time
    )
    RETURNING id INTO gid;

    -- Every existing (non-rejected/deactivated) member joins the group; site
    -- admins become group admins. Pending users are grandfathered active —
    -- membership, not approval, now gates access.
    INSERT INTO group_members (group_id, user_id, role)
    SELECT gid, id, CASE WHEN role = 'admin' THEN 'admin' ELSE 'member' END
    FROM users WHERE status IN ('active', 'pending');

    UPDATE users SET status = 'active' WHERE status = 'pending';
    UPDATE users SET active_group_id = gid WHERE status = 'active';

    UPDATE polls SET group_id = gid WHERE group_id IS NULL;
    UPDATE court_reservations SET group_id = gid WHERE group_id IS NULL;

    INSERT INTO credential_shares (credential_id, group_id)
    SELECT id, gid FROM court_credentials
    ON CONFLICT DO NOTHING;
END $$;
