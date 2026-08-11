-- Courts v1 (multi-tenant club court boards): tenant clubs, their admins,
-- front-desk player credentials, physical courts, live sessions and per-court
-- queues. Additive — nothing existing is touched.
--
-- Concurrency contract: every take/join/queue/engine mutation runs in a
-- transaction that first calls
--   pg_advisory_xact_lock(hashtext(club_id::text || ':' || court_number::text))
-- so a court's state machine is single-writer.

CREATE TABLE clubs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT UNIQUE NOT NULL CHECK (slug ~ '^[a-z0-9-]{3,32}$'),
    name TEXT NOT NULL,
    brand_color TEXT NOT NULL DEFAULT '#b06f3c',
    court_count INT NOT NULL,
    session_minutes INT NOT NULL DEFAULT 45,
    queue_depth INT NOT NULL DEFAULT 3,
    auto_extend BOOLEAN NOT NULL DEFAULT TRUE,
    opens_at TIME NOT NULL DEFAULT '06:00',
    closes_at TIME NOT NULL DEFAULT '22:00',
    -- Same-day window only: an inverted pair would make open_now() permanently
    -- false (kiosk bricked). Belt-and-braces under the FOR UPDATE re-check in
    -- admin_patch_config — a lost race 400s here instead of committing.
    CONSTRAINT clubs_hours_window CHECK (closes_at > opens_at),
    kiosk_theme TEXT NOT NULL DEFAULT 'light',
    status TEXT NOT NULL DEFAULT 'onboarding'
        CHECK (status IN ('onboarding', 'live', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE club_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    club_id UUID NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    must_change BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Plaintext password is deliberate: the front desk reprints slips, same trust
-- level as the physical slips + parity with the app's stored kiosk logins.
CREATE TABLE club_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    club_id UUID NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (club_id, username)
);

-- Rows seeded 1..court_count on club create; raising court_count inserts the
-- missing rows, lowering it is forbidden while sessions are active on the
-- removed courts.
CREATE TABLE club_courts (
    club_id UUID NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    number INT NOT NULL,
    closed BOOLEAN NOT NULL DEFAULT FALSE,
    closed_reason TEXT,
    PRIMARY KEY (club_id, number)
);

CREATE TABLE court_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    club_id UUID NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    court_number INT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ends_at TIMESTAMPTZ NOT NULL,
    extensions INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'done'))
);

-- One live game per court.
CREATE UNIQUE INDEX court_sessions_one_active
    ON court_sessions (club_id, court_number) WHERE status = 'active';

CREATE TABLE session_players (
    session_id UUID NOT NULL REFERENCES court_sessions(id) ON DELETE CASCADE,
    credential_id UUID NOT NULL REFERENCES club_credentials(id) ON DELETE CASCADE,
    PRIMARY KEY (session_id, credential_id)
);

CREATE TABLE court_queues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    club_id UUID NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    court_number INT NOT NULL,
    position INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (club_id, court_number, position)
);

CREATE TABLE queue_players (
    queue_id UUID NOT NULL REFERENCES court_queues(id) ON DELETE CASCADE,
    credential_id UUID NOT NULL REFERENCES club_credentials(id) ON DELETE CASCADE,
    PRIMARY KEY (queue_id, credential_id)
);

-- Fast lookups for the double-use check (a credential may sit in at most one
-- active session OR one queue group) and for board rendering.
CREATE INDEX session_players_credential ON session_players (credential_id);
CREATE INDEX queue_players_credential ON queue_players (credential_id);
CREATE INDEX court_sessions_active_expiry ON court_sessions (ends_at) WHERE status = 'active';
