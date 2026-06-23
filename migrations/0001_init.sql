-- RallyUp — Bintang Badminton Group App
-- Initial schema. All 11 tables from PRD §12. Times are TIMESTAMPTZ; the app
-- treats America/Los_Angeles as the wall-clock timezone for game_date math.

-- 12.1 users -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name    VARCHAR(30)  NOT NULL,
    email           VARCHAR(254) NOT NULL UNIQUE,
    role            VARCHAR(10)  NOT NULL DEFAULT 'member',   -- 'admin' | 'member'
    status          VARCHAR(15)  NOT NULL DEFAULT 'pending',  -- 'pending' | 'active' | 'deactivated' | 'rejected'
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    approved_at     TIMESTAMPTZ,
    approved_by     UUID REFERENCES users(id),
    last_active_at  TIMESTAMPTZ,
    deactivated_at  TIMESTAMPTZ
);

-- Notification preferences (which event types a user wants). JSONB map of
-- event-category -> bool; absent key means "send" (opt-out model).
ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_prefs JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 12.2 invite_codes ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS invite_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        VARCHAR(12) NOT NULL UNIQUE,
    created_by  UUID NOT NULL REFERENCES users(id),
    used_by     UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_code ON invite_codes (code);

-- 12.3 polls -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS polls (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by    UUID NOT NULL REFERENCES users(id),
    game_date     DATE NOT NULL,
    proposed_time TIME NOT NULL,
    note          VARCHAR(120),
    auto_created  BOOLEAN NOT NULL DEFAULT false,
    attendance_locked BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_poll_per_date UNIQUE (game_date)
);

-- 12.4 poll_votes ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS poll_votes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    poll_id    UUID NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id),
    vote       VARCHAR(5) NOT NULL,   -- 'yes' | 'no' | 'maybe'
    voted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    CONSTRAINT unique_vote_per_user_per_poll UNIQUE (poll_id, user_id)
);

-- 12.5 attendance ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attendance (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    poll_id      UUID NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id),
    confirmed_by UUID NOT NULL REFERENCES users(id),
    confirmed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_attendance_per_poll_user UNIQUE (poll_id, user_id)
);

-- 12.6 court_credentials -----------------------------------------------------
CREATE TABLE IF NOT EXISTS court_credentials (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    posted_by        UUID NOT NULL REFERENCES users(id),
    game_date        DATE NOT NULL,
    bintang_name     VARCHAR(50) NOT NULL,
    bintang_password VARCHAR(50) NOT NULL,
    screenshot_path  VARCHAR(500),
    posted_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_court_credentials_game_date ON court_credentials (game_date);

-- 12.7 court_reservations ----------------------------------------------------
CREATE TABLE IF NOT EXISTS court_reservations (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    court_number             SMALLINT NOT NULL CHECK (court_number BETWEEN 1 AND 53),
    credential_id            UUID REFERENCES court_credentials(id) ON DELETE SET NULL,
    credential_name_snapshot VARCHAR(50),
    reserved_by              UUID NOT NULL REFERENCES users(id),
    court_type               VARCHAR(10) NOT NULL,  -- 'full' | 'half'
    player_count             SMALLINT,
    duration_minutes         SMALLINT NOT NULL DEFAULT 45,
    start_at                 TIMESTAMPTZ NOT NULL,
    -- Computed on write (start_at + duration). NOT a GENERATED column:
    -- timestamptz + interval is only STABLE, which Postgres rejects for one.
    expiry_at                TIMESTAMPTZ NOT NULL,
    queue_number             SMALLINT,
    notes                    VARCHAR(100),
    status                   VARCHAR(10) NOT NULL DEFAULT 'active',  -- 'active' | 'completed' | 'cancelled'
    notification_sent_flags  JSONB NOT NULL DEFAULT '{}'::jsonb,
    completed_at             TIMESTAMPTZ,
    completed_by             UUID REFERENCES users(id),
    game_date                DATE NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reservations_date_status ON court_reservations (game_date, status);
CREATE INDEX IF NOT EXISTS idx_reservations_active_cred ON court_reservations (credential_id) WHERE status = 'active';

-- 12.8 kcal_logs -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kcal_logs (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id   UUID NOT NULL REFERENCES users(id),
    game_date DATE NOT NULL,
    kcal      SMALLINT NOT NULL CHECK (kcal BETWEEN 0 AND 2000),
    note      VARCHAR(100),
    logged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_kcal_per_user_per_day UNIQUE (user_id, game_date)
);

-- 12.9 push_subscriptions ----------------------------------------------------
CREATE TABLE IF NOT EXISTS push_subscriptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    endpoint        TEXT NOT NULL UNIQUE,
    p256dh          TEXT NOT NULL,
    auth            TEXT NOT NULL,
    device_label    VARCHAR(100),
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_success_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_push_subs_user ON push_subscriptions (user_id) WHERE active;

-- 12.10 security_events ------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(40) NOT NULL,
    user_id    UUID REFERENCES users(id),
    ip_address INET,
    metadata   JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_user_type ON security_events (user_id, event_type);

-- 12.11 app_config -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_config (
    key        VARCHAR(60) PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default configuration. ON CONFLICT DO NOTHING keeps operator edits.
INSERT INTO app_config (key, value) VALUES
    ('auto_poll_enabled', 'true'),
    ('auto_poll_time', '10:00'),
    ('auto_poll_note', ''),
    ('auto_poll_final_reminder_time', '17:00'),
    ('notification_batch_window_seconds', '90')
ON CONFLICT (key) DO NOTHING;
