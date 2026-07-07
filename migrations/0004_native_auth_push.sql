-- Native mobile apps (Phase 0): bearer-token auth + APNs/FCM push.
--
-- refresh_tokens: rotating, single-use refresh tokens for the iOS/Android apps.
-- Only a SHA-256 hash of the secret is stored. `family` ties a rotation chain
-- together: if an already-used token is presented again (theft/replay), the
-- whole family is revoked.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,          -- sha256 hex
    family     UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,                       -- set when rotated (single-use)
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens (family);

-- device_tokens: APNs (iOS) / FCM (Android) push registrations per device.
CREATE TABLE IF NOT EXISTS device_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform        VARCHAR(8) NOT NULL CHECK (platform IN ('apns', 'fcm')),
    token           TEXT NOT NULL UNIQUE,
    device_label    VARCHAR(100),
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_success_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens (user_id) WHERE active;
