-- Shareable group invite links: admin mints a link anyone can use to join
-- after signing in. One active link per group (partial unique index); links
-- expire and can be rotated/disabled, so a leaked link has a short life.

CREATE TABLE group_invite_links (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    token       TEXT NOT NULL UNIQUE,
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    join_count  INT NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX group_invite_links_one_active
    ON group_invite_links (group_id) WHERE revoked_at IS NULL;
CREATE INDEX group_invite_links_token ON group_invite_links (token);
