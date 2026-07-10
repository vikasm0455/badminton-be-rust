-- Per-group venue configuration: every facility numbers its courts
-- differently, so the court range moves from a hardcoded CHECK to group
-- config. Existing groups keep the historical 1–53 range; each group's
-- admin can tighten it from the app's venue settings.

ALTER TABLE groups
    ADD COLUMN IF NOT EXISTS venue_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS court_min  SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS court_max  SMALLINT NOT NULL DEFAULT 53,
    ADD CONSTRAINT groups_court_range_chk
        CHECK (court_min >= 1 AND court_max >= court_min AND court_max <= 500);

-- Validation is per-group at the application layer now.
ALTER TABLE court_reservations
    DROP CONSTRAINT IF EXISTS court_reservations_court_number_check;

-- Keep a sane global floor so bad writes can't go negative.
ALTER TABLE court_reservations
    ADD CONSTRAINT court_reservations_court_number_chk CHECK (court_number >= 1);
