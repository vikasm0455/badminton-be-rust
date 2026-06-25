-- Multiple kiosk logins can belong to one court (a whole group playing/queued
-- together). Attach them all to a single reservation — one timer per court —
-- instead of creating a separate reservation+timer per login.
CREATE TABLE IF NOT EXISTS reservation_credentials (
    reservation_id UUID NOT NULL REFERENCES court_reservations(id) ON DELETE CASCADE,
    credential_id  UUID NOT NULL REFERENCES court_credentials(id)  ON DELETE CASCADE,
    name_snapshot  VARCHAR(50) NOT NULL,
    PRIMARY KEY (reservation_id, credential_id)
);
CREATE INDEX IF NOT EXISTS idx_rescred_credential ON reservation_credentials (credential_id);

-- Block a *true* duplicate: the same queue slot on the same court on the same
-- day. Distinct queue positions (#3 vs #4) and non-queued rows stay allowed.
-- First retire any pre-existing same-slot duplicates (keep the most recent) so
-- the unique index can be created on existing data.
UPDATE court_reservations c SET status = 'cancelled'
WHERE c.status = 'active' AND c.queue_number IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM court_reservations c2
    WHERE c2.status = 'active' AND c2.queue_number IS NOT NULL
      AND c2.game_date = c.game_date
      AND c2.court_number = c.court_number
      AND c2.queue_number = c.queue_number
      AND (c2.created_at > c.created_at OR (c2.created_at = c.created_at AND c2.id > c.id))
  );

CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_court_queue_slot
    ON court_reservations (game_date, court_number, queue_number)
    WHERE status = 'active' AND queue_number IS NOT NULL;
