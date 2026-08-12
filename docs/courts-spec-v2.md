# Courts v2 — day-pass model, stations, unsign, timed closures (build contract)

Extends the shipped v1 (see docs/courts-spec.md in badminton-be-rust). Approved mock:
scratchpad courts-mock/ — register.html (walk-in station), checkin.html (member
station), kiosk.html (courts-only board + leave modals), admin.html (Today's
logins + Members + timed closures + timezone).

## Locked product decisions
- EVERYTHING is a day pass: a credential is valid only on its issue day, in the
  club's timezone. No day-pass/member choice anywhere.
- Walk-ins: self-serve at a dedicated WALK-IN SIGNUP STATION (own URL). Enter
  desired username -> availability -> generated memorable password -> shown big.
  No payment logic of any kind. Username frees itself after the day.
- Members: permanent USERNAME + club-issued MEMBER ID (their existing card,
  barcode encodes the member ID; USB scanners type it like a keyboard). At the
  MEMBER CHECK-IN STATION (own URL): enter/scan member ID -> shows display name,
  permanent username, and TODAY'S freshly-generated password. Same password on
  repeat check-ins the same day. New password each day.
- The court board stays courts-only (three separate systems; small footer
  wayfinding line only).
- UNSIGN: leave a court or a queue in groups of EXACTLY 2 or 4 (mirror of
  signup; 1-or-3 never remains). Leavers authenticate with username+password.
  Whole group leaving a court ends the session and promotes the queue head
  IMMEDIATELY (same drop-revoked/expired rules as the engine). A pair leaving a
  4-queue-group leaves a pair-group behind; a pair-group leaving = group gone,
  positions renumber.
- TIMED CLOSURES: close court with custom reason + from/until (from defaults to
  now, until required, until > from). Board shows "Closed until <time> ·
  <reason>" and "reopens automatically". Court reopens itself (computed from
  the window) with a broadcast at both boundaries. Reopen button clears early.
- Admin "Today's logins": all of today's credentials WITH visible passwords
  (kind chip walkin|member, where-is-it, revoke). Any staff role may view
  (future RBAC: including read-only).
- Admin "Members": add (member ID + permanent username + optional name),
  list, remove. The old issue-credentials endpoint/UI is DELETED.
- Config: + club timezone (IANA, validated via chrono-tz, default
  America/Los_Angeles; helper: day passes expire at midnight in this tz).
  Court cap raised to 100 (config + platform create). Opening hours + day-pass
  validity + closure display all computed in club tz (v1 used server-local —
  fix it).

## Backend (badminton-be-rust)
Migration 0010_clubs_v2.sql (additive):
- clubs + timezone TEXT NOT NULL DEFAULT 'America/Los_Angeles'
- club_members: id uuid pk, club_id fk, member_ref TEXT (the partner's card ID),
  username TEXT, display_name TEXT, status TEXT default 'active'
  ('active'|'removed'), created_at; UNIQUE(club_id, member_ref),
  UNIQUE(club_id, username)
- club_credentials + kind TEXT NOT NULL DEFAULT 'walkin' ('walkin'|'member'),
  + member_id uuid NULL fk club_members, + valid_date DATE NOT NULL DEFAULT
  CURRENT_DATE; drop old unique(club_id,username), new UNIQUE(club_id,
  username, valid_date). Existing rows: kind walkin, valid_date =
  issued_at::date (they expire naturally).
- club_courts: + closed_from timestamptz NULL, + closed_until timestamptz NULL
  (keep closed/closed_reason for compat; closed state is now COMPUTED: closed
  bool OR (closed_from <= now AND now < closed_until)). Prefer migrating fully
  to the window columns; keep bool only if removal breaks v1 rows.

Validity rule (single helper): credential usable iff status='active' AND
valid_date == today(club.timezone). Used by take/join/queue/leave validation,
engine promotion drop-check, and auto-extend guard (expired == revoked
semantics). No midnight sweeps needed.

Endpoints:
Kiosk stations (public, rate-limited per IP via existing limiter patterns):
- POST /api/clubs/{slug}/walkin/check {username} -> {available, reason?}
  (charset [a-z0-9_.-]{3,20} lowercase; taken if any of: today's active
  credential with that username, OR a club_members.username)
- POST /api/clubs/{slug}/walkin/create {username} -> {username, password}
  (same validation; generate existing word-word-NN password; feature event
  walkin_created; cap per-IP creations e.g. 30/day to prevent squatting)
- POST /api/clubs/{slug}/checkin {member_ref} -> {display_name, member_ref,
  username, password} (find active member by exact member_ref; find-or-create
  TODAY's credential (kind member); same password redisplayed all day; unknown
  member_ref counts toward a per-IP+ref lockout like kiosk password failures;
  feature event member_checkin)
- POST /api/clubs/{slug}/leave {court_number, players x2|x4}: all leavers must
  be players of the court's ACTIVE session; allowed remainders {0,2}; on 0 ->
  session done + immediate promotion (factor a shared promote_next used by
  engine + here, same advisory-lock discipline: court lock + sorted credential
  locks incl. incoming promoted group); broadcast; feature event court_left.
- POST /api/clubs/{slug}/queue/leave {court_number, players x2|x4}: all in the
  SAME queue group; remainder {0,2}; renumber on removal; broadcast; event
  queue_left.
- Board: courts carry closed_until/closed_reason when closed; status computed
  from window; otherwise unchanged shape.
Admin (club_admin role, must_change + suspended rules as v1):
- GET/POST /api/clubs/{slug}/admin/members; POST /api/clubs/{slug}/admin/members/{id}/remove
  (remove frees the username for members/walk-ins from TOMORROW; today's
  credential of a removed member is revoked immediately)
- GET /api/clubs/{slug}/admin/credentials -> TODAY's credentials only:
  {id, username, password, kind, member_name?, status, where{...}} (passwords
  intentionally visible)
- DELETE the old POST admin/credentials issue endpoint entirely.
- POST /api/clubs/{slug}/admin/courts/{n}/close {reason, from?, until}
  (validate until>from>=now-5min; tz-aware display strings); reopen clears
  window+reason.
- PATCH admin/config: + timezone (chrono-tz validated), court_count 1..=100.
Platform: create accepts optional timezone; court_count 1..=100.
Engine: promotion + auto-extend use the validity helper; detect closure-window
boundary crossings each tick and broadcast so boards repaint.
Cargo: add chrono-tz. Metrics: walkin_created, member_checkin, court_left,
queue_left, club_member_added, club_member_removed + keep v1 events.
Tests (repo style, keep all 39 green): walkin availability incl. member-reserved
and freed-next-day (valid_date), checkin same-day idempotent password + new
next day (inject dates via valid_date writes), expired-cred rejected from
take/join/queue and dropped at promotion, leave-court remainder rules +
immediate promotion, leave-queue renumber, closure window computed status +
until>from validation, timezone validation rejects garbage.

## Frontend (badminton-fe)
- NEW /courts/[slug]/signup — walk-in station per register.html: big input,
  debounced availability via walkin/check, create, giant result, auto-clear
  after ~45s + Done button.
- NEW /courts/[slug]/checkin — member station per checkin.html: barcode-first
  (input ALWAYS focused — refocus on blur; Enter submits; USB scanners type +
  Enter), typed fallback is the same input, result panel, auto-clear ~45s.
- Board /courts/[slug]: add Leave court / Leave queue modals (2/4 seg, same
  CredFields, server errors inline), closed cards show until+reason+"reopens
  automatically", footer wayfinding line naming the two stations.
- Admin: config + timezone select + max 100; close modal reason+from/until;
  Today's logins table (visible password column, kind chips, member name);
  Members panel + add/remove; delete issue-credentials UI.
- lib.ts: new types/calls; keep envelope/error handling patterns.
Build must stay green; no PWA-route changes.
