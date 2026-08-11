# BadmintonRallyUp Courts — build contract (v1)

Multi-tenant club court-reservation web product. BE extends `badminton-be-rust`
(Rust/Axum, sqlx/Postgres, Redis); FE extends `badminton-fe` (Next 14 app
router). Desktop-only web UI. Approved mock (port faithfully): scratchpad
`courts-mock/` — kiosk.html / admin.html / platform.html + shell.css
(light-first tokens, dark via [data-theme=dark], topbar layout, 5-court grid).

## Product rules (non-negotiable)
- Groups of EXACTLY 2 or 4 credentials. Join-half = exactly 2. Never 1 or 3.
- Court capacity 4. States: available (no active session), half (active, 2
  players), full (active, 4), closed (admin).
- Sessions run `session_minutes` (club config). Timer zero →
  - queue non-empty: end session, promote queue position 1 (their session
    starts immediately, full session_minutes). If any member of the promoted
    group is revoked, DROP that group and promote the next; if all dropped and
    queue empties, fall through to the empty-queue rule.
  - queue empty + club.auto_extend: same players keep court, ends_at += session_minutes.
  - queue empty + !auto_extend: session ends, court available.
- Queues are per-court, max `queue_depth` groups (club config).
- A credential may be in AT MOST one place: one active session OR one queue
  group. Enforce at action time inside the court transaction.
- Kiosk actions allowed only within opens_at..closes_at (server local time,
  same time source as the app: time::now_local/today helpers). Board is always
  viewable. Engine keeps promoting after close.
- Kiosk = shared computer: no session/cookie for players; every action carries
  credentials in the body, validated then forgotten.

## Migration 0009_clubs.sql (additive)
- clubs: id uuid pk default gen_random_uuid(), slug text unique not null
  (lowercase [a-z0-9-]{3,32}), name text, brand_color text default '#b06f3c',
  court_count int not null, session_minutes int not null default 45,
  queue_depth int not null default 3, auto_extend bool default true,
  opens_at time not null default '06:00', closes_at time not null default '22:00',
  kiosk_theme text not null default 'light', status text not null default
  'onboarding' ('onboarding'|'live'|'suspended'), created_at timestamptz.
- club_admins: id uuid pk, club_id fk, email text unique, name text,
  password_hash text, must_change bool default true, created_at.
- club_credentials: id uuid pk, club_id fk, username text, password text,
  status text default 'active' ('active'|'revoked'), issued_at timestamptz,
  unique (club_id, username). (Plaintext password is deliberate: front desk
  reprints slips; same trust level as the physical slips + parity with the
  app's stored logins.)
- club_courts: club_id fk, number int, closed bool default false,
  closed_reason text, pk (club_id, number). Rows seeded 1..court_count on club
  create; adding courts via config inserts missing rows, reducing court_count
  forbids while sessions active on removed courts.
- court_sessions: id uuid pk, club_id, court_number, started_at, ends_at
  timestamptz, extensions int default 0, status 'active'|'done'.
  Partial unique index: (club_id, court_number) WHERE status='active'.
- session_players: session_id fk cascade, credential_id fk, pk(session_id, credential_id).
- court_queues: id uuid pk, club_id, court_number, position int, created_at.
  Unique (club_id, court_number, position).
- queue_players: queue_id fk cascade, credential_id fk, pk(queue_id, credential_id).
Concurrency: every take/join/queue/engine mutation runs in a transaction that
first calls pg_advisory_xact_lock(hashtext(club_id::text || ':' || court_number::text)).

## Auth
- Platform admin: POST /api/platform/otp {email} → only env
  PLATFORM_ADMIN_EMAIL (fallback: existing admin allowlist if one exists) gets
  a code via existing OTP+Resend machinery (mirror existing signup/login OTP
  flow, Redis keys otp:platform:<email>); POST /api/platform/verify {email,
  code} → issue_token(role "platform"). All /api/platform/* guarded by role.
- Club admin: POST /api/clubs/{slug}/admin/login {email,password} →
  argon2 verify (add argon2 crate) → issue_token(user_id=club_admin.id, role
  "club_admin"). Guard checks role + admin belongs to {slug}'s club.
  Onboarding generates a temp password (word-word-NN style), emails it via
  existing email::send helper, must_change=true;
  POST /api/clubs/{slug}/admin/password {current,new} clears must_change.
- Kiosk endpoints: no auth (public per slug), suspended clubs 404.

## Endpoints (all under existing ApiEnvelope response shape; feature_event map
additions in lib.rs listed at the end)
Platform (role platform):
- GET  /api/platform/clubs → [{id,slug,name,court_count,admin_email,status,created_at, courts_active_today}]
- POST /api/platform/clubs {name,slug,brand_color,court_count,session_minutes,
  queue_depth,admin_name,admin_email} → creates club(status onboarding) +
  admin + temp password email; returns {club, invite_emailed: bool}
- PATCH /api/platform/clubs/{id} {status?...} (live/suspend)
Club admin (role club_admin, own club only):
- GET   /api/clubs/{slug}/admin/overview → {config, stats:{courts, players_on_court, groups_queued, credentials_today}, courts:[{number,closed,closed_reason}]}
- PATCH /api/clubs/{slug}/admin/config {court_count?,session_minutes?,queue_depth?,auto_extend?,opens_at?,closes_at?,kiosk_theme?,brand_color?}
- POST  /api/clubs/{slug}/admin/courts/{n}/close {reason} | /reopen
  Closing: active session keeps running to its end but court takes no new
  groups; its queue groups are released (deleted) — message tells admin to
  redirect players at the desk.
- POST  /api/clubs/{slug}/admin/credentials → generates {username: <adj><noun>-NN or court-xxx style, password: word-word-NN} unique in club; returns pair
- GET   /api/clubs/{slug}/admin/credentials?today=1 → [{id,username,password,status,issued_at,where:{kind:'court'|'queue'|null,court_number,position}}]
- POST  /api/clubs/{slug}/admin/credentials/{id}/revoke
Kiosk (public):
- GET /api/clubs/{slug}/board → {club:{name,slug,brand_color,kiosk_theme,
  court_count,session_minutes,queue_depth,opens_at,closes_at,open_now:bool},
  courts:[{number,status:'available'|'half'|'full'|'closed',closed_reason?,
  players:[username...],seconds_left?:int,queue:[{position,size,label,eta_minutes}],
  queue_len,queue_depth}], now}
  label = "<first username> + N others" (N=size-1) or "<username> pair".
- GET /api/clubs/{slug}/board/stream → SSE; event "board" data=<same JSON as
  board> pushed on every mutation + engine tick that changed state. Mirror the
  existing reservations SSE pattern; per-club channels via a
  DashMap<Uuid, broadcast::Sender<...>> (or Mutex<HashMap>) in AppState.
- POST /api/clubs/{slug}/take  {court_number, players:[{username,password} x2|x4]}
- POST /api/clubs/{slug}/join  {court_number, players: x2} (court must be half)
- POST /api/clubs/{slug}/queue {court_number, players: x2|x4} (court full, queue_len<depth)
  Validation errors → success:false envelope, message human, data {errors:
  [{username, code:'not_found'|'revoked'|'bad_password'|'on_court'|'in_queue'|'duplicate', court_number?}]}
  ('duplicate' = same username twice in the submitted group.)
Engine: tokio task every 3s: SELECT expired active sessions FOR UPDATE SKIP
LOCKED (inside per-court advisory-lock txns) → apply rules above → broadcast.

## Metrics (rallyup-metrics-rule)
feature_event() additions: POST /api/platform/clubs→club_onboarded,
PATCH admin/config→club_config_saved, POST admin/credentials→club_credential_issued,
credentials/{id}/revoke→club_credential_revoked, take→kiosk_court_taken,
join→kiosk_court_joined, queue→kiosk_queue_joined, admin/login→club_admin_login.
Engine calls record_feature directly: kiosk_queue_promoted, kiosk_session_auto_extended.

## Frontend (badminton-fe)
New desktop-only tree, NO PWA chrome, its own layout:
- src/app/courts/layout.tsx: imports courts.css (faithful port of mock
  shell.css incl. dark tokens), <div data-courts-root>, min-width 1180 note.
- src/app/courts/[slug]/page.tsx — KIOSK (port kiosk.html): board from GET,
  live via EventSource on /board/stream with 5s polling fallback; local 1s
  countdown from seconds_left resync on every push; court cards exactly as
  mock (5-col grid, states, queue rows with ETAs = seconds_left/60 +
  (pos-1)*session_minutes rounded); modals: take (2/4 seg), join (fixed 2),
  queue (2/4) with per-field server errors inline; theme from
  club.kiosk_theme via data-theme attr; partner name + brand_color chip in
  topbar; closed-hours banner when !open_now (actions disabled).
- src/app/courts/[slug]/admin/page.tsx — CLUB ADMIN (port admin.html): login
  form (+ forced password change when must_change), then overview stats,
  config form (all fields incl. kiosk_theme + brand color), closures table,
  credentials panel (issue modal shows generated pair + Copy, revoke,
  where-is-it chips). JWT in localStorage key rallyup_club_admin.
- src/app/platform/page.tsx — PLATFORM (port platform.html): OTP login
  (email+code), clubs table, onboard form (slug preview
  badmintonrallyup.com/courts/<slug>, color swatches, counts), success panel
  shows kiosk URL + "invite emailed". JWT key rallyup_platform.
- Shared: src/app/courts/lib.ts (fetch helpers hitting same-origin /api like
  the rest of the app, ApiEnvelope unwrap, TS types mirroring the contract).
- Do NOT touch existing PWA routes/styles; globals.css untouched (courts.css
  scopes everything under [data-courts-root] or .courts-* classes).
Kiosk URL v1 is path-based: badmintonrallyup.com/courts/<slug> (subdomain
courts.badmintonrallyup.com is a later Cloudflare change).

## Quality bars
- BE: cargo check + cargo test green; new unit tests for the engine
  (promotion, auto-extend, revoked-group drop) using the repo's existing test
  style; take/join/queue validation tests. Follow repo idiom (ApiError,
  envelopes, tracing, comment tone).
- FE: npm run build green; TypeScript strict-clean; no mobile viewport work.
- Everything metric-instrumented and matching mock visuals.
