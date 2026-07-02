# Migration 0003 — Multi-tenancy (groups)

What ships: open signup, user-created groups, email invites, per-group
polls/courts, and per-group **sharing** of court logins. kCal stays personal.

## How it runs

`migrations/0003_groups.sql` is a normal sqlx migration: **it runs
automatically, once, the first time the new API image boots** against the
production database (same mechanism as 0001/0002). Nothing to run by hand —
but review below is exactly what it will do, and how to verify afterward.

Local testing never touches the server: the E2E suite runs against a local
Postgres (`rallyup_*` scratch databases) only.

## What it changes (schema)

| Object | Change |
|---|---|
| `groups` (new) | id, name, created_by + per-group auto-poll settings |
| `group_members` (new) | (group_id, user_id, role admin\|member) |
| `group_invites` (new) | email invites; one live invite per (group, email) |
| `credential_shares` (new) | which groups can see a court login |
| `users` | + `active_group_id` (the group scoping your app view) |
| `polls` | + `group_id`; unique poll per **(group, date)** instead of per date |
| `court_reservations` | + `group_id`; queue-slot unique index now per group |

## The one-time backfill (only if data exists)

Runs only when `groups` is empty AND at least one user exists:

1. Creates the group **“Bintang Badminton”**, owned by the earliest active
   site admin (you).
2. Adds every `active`/`pending` user as a member; site admins → group admins;
   pending users become active (membership replaces approval).
3. Sets everyone's `active_group_id` to it — nobody sees an onboarding screen.
4. Points all existing polls and reservations at it.
5. Shares every existing court login with it.
6. Copies the old global auto-poll settings (from `app_config`) onto the group.

Fresh/empty database → the backfill is a no-op; idempotent on re-run
(guarded by `IF EXISTS (SELECT 1 FROM groups)`).

## Verify after deploy

```sql
SELECT name, auto_poll_enabled FROM groups;                 -- Bintang Badminton | t
SELECT COUNT(*) FROM group_members;                          -- = your member count
SELECT COUNT(*) FROM users  WHERE active_group_id IS NULL;   -- 0
SELECT COUNT(*) FROM polls  WHERE group_id IS NULL;          -- 0
SELECT COUNT(*) FROM court_reservations WHERE group_id IS NULL; -- 0
```

And in the app: everyone still sees the same polls/courts/logins as before;
the Home header now shows a “Bintang Badminton” pill; More → My groups.

## Rollback note

The migration is additive (new tables/columns) except for two index swaps
(poll uniqueness, queue-slot uniqueness). Rolling back the app image to the
previous version keeps working against the migrated schema EXCEPT poll
creation (old code inserts polls without group_id — allowed, column is
nullable) and per-date poll uniqueness (relaxed to per-group). Practical
rollback: restore the previous image; don't drop the new tables.

## Post-release cleanup (after the groups release is stable)

Every piece of code made obsolete by multi-tenancy is tagged with a single
grep-able marker. To find it all:

```bash
grep -rn "LEGACY-SINGLE-TENANT" badminton-be-rust/src badminton-fe/src
```

Safe to delete once the release has been stable for a while (say a month):

| What | Where |
|---|---|
| approve/reject member handlers + routes | `admin.rs`, `lib.rs` |
| invite-CODE handlers + routes + `InviteRow` | `admin.rs`, `lib.rs` |
| `notify::member_approved` / `member_rejected` | `notify.rs` |
| `email::send_approved` / `send_rejected` | `email.rs` |
| `otp::check_invite_attempt` | `otp.rs` |
| unused security consts (`INVITE_USED`, `INVALID_INVITE_ATTEMPT`, `MEMBER_APPROVED/REJECTED`) | `security.rs` — delete with the handlers |
| FE `/admin/invites` page + `InviteRow` type | `app/admin/invites/`, `lib/types.ts` |
| FE `/pending` page + its redirects | `app/pending/`, `login/page.tsx`, `(app)/layout.tsx` |
| FE `/join` redirect stub | `app/join/` — keep while old invite links circulate |

Database leftovers go in a **new** migration (e.g. `0004_drop_legacy.sql`):

```sql
DROP TABLE IF EXISTS invite_codes;
DELETE FROM app_config WHERE key IN
  ('auto_poll_enabled','auto_poll_time','auto_poll_note','auto_poll_final_reminder_time');
```

### ⚠️ What must NEVER be deleted

**Applied migration files** (`0001`–`0003`) are permanent. sqlx records each
applied migration with a checksum in `_sqlx_migrations`; if a recorded file is
missing or edited, the API refuses to boot (`VersionMissing`/`VersionMismatch`).
The migration runs only once ever — an already-applied file costs nothing to
keep. All schema removal happens through NEW migrations, never by touching old
ones.

## New env (optional)

`APP_BASE_URL` — public URL used in invite emails
(e.g. `https://rally-up.boyishesh.com`). Unset → emails just say
“sign up in the RallyUp app”.
