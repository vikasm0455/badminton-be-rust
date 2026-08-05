#!/bin/zsh
# E2E regression: multi-tenancy (groups) — verifies Phase 0 didn't break anything.
set -u
cd /Users/vikki/Documents/rust/vm_home_server/badminton-be-rust

PGPW='@Anu_@Vikki_0455'
PSQL() { PGPASSWORD=$PGPW psql -U postgres -h 127.0.0.1 -qtAX "$@"; }
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ❌ $1 — expected [$2] got: $(echo $3 | head -c 200)"; }
check(){ case "$3" in *"$2"*) ok "$1";; *) bad "$1" "$2" "$3";; esac }

# ============ PART 1: legacy → 0003+0004 migration chain ====================
echo "── Part 1: migration chain on a legacy single-tenant DB"
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_mig_test" >/dev/null
PSQL -d postgres -c "CREATE DATABASE rallyup_mig_test" >/dev/null
PSQL -d rallyup_mig_test -f migrations/0001_init.sql >/dev/null 2>&1
PSQL -d rallyup_mig_test -f migrations/0002_reservation_credentials.sql >/dev/null 2>&1
PSQL -d rallyup_mig_test >/dev/null <<'SQL'
INSERT INTO users (id, display_name, email, role, status) VALUES
 ('00000000-0000-0000-0000-000000000001','Vikas','vikas@x.com','admin','active'),
 ('00000000-0000-0000-0000-000000000002','Suchi','suchi@x.com','member','active');
INSERT INTO polls (created_by, game_date, proposed_time) VALUES ('00000000-0000-0000-0000-000000000001', CURRENT_DATE, '18:00');
INSERT INTO court_credentials (posted_by, game_date, bintang_name, bintang_password) VALUES ('00000000-0000-0000-0000-000000000002', CURRENT_DATE, 'Suchi', 'lion16');
SQL
PSQL -d rallyup_mig_test -f migrations/0003_groups.sql >/dev/null 2>&1
PSQL -d rallyup_mig_test -f migrations/0004_native_auth_push.sql >/dev/null 2>&1
PSQL -d rallyup_mig_test -f migrations/0005_group_venue.sql >/dev/null 2>&1
check "default group created"       "Bintang Badminton" "$(PSQL -d rallyup_mig_test -c 'SELECT name FROM groups')"
check "members migrated"            "2"  "$(PSQL -d rallyup_mig_test -c 'SELECT COUNT(*) FROM group_members')"
check "credential shared"           "1"  "$(PSQL -d rallyup_mig_test -c 'SELECT COUNT(*) FROM credential_shares')"
check "0004 tables exist"           "0"  "$(PSQL -d rallyup_mig_test -c 'SELECT COUNT(*) FROM refresh_tokens')"
check "device_tokens exists"        "0"  "$(PSQL -d rallyup_mig_test -c 'SELECT COUNT(*) FROM device_tokens')"
PSQL -d postgres -c "DROP DATABASE rallyup_mig_test" >/dev/null

# ============ PART 2: multi-group API regression =============================
echo "── Part 2: live API multi-group flows"
redis-cli ping >/dev/null 2>&1 || redis-server --daemonize yes >/dev/null 2>&1
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_groups_e2e" >/dev/null

DATABASE_URL="postgres://postgres:%40Anu_%40Vikki_0455@127.0.0.1:5432/rallyup_groups_e2e" \
REDIS_URL="redis://127.0.0.1:6379" JWT_SECRET="dev-smoke-secret-at-least-32-characters-longxx" \
UPLOADS_PATH="./uploads_e2e" PORT=8089 RUST_LOG=warn \
RESEND_API_KEY="" \
target/debug/rallyup-api > /tmp/groups_e2e.log 2>&1 &
API=$!
sleep 6
B="localhost:8089"

clear_otp_limits() { redis-cli --scan --pattern 'otp_req:*' | while read -r k; do redis-cli del "$k" >/dev/null; done }
signup() {
  clear_otp_limits
  curl -s -X POST $B/api/auth/signup -H 'Content-Type: application/json' -d "{\"display_name\":\"$1\",\"email\":\"$2\"}" >/dev/null
  sleep 0.3
  local otp; otp=$(redis-cli get "otp:signup:$2")
  curl -s -c "$3" -X POST $B/api/auth/signup/verify -H 'Content-Type: application/json' -d "{\"email\":\"$2\",\"code\":\"$otp\"}"
}
A() { curl -s -b /tmp/ck_a.txt "$@"; }
BB(){ curl -s -b /tmp/ck_b.txt "$@"; }
C() { curl -s -b /tmp/ck_c.txt "$@"; }
jqf(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(\"$1\"))" 2>/dev/null; }

R=$(signup Alice alice@test.io /tmp/ck_a.txt)
check "A signup (cookie web flow)"  '"status":"active"' "$R"
R=$(A -X POST $B/api/groups -H 'Content-Type: application/json' -d '{"name":"Alpha"}')
check "A creates Alpha"             '"role":"admin"' "$R"
R=$(A -X POST $B/api/groups/invites -H 'Content-Type: application/json' -d '{"email":"bob@test.io"}')
check "invite reports email_delivery (no key → skipped)" '"email_delivery":"skipped"' "$R"
check "invite honest message when not sent" 'Invite saved' "$R"
check "invite returns invite list"  '"email":"bob@test.io"' "$R"
signup Bob bob@test.io /tmp/ck_b.txt >/dev/null
INV=$(BB $B/api/invites | jqf "d['data'][0]['id']")
R=$(BB -X POST $B/api/invites/$INV/accept)
check "B accepts invite"            '"name":"Alpha"' "$R"
R=$(BB -X POST $B/api/groups/invites -H 'Content-Type: application/json' -d '{"email":"x@y.io"}')
check "member cannot invite → 403"  'forbidden' "$R"

R=$(BB -X POST $B/api/credentials -H 'Content-Type: application/json' -d '{"bintang_name":"Suchi","bintang_password":"lion16","screenshot_path":null}')
CRED=$(echo "$R" | jqf "d['data']['id']")
R=$(A $B/api/credentials/today)
check "A sees B's login in Alpha"   'lion16' "$R"
R=$(A -X PUT $B/api/credentials/$CRED -H 'Content-Type: application/json' -d '{"bintang_name":"Hax","bintang_password":"nope"}')
check "non-owner cannot edit login → 403" 'forbidden' "$R"
R=$(BB -X PUT $B/api/credentials/$CRED -H 'Content-Type: application/json' -d '{"bintang_name":"Suchi","bintang_password":"tiger99"}')
check "owner edits own login"       'Login updated' "$R"
R=$(A $B/api/credentials/today)
check "edit visible to group"       'tiger99' "$R"

signup Cara cara@test.io /tmp/ck_c.txt >/dev/null
C -X POST $B/api/groups -H 'Content-Type: application/json' -d '{"name":"Beta"}' >/dev/null
R=$(C $B/api/credentials/today)
check "C (Beta) sees NO Alpha logins [ISOLATION]" '"data":[]' "$R"
APOLL=$(A -X POST $B/api/polls -H 'Content-Type: application/json' -d '{"proposed_time":"18:00"}' | jqf "d['data']['id']")
R=$(C $B/api/polls/today)
check "C sees no Alpha poll [ISOLATION]" '"data":null' "$R"

# ---- shareable poll links
R=$(C -X POST $B/api/polls/$APOLL/share-link)
check "non-member cannot share poll" 'not found' "$R"
R=$(A -X POST $B/api/polls/$APOLL/share-link)
check "member shares poll"          '/p/' "$R"
PSHARE=$(echo "$R" | jqf "d['data']['url'].split('/p/')[1]")
BB -X PUT $B/api/polls/$APOLL/vote -H 'Content-Type: application/json' -d '{"vote":"yes"}' >/dev/null
R=$(curl -s $B/api/poll-share/$PSHARE)
check "poll share info is public"   '"group_name":"Alpha"' "$R"
check "poll share shows live count" '"yes":1' "$R"
R=$(curl -s -o /dev/null -w '%{http_code}' $B/api/poll-share/deadbeefdeadbeefdeadbeefdeadbeef)
check "unknown share token 404s"    '404' "$R"
R=$(BB -X POST $B/api/polls/$APOLL/share-link)
check "second sharer gets same URL" "$PSHARE" "$R"
R=$(curl -s $B/api/poll-share/$PSHARE)
check "share time is 12-hour"       '"proposed_time":"6:00 PM"' "$R"
# Age the poll to yesterday: token must go dark, sharing/voting must stop.
PSQL -d rallyup_groups_e2e -c "UPDATE polls SET game_date = game_date - 1 WHERE id = '$APOLL'" >/dev/null
R=$(curl -s $B/api/poll-share/$PSHARE)
check "ended link says only ended"  '"ended":true,"poll":null' "$R"
R=$(A -X POST $B/api/polls/$APOLL/share-link)
check "cannot share a past poll"    "Only today's polls" "$R"
R=$(BB -X PUT $B/api/polls/$APOLL/vote -H 'Content-Type: application/json' -d '{"vote":"no"}')
check "cannot vote on a past poll"  'This poll has ended' "$R"
PSQL -d rallyup_groups_e2e -c "UPDATE polls SET game_date = game_date + 1 WHERE id = '$APOLL'" >/dev/null
R=$(C -X POST $B/api/polls -H 'Content-Type: application/json' -d '{"proposed_time":"19:00"}')
check "C creates Beta poll same date" '"proposed_time":"19:00"' "$R"

BB -X POST $B/api/groups -H 'Content-Type: application/json' -d '{"name":"Gamma"}' >/dev/null
R=$(BB $B/api/credentials/today)
check "B in Gamma still sees own login" '"is_mine":true' "$R"
ALPHA=$(BB $B/api/groups | jqf "[g['id'] for g in d['data'] if g['name']=='Alpha'][0]")
GAMMA=$(BB $B/api/groups | jqf "[g['id'] for g in d['data'] if g['name']=='Gamma'][0]")
R=$(BB -X PUT $B/api/credentials/$CRED/shares -H 'Content-Type: application/json' -d "{\"group_ids\":[\"$ALPHA\",\"$GAMMA\"]}")
check "owner re-shares to 2 groups" 'Sharing updated' "$R"
R=$(A -X PUT $B/api/credentials/$CRED/shares -H 'Content-Type: application/json' -d '{"group_ids":[]}')
check "non-owner cannot edit shares → 403" 'forbidden' "$R"

BB -X PUT $B/api/groups/active -H 'Content-Type: application/json' -d "{\"group_id\":\"$ALPHA\"}" >/dev/null
R=$(A -X POST $B/api/reservations -H 'Content-Type: application/json' -d "{\"court_number\":5,\"court_type\":\"full\",\"credential_ids\":[\"$CRED\"],\"player_count\":4,\"duration_minutes\":45,\"start_type\":\"now\",\"queue_number\":1,\"notes\":null}")
check "A logs court 5 q1 in Alpha"  '"court_number":5' "$R"
RES=$(echo "$R" | jqf "d['data']['id']")
R=$(C -X POST $B/api/reservations -H 'Content-Type: application/json' -d "{\"court_number\":5,\"court_type\":\"full\",\"credential_ids\":[\"$CRED\"],\"player_count\":4,\"duration_minutes\":45,\"start_type\":\"now\",\"queue_number\":2,\"notes\":null}")
check "C cannot attach Alpha login [ISOLATION]" 'credential not found' "$R"
R=$(C -X POST $B/api/reservations -H 'Content-Type: application/json' -d '{"court_number":5,"court_type":"full","credential_ids":[],"player_count":4,"duration_minutes":45,"start_type":"now","queue_number":1,"notes":null}')
check "C logs court 5 q1 in Beta (per-group index)" '"court_number":5' "$R"
R=$(C $B/api/reservations/today)
check "C sees only Beta reservations" '1' "$(echo $R | jqf "len(d['data'])")"

R=$(BB -X PUT $B/api/reservations/$RES/cancel)
check "member cannot cancel → 403"  'forbidden' "$R"
R=$(A -X PUT $B/api/reservations/$RES/cancel)
check "group admin cancels"         'cancelled' "$R"
R=$(A $B/api/members)
check "Alpha roster = 2"            '2' "$(echo $R | jqf "len(d['data'])")"

# ---- shareable invite links
R=$(A -X POST $B/api/groups/invite-link)
check "admin creates invite link"   '/join/' "$R"
LINKTOK=$(echo "$R" | jqf "d['data']['url'].split('/join/')[1]")
R=$(BB -X POST $B/api/groups/invite-link)
check "member cannot create link → 403" 'forbidden' "$R"
R=$(curl -s $B/api/join/$LINKTOK)
check "join info is public"         '"group_name":"Alpha"' "$R"
signup Dora dora@test.io /tmp/ck_d.txt >/dev/null
DD() { curl -s -b /tmp/ck_d.txt "$@"; }
R=$(DD -X POST $B/api/join/$LINKTOK)
check "Dora joins via link"         'Welcome to Alpha' "$R"
check "join reports newly_joined"   '"newly_joined":true' "$R"
R=$(DD -X POST $B/api/join/$LINKTOK)
check "re-join is idempotent"       'already a member' "$R"
DORA=$(DD $B/api/auth/me | jqf "d['data']['id']")
A -X POST $B/api/moderation/block -H 'Content-Type: application/json' -d "{\"user_id\":\"$DORA\"}" >/dev/null
R=$(DD -X POST $B/api/join/$LINKTOK)
check "admin-blocked user can't use link" 'no longer valid' "$R"
A -X DELETE $B/api/moderation/block/$DORA >/dev/null
R=$(A $B/api/groups/invite-link)
check "join_count incremented"      '"join_count":1' "$R"
R=$(A -X POST $B/api/groups/invite-link)
NEWTOK=$(echo "$R" | jqf "d['data']['url'].split('/join/')[1]")
R=$(C -X POST $B/api/join/$LINKTOK)
check "rotated link kills old token" 'no longer valid' "$R"
A -X DELETE $B/api/groups/invite-link >/dev/null
R=$(C -X POST $B/api/join/$NEWTOK)
check "disabled link rejected"      'no longer valid' "$R"
R=$(curl -s $B/api/join/$NEWTOK)
check "disabled link info leaks nothing" '"success":false' "$R"

R=$(A -X POST $B/api/groups/leave)
check "sole admin cannot leave → 409" 'promote another' "$R"
BOB=$(BB $B/api/auth/me | jqf "d['data']['id']")
A -X PUT $B/api/groups/members/$BOB -H 'Content-Type: application/json' -d '{"role":"admin"}' >/dev/null
A -X POST $B/api/groups/leave >/dev/null
R=$(A $B/api/auth/me)
check "A back to onboarding"        '"groups_count":0' "$R"

R=$(BB -X PUT $B/api/config/auto-poll -H 'Content-Type: application/json' -d '{"enabled":true,"time":"09:30"}')
check "Alpha admin sets auto-poll"  '"time":"09:30"' "$R"
R=$(C -X PUT $B/api/config/auto-poll -H 'Content-Type: application/json' -d '{"enabled":true}')
check "Beta auto-poll separate"     '"time":"10:00"' "$R"
R=$(BB $B/api/groups)
check "B belongs to 2 groups"       '2' "$(echo $R | jqf "len(d['data'])")"
R=$(BB $B/api/kcal/today)
check "kcal stays private shape"    '"my_log"' "$R"

# ---- personal stats (B voted yes on APOLL earlier; attendance never confirmed)
R=$(BB $B/api/stats/me)
check "stats: yes-vote day counts as session" '"sessions_total":1' "$R"
check "stats: 8 weekly buckets"     '8' "$(echo $R | jqf "len(d['data']['weekly_sessions'])")"
check "stats: yes rate present"     '"yes_rate_percent":' "$R"
R=$(DD $B/api/stats/me)
check "stats: no history = zeros"   '"sessions_total":0' "$R"

kill $API 2>/dev/null
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_groups_e2e" >/dev/null
rm -rf uploads_e2e /tmp/ck_a.txt /tmp/ck_b.txt /tmp/ck_c.txt
echo
echo "════════ GROUPS REGRESSION: $PASS passed, $FAIL failed ════════"
exit $FAIL
