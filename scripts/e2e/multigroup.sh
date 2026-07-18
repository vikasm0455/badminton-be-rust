#!/bin/zsh
# E2E: multi-group model — cross-group polls, login-derived court mapping,
# owner-visible in-use group, ambiguity candidates, duplicate guard.
set -u
cd "$(dirname "$0")/../.."

PGPW='@Anu_@Vikki_0455'
PSQL() { PGPASSWORD=$PGPW psql -U postgres -h 127.0.0.1 -qtAX "$@"; }
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ❌ $1 — expected [$2] got: $(echo $3 | head -c 200)"; }
check(){ case "$3" in *"$2"*) ok "$1";; *) bad "$1" "$2" "$3";; esac }
jqf(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(\"$1\"))" 2>/dev/null; }

redis-cli ping >/dev/null 2>&1 || redis-server --daemonize yes >/dev/null 2>&1
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_mg_e2e" >/dev/null 2>&1
cargo build --bin rallyup-api 2>/dev/null >/dev/null

DATABASE_URL="postgres://postgres:%40Anu_%40Vikki_0455@127.0.0.1:5432/rallyup_mg_e2e" \
REDIS_URL="redis://127.0.0.1:6379" JWT_SECRET="dev-smoke-secret-at-least-32-characters-longxx" \
UPLOADS_PATH="./uploads_mg_e2e" PORT=8092 RUST_LOG=warn \
target/debug/rallyup-api > /tmp/mg_e2e.log 2>&1 &
API=$!
sleep 6
B="localhost:8092"

clear_limits() { redis-cli --scan --pattern 'otp_req:*' | while read -r k; do redis-cli del "$k" >/dev/null; done }
native_signup() { # name email -> access token
  clear_limits
  curl -s -X POST $B/api/auth/signup -H 'Content-Type: application/json' -H 'X-Client: native' -d "{\"display_name\":\"$1\",\"email\":\"$2\"}" >/dev/null
  sleep 0.3
  local otp; otp=$(redis-cli get "otp:signup:$2")
  curl -s -X POST $B/api/auth/signup/verify -H 'Content-Type: application/json' -H 'X-Client: native' -d "{\"email\":\"$2\",\"code\":\"$otp\"}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['access_token'])"
}
H() { echo "Authorization: Bearer $1"; }

echo "── Setup: Alex ∈ {CS, SS} · Bob ∈ {SS} · Cara ∈ {CS}"
AT=$(native_signup Alex alex@mg.io)
curl -s -X POST $B/api/groups -H "$(H $AT)" -H 'Content-Type: application/json' -d '{"name":"City Smashers"}' >/dev/null
CS=$(curl -s $B/api/groups -H "$(H $AT)" | jqf "d['data'][0]['id']")
curl -s -X POST $B/api/groups -H "$(H $AT)" -H 'Content-Type: application/json' -d '{"name":"Sunday Smash"}' >/dev/null
SS=$(curl -s $B/api/groups -H "$(H $AT)" | jqf "[g['id'] for g in d['data'] if g['name']=='Sunday Smash'][0]")
# active is SS (last created) — invite Bob to SS
curl -s -X POST $B/api/groups/invites -H "$(H $AT)" -H 'Content-Type: application/json' -d '{"email":"bob@mg.io"}' >/dev/null
BT=$(native_signup Bob bob@mg.io)
INV=$(curl -s $B/api/invites -H "$(H $BT)" | jqf "d['data'][0]['id']")
curl -s -X POST $B/api/invites/$INV/accept -H "$(H $BT)" >/dev/null
# invite Cara to CS
curl -s -X PUT $B/api/groups/active -H "$(H $AT)" -H 'Content-Type: application/json' -d "{\"group_id\":\"$CS\"}" >/dev/null
curl -s -X POST $B/api/groups/invites -H "$(H $AT)" -H 'Content-Type: application/json' -d '{"email":"cara@mg.io"}' >/dev/null
CT=$(native_signup Cara cara@mg.io)
INV=$(curl -s $B/api/invites -H "$(H $CT)" | jqf "d['data'][0]['id']")
curl -s -X POST $B/api/invites/$INV/accept -H "$(H $CT)" >/dev/null
echo "  (setup done)"

echo "── Cross-group polls"
# Alex active=CS: create CS poll; then switch to SS and create SS poll
curl -s -X POST $B/api/polls -H "$(H $AT)" -H 'Content-Type: application/json' -d '{"proposed_time":"18:30"}' >/dev/null
curl -s -X PUT $B/api/groups/active -H "$(H $AT)" -H 'Content-Type: application/json' -d "{\"group_id\":\"$SS\"}" >/dev/null
curl -s -X POST $B/api/polls -H "$(H $AT)" -H 'Content-Type: application/json' -d '{"proposed_time":"19:00"}' >/dev/null
R=$(curl -s $B/api/polls/tonight -H "$(H $AT)")
check "tonight lists both groups' polls"     "2" "$(echo $R | jqf "len(d['data'])")"
check "tonight carries group names"          "City Smashers" "$R"
CSPOLL=$(echo "$R" | jqf "[p['id'] for p in d['data'] if p['group_name']=='City Smashers'][0]")
# Alex's ACTIVE group is SS — voting on the CS poll must work (membership, not active group)
R=$(curl -s -X PUT $B/api/polls/$CSPOLL/vote -H "$(H $AT)" -H 'Content-Type: application/json' -d '{"vote":"yes"}')
check "cross-group vote works"               '"my_vote":"yes"' "$R"
# Bob (SS only) must NOT see or vote the CS poll
R=$(curl -s -X PUT $B/api/polls/$CSPOLL/vote -H "$(H $BT)" -H 'Content-Type: application/json' -d '{"vote":"yes"}')
check "non-member vote rejected"             'not found' "$R"
R=$(curl -s $B/api/polls/tonight -H "$(H $BT)")
check "Bob's tonight = SS only"              "1" "$(echo $R | jqf "len(d['data'])")"

echo "── Logins + resolve-group"
# Alex posts login (active=SS) then shares to BOTH groups
R=$(curl -s -X POST $B/api/credentials -H "$(H $AT)" -H 'Content-Type: application/json' -d '{"bintang_name":"Alex","bintang_password":"mg-alex1","screenshot_path":null}')
AC=$(echo "$R" | jqf "d['data']['id']")
curl -s -X PUT $B/api/credentials/$AC/shares -H "$(H $AT)" -H 'Content-Type: application/json' -d "{\"group_ids\":[\"$CS\",\"$SS\"]}" >/dev/null
# Bob posts login (SS only)
R=$(curl -s -X POST $B/api/credentials -H "$(H $BT)" -H 'Content-Type: application/json' -d '{"bintang_name":"Bob","bintang_password":"mg-bob01","screenshot_path":null}')
BC=$(echo "$R" | jqf "d['data']['id']")
# Alex's login alone → shared to 2 groups → ambiguous, 2 candidates
R=$(curl -s -X POST $B/api/reservations/resolve-group -H "$(H $AT)" -H 'Content-Type: application/json' -d "{\"credential_ids\":[\"$AC\"]}")
check "solo multi-shared login → 2 candidates" "2" "$(echo $R | jqf "len(d['data'])")"
# Alex + Bob logins → common group = SS → single candidate
R=$(curl -s -X POST $B/api/reservations/resolve-group -H "$(H $AT)" -H 'Content-Type: application/json' -d "{\"credential_ids\":[\"$AC\",\"$BC\"]}")
check "common group auto-resolves to one"    "1" "$(echo $R | jqf "len(d['data'])")"
check "…and it is Sunday Smash"              "Sunday Smash" "$R"
echo "── Court mapping + visibility"
# create with explicit SS group (as resolved)
R=$(curl -s -X POST $B/api/reservations -H "$(H $AT)" -H 'Content-Type: application/json' -d "{\"group_id\":\"$SS\",\"court_number\":7,\"court_type\":\"full\",\"credential_ids\":[\"$AC\",\"$BC\"],\"player_count\":4,\"duration_minutes\":45,\"start_type\":\"now\",\"queue_number\":1,\"notes\":null}")
check "court created in resolved group"      '"court_number":7' "$R"
# SS members see it; CS view doesn't
R=$(curl -s $B/api/reservations/today -H "$(H $BT)")
check "SS member (Bob) sees the court"       '"court_number":7' "$R"
R=$(curl -s $B/api/reservations/today -H "$(H $CT)")
check "CS member (Cara) sees NO court"       '"data":[]' "$R"
# Owner sees WHICH group uses their login; Cara sees generic elsewhere
R=$(curl -s "$B/api/credentials/today?scope=all" -H "$(H $AT)")
check "owner sees using group's name"        '"in_use_group_name":"Sunday Smash"' "$R"
R=$(curl -s $B/api/credentials/today -H "$(H $CT)")
check "other group sees generic in-use"      '"in_use_elsewhere":true' "$R"
check "…with court number withheld"          '"in_use_court":null' "$R"
echo "── Duplicate guard + scope=all"
R=$(curl -s -X POST $B/api/reservations -H "$(H $AT)" -H 'Content-Type: application/json' -d "{\"group_id\":\"$SS\",\"court_number\":9,\"court_type\":\"full\",\"credential_ids\":[\"$BC\"],\"player_count\":2,\"duration_minutes\":45,\"start_type\":\"now\",\"queue_number\":1,\"notes\":null}")
check "login already on a court → blocked"   "login is in use" "$R"
R=$(curl -s -X POST $B/api/reservations -H "$(H $CT)" -H 'Content-Type: application/json' -d "{\"group_id\":\"$SS\",\"court_number\":9,\"court_type\":\"full\",\"credential_ids\":[],\"player_count\":2,\"duration_minutes\":45,\"start_type\":\"now\",\"queue_number\":1,\"notes\":null}")
check "non-member explicit group → 403"      'forbidden' "$R"
R=$(curl -s "$B/api/credentials/today?scope=all" -H "$(H $BT)")
check "scope=all shows every visible login"  "2" "$(echo $R | jqf "len(d['data'])")"

kill $API 2>/dev/null
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_mg_e2e" >/dev/null 2>&1
rm -rf uploads_mg_e2e
echo
echo "════════ MULTI-GROUP E2E: $PASS passed, $FAIL failed ════════"
exit $FAIL
