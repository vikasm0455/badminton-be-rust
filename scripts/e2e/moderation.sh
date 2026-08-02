#!/bin/zsh
# E2E: Guideline 1.2 moderation — report hides content for the reporter,
# block hides ALL of a member's content instantly, unblock restores it.
set -u
cd "$(dirname "$0")/../.."

PGPW='@Anu_@Vikki_0455'
PSQL() { PGPASSWORD=$PGPW psql -U postgres -h 127.0.0.1 -qtAX "$@"; }
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ❌ $1 — expected [$2] got: $(echo $3 | head -c 200)"; }
check(){ case "$3" in *"$2"*) ok "$1";; *) bad "$1" "$2" "$3";; esac }
checknot(){ case "$3" in *"$2"*) bad "$1" "NOT $2" "$3";; *) ok "$1";; esac }
jqf(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(\"$1\"))" 2>/dev/null; }

redis-cli ping >/dev/null 2>&1 || redis-server --daemonize yes >/dev/null 2>&1
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_mod_e2e" >/dev/null 2>&1
cargo build --bin rallyup-api 2>/dev/null >/dev/null

DATABASE_URL="postgres://postgres:%40Anu_%40Vikki_0455@127.0.0.1:5432/rallyup_mod_e2e" \
REDIS_URL="redis://127.0.0.1:6379" JWT_SECRET="dev-smoke-secret-at-least-32-characters-longxx" \
UPLOADS_PATH="./uploads_mod_e2e" PORT=8094 RUST_LOG=warn \
RESEND_API_KEY="" \
target/debug/rallyup-api > /tmp/mod_e2e.log 2>&1 &
API_PID=$!
sleep 6
B="localhost:8094"

clear_limits() { redis-cli --scan --pattern 'otp_req:*' | while read -r k; do redis-cli del "$k" >/dev/null; done }
mint() { # name email -> token
  clear_limits
  curl -s -X POST $B/api/auth/signup -H 'Content-Type: application/json' -H 'X-Client: native' -d "{\"display_name\":\"$1\",\"email\":\"$2\"}" >/dev/null
  sleep 0.3
  local otp; otp=$(redis-cli get "otp:signup:$2")
  curl -s -X POST $B/api/auth/signup/verify -H 'Content-Type: application/json' -H 'X-Client: native' -d "{\"email\":\"$2\",\"code\":\"$otp\"}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['access_token'])"
}
H() { echo "Authorization: Bearer $1"; }
CT='Content-Type: application/json'

echo "── Setup: Alex + Maya share a group; Maya posts a login, poll vote, court"
AT=$(mint Alex alex@mod.io)
curl -s -X POST $B/api/groups -H "$(H $AT)" -H "$CT" -d '{"name":"City Smashers"}' >/dev/null
curl -s -X POST $B/api/groups/invites -H "$(H $AT)" -H "$CT" -d '{"email":"maya@mod.io"}' >/dev/null
MT=$(mint Maya maya@mod.io)
INV=$(curl -s $B/api/invites -H "$(H $MT)" | jqf "d['data'][0]['id']")
curl -s -X POST $B/api/invites/$INV/accept -H "$(H $MT)" >/dev/null
MAYA_ID=$(curl -s $B/api/auth/me -H "$(H $MT)" | jqf "d['data']['id']")
# Maya's content: poll (as creator), a login, a court
PID=$(curl -s -X POST $B/api/polls -H "$(H $MT)" -H "$CT" -d '{"proposed_time":"19:00"}' | jqf "d['data']['id']")
curl -s -X PUT $B/api/polls/$PID/vote -H "$(H $MT)" -H "$CT" -d '{"vote":"yes"}' >/dev/null
CID=$(curl -s -X POST $B/api/credentials -H "$(H $MT)" -H "$CT" -d '{"bintang_name":"Maya","bintang_password":"drop-77","screenshot_path":null}' | jqf "d['data']['id']")
RID=$(curl -s -X POST $B/api/reservations -H "$(H $MT)" -H "$CT" -d "{\"court_number\":7,\"court_type\":\"full\",\"credential_ids\":[\"$CID\"],\"player_count\":4,\"duration_minutes\":45,\"start_type\":\"now\",\"queue_number\":1,\"notes\":null}" | jqf "d['data']['id']")
echo "  (setup done)"

echo "── Baseline: Alex sees Maya's content"
R=$(curl -s $B/api/credentials/today -H "$(H $AT)")
check "login visible before any action"        "drop-77" "$R"
R=$(curl -s $B/api/reservations/today -H "$(H $AT)")
check "court visible before any action"        '"court_number":7' "$R"
R=$(curl -s $B/api/polls/tonight -H "$(H $AT)")
check "poll visible before any action"         '"19:00"' "$R"

echo "── Report: hides that item for the reporter only"
R=$(curl -s -X POST $B/api/moderation/report -H "$(H $AT)" -H "$CT" -d "{\"content_type\":\"credential\",\"content_id\":\"$CID\",\"note\":\"test report\"}")
check "report accepted"                        "hidden for you" "$R"
R=$(curl -s $B/api/credentials/today -H "$(H $AT)")
checknot "reported login gone for reporter"    "drop-77" "$R"
R=$(curl -s $B/api/credentials/today -H "$(H $MT)")
check "owner still sees their own login"       "drop-77" "$R"
R=$(PSQL -d rallyup_mod_e2e -c "SELECT COUNT(*) FROM content_reports")
check "report row stored for operator review"  "1" "$R"

echo "── Block: hides ALL of Maya's content for Alex instantly"
R=$(curl -s -X POST $B/api/moderation/block -H "$(H $AT)" -H "$CT" -d "{\"user_id\":\"$MAYA_ID\"}")
check "block accepted"                         "hidden from your app" "$R"
R=$(curl -s $B/api/reservations/today -H "$(H $AT)")
checknot "blocked member's court gone"         '"court_number":7' "$R"
R=$(curl -s $B/api/polls/tonight -H "$(H $AT)")
checknot "blocked member's poll gone"          '"19:00"' "$R"
R=$(curl -s $B/api/moderation/blocked -H "$(H $AT)")
check "blocked list shows Maya"                "Maya" "$R"
R=$(curl -s -X POST $B/api/moderation/block -H "$(H $AT)" -H "$CT" -d "{\"user_id\":\"$(curl -s $B/api/auth/me -H "$(H $AT)" | jqf "d['data']['id']")\"}")
check "self-block rejected"                    "can't block yourself" "$R"

echo "── Maya is unaffected and unaware"
R=$(curl -s $B/api/polls/tonight -H "$(H $MT)")
check "Maya still sees her own poll"           '"19:00"' "$R"
R=$(curl -s $B/api/reservations/today -H "$(H $MT)")
check "Maya still sees her own court"          '"court_number":7' "$R"

echo "── Unblock restores"
curl -s -X DELETE $B/api/moderation/block/$MAYA_ID -H "$(H $AT)" >/dev/null
R=$(curl -s $B/api/polls/tonight -H "$(H $AT)")
check "poll back after unblock"                '"19:00"' "$R"
R=$(curl -s $B/api/reservations/today -H "$(H $AT)")
check "court back after unblock"               '"court_number":7' "$R"
R=$(curl -s $B/api/credentials/today -H "$(H $AT)")
checknot "reported login stays hidden (report is separate)" "drop-77" "$R"

kill $API_PID 2>/dev/null
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_mod_e2e" >/dev/null 2>&1
rm -rf uploads_mod_e2e
echo
echo "════════ MODERATION E2E: $PASS passed, $FAIL failed ════════"
exit $FAIL
