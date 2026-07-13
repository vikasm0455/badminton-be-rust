#!/bin/zsh
# E2E: native-app auth + push registration + account deletion (Phase 0 surface).
# Local-only (fresh DB, local redis). Run from anywhere:
#   ./scripts/e2e/native-auth.sh
set -u
cd "$(dirname "$0")/../.."

PGPW='@Anu_@Vikki_0455'
PSQL() { PGPASSWORD=$PGPW psql -U postgres -h 127.0.0.1 -qtAX "$@"; }
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✅ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ❌ $1 — expected [$2] got: $(echo $3 | head -c 180)"; }
check(){ case "$3" in *"$2"*) ok "$1";; *) bad "$1" "$2" "$3";; esac }
jqf(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(\"$1\"))" 2>/dev/null; }

redis-cli ping >/dev/null 2>&1 || redis-server --daemonize yes >/dev/null 2>&1
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_native_e2e" >/dev/null 2>&1
cargo build --bin rallyup-api 2>/dev/null >/dev/null

DATABASE_URL="postgres://postgres:%40Anu_%40Vikki_0455@127.0.0.1:5432/rallyup_native_e2e" \
REDIS_URL="redis://127.0.0.1:6379" JWT_SECRET="dev-smoke-secret-at-least-32-characters-longxx" \
UPLOADS_PATH="./uploads_native_e2e" PORT=8091 RUST_LOG=warn \
REFRESH_REUSE_GRACE_SECS=2 \
target/debug/rallyup-api > /tmp/native_e2e.log 2>&1 &
API=$!
sleep 6
B="localhost:8091"

clear_limits() { redis-cli --scan --pattern 'otp_req:*' | while read -r k; do redis-cli del "$k" >/dev/null; done }
native_signup() { # name email -> "access refresh"
  clear_limits
  curl -s -X POST $B/api/auth/signup -H 'Content-Type: application/json' -H 'X-Client: native' -d "{\"display_name\":\"$1\",\"email\":\"$2\"}" >/dev/null
  sleep 0.3
  local otp; otp=$(redis-cli get "otp:signup:$2")
  curl -s -X POST $B/api/auth/signup/verify -H 'Content-Type: application/json' -H 'X-Client: native' -d "{\"email\":\"$2\",\"code\":\"$otp\"}" \
    | python3 -c "import sys,json;d=json.load(sys.stdin)['data'];print(d['access_token'],d['refresh_token'])"
}

echo "── Native token lifecycle"
read -r ACC REF <<< "$(native_signup Alex alex@nat.io)"
check "signup(native) returns tokens"        "eyJ" "$ACC"
R=$(curl -s $B/api/auth/me -H "Authorization: Bearer $ACC")
check "bearer auth works"                    '"display_name":"Alex"' "$R"
R=$(curl -s $B/api/auth/me)
check "no auth → 401 envelope"               'unauthorized' "$R"

R=$(curl -s -X POST $B/api/auth/token/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REF\"}")
ACC2=$(echo "$R" | jqf "d['data']['access_token']")
REF2=$(echo "$R" | jqf "d['data']['refresh_token']")
check "refresh rotates"                      "eyJ" "$ACC2"
R=$(curl -s -X POST $B/api/auth/token/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REF\"}")
check "immediate replay = retry grace → 200" "access_token" "$R"
sleep 3
R=$(curl -s -X POST $B/api/auth/token/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REF\"}")
check "replay after grace = THEFT → 401"     'unauthorized' "$R"
R=$(curl -s -X POST $B/api/auth/token/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REF2\"}")
check "whole family revoked after theft"     'unauthorized' "$R"
R=$(curl -s -X POST $B/api/auth/token/refresh -H 'Content-Type: application/json' -d '{"refresh_token":"garbage"}')
check "garbage refresh → 401"                'unauthorized' "$R"

echo "── Logout revocation"
read -r ACC REF <<< "$(native_signup Buster buster@nat.io)"
curl -s -X POST $B/api/auth/logout -H "Authorization: Bearer $ACC" -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REF\"}" >/dev/null
R=$(curl -s -X POST $B/api/auth/token/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REF\"}")
check "logout revokes refresh"               'unauthorized' "$R"

echo "── Device registration"
read -r ACC REF <<< "$(native_signup Dev dev@nat.io)"
TOK=$(python3 -c "print('cd'*32)")
R=$(curl -s -X POST $B/api/push/device -H "Authorization: Bearer $ACC" -H 'Content-Type: application/json' -d "{\"platform\":\"apns\",\"token\":\"$TOK\",\"device_label\":\"e2e\"}")
check "device registers"                     'Device registered' "$R"
R=$(curl -s -X POST $B/api/push/device -H "Authorization: Bearer $ACC" -H 'Content-Type: application/json' -d "{\"platform\":\"apns\",\"token\":\"$TOK\"}")
check "re-register same token idempotent"    'success":true' "$R"
CNT=$(PSQL -d rallyup_native_e2e -c "SELECT COUNT(*) FROM device_tokens WHERE token='$TOK'")
check "single row for re-registered token"   "1" "$CNT"
R=$(curl -s -X DELETE $B/api/push/device -H "Authorization: Bearer $ACC" -H 'Content-Type: application/json' -d "{\"token\":\"$TOK\"}")
check "device unregisters"                   'success":true' "$R"
R=$(curl -s -X POST $B/api/push/device -H 'Content-Type: application/json' -d "{\"platform\":\"apns\",\"token\":\"$TOK\"}")
check "unauthenticated register → 401"       'unauthorized' "$R"

echo "── Account deletion (Apple 5.1.1)"
read -r AACC AREF <<< "$(native_signup Owner owner@nat.io)"
curl -s -X POST $B/api/groups -H "Authorization: Bearer $AACC" -H 'Content-Type: application/json' -d '{"name":"Del Club"}' >/dev/null
clear_limits
curl -s -X POST $B/api/groups/invites -H "Authorization: Bearer $AACC" -H 'Content-Type: application/json' -d '{"email":"heir@nat.io"}' >/dev/null
read -r HACC HREF <<< "$(native_signup Heir heir@nat.io)"
INV=$(curl -s $B/api/invites -H "Authorization: Bearer $HACC" | jqf "d['data'][0]['id']")
curl -s -X POST $B/api/invites/$INV/accept -H "Authorization: Bearer $HACC" >/dev/null
curl -s -X POST $B/api/credentials -H "Authorization: Bearer $AACC" -H 'Content-Type: application/json' -d '{"bintang_name":"Owner","bintang_password":"gone1","screenshot_path":null}' >/dev/null
curl -s -X POST $B/api/kcal -H "Authorization: Bearer $AACC" -H 'Content-Type: application/json' -d '{"kcal":300}' >/dev/null
R=$(curl -s -X DELETE $B/api/auth/me -H "Authorization: Bearer $AACC")
check "delete account succeeds"              'success":true' "$R"
R=$(curl -s -X POST $B/api/auth/token/refresh -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$AREF\"}")
check "deleted user sessions dead"           'unauthorized' "$R"
CNT=$(PSQL -d rallyup_native_e2e -c "SELECT COUNT(*) FROM kcal_logs k JOIN users u ON u.id=k.user_id WHERE u.email LIKE 'deleted-%'")
check "kcal purged"                          "0" "$CNT"
NAME=$(PSQL -d rallyup_native_e2e -c "SELECT display_name FROM users WHERE email LIKE 'deleted-%' LIMIT 1")
check "user row anonymized"                  "Deleted member" "$NAME"
ROLE=$(curl -s $B/api/auth/me -H "Authorization: Bearer $HACC" | jqf "d['data']['active_group_role']")
check "sole-admin succession → heir is admin" "admin" "$ROLE"

echo "── Web cookie flow untouched"
clear_limits
curl -s -X POST $B/api/auth/signup -H 'Content-Type: application/json' -d '{"display_name":"Webby","email":"web@nat.io"}' >/dev/null
sleep 0.3
OTP=$(redis-cli get "otp:signup:web@nat.io")
R=$(curl -s -c /tmp/nat_ck.txt -X POST $B/api/auth/signup/verify -H 'Content-Type: application/json' -d "{\"email\":\"web@nat.io\",\"code\":\"$OTP\"}")
case "$R" in *access_token*) bad "web verify has NO tokens in body" "ABSENT" "$R";; *) ok "web verify has NO tokens in body";; esac
R=$(curl -s -b /tmp/nat_ck.txt $B/api/auth/me)
check "cookie session works"                 '"display_name":"Webby"' "$R"

kill $API 2>/dev/null
PSQL -d postgres -c "DROP DATABASE IF EXISTS rallyup_native_e2e" >/dev/null 2>&1
rm -rf uploads_native_e2e /tmp/nat_ck.txt
echo
echo "════════ NATIVE-AUTH E2E: $PASS passed, $FAIL failed ════════"
exit $FAIL
