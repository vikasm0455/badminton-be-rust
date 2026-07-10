# Deploying the native-app backend (Phase 0 → venue → metrics)

One deploy takes the server from the currently-running multi-tenant build to
full native-app support. Everything is **additive** — the web PWA is untouched
and no user notices anything.

## 1 · Deploy

```bash
docker compose pull && docker compose up -d
```

Migrations `0004_native_auth_push.sql` (refresh/device tokens) and
`0005_group_venue.sql` (per-group court ranges; existing groups keep 1–53)
self-apply on boot. Rollback = redeploy the previous image; both migrations
are additive so the old build keeps working against the new schema.

## 2 · Environment variables (server `.env` — never committed)

| Var | Required | Purpose |
|---|---|---|
| `METRICS_TOKEN` | recommended | Bearer token gating `/metrics` (404 without it) |
| `APNS_KEY_P8` | for iOS push | Path to the AuthKey_XXXX.p8 file (mount it into the container) |
| `APNS_KEY_ID` | for iOS push | 10-char Key ID shown next to the key |
| `APNS_TEAM_ID` | for iOS push | 10-char Team ID (Membership page) |
| `APNS_BUNDLE_ID` | for iOS push | `com.badmintonrallyup.app` |
| `APNS_SANDBOX` | dev builds | `true` while testing debug builds; `false` for TestFlight/App Store |
| `FCM_SERVICE_ACCOUNT` | for Android push (Phase 3) | Path to the Firebase service-account JSON |

Unset push vars ⇒ that channel is silently skipped (same pattern as Resend);
web push keeps working regardless.

## 3 · Observability

- **Dashboard**: Grafana → Dashboards → Import → `grafana-rallyup-native.json`
  (pick your Prometheus datasource). Panels: web-vs-native traffic, feature
  events, refresh-token outcomes incl. the theft signal, push deliveries,
  mobile p95 latency.
- **Alerts**: merge `prometheus-rallyup-alerts.yml` into Prometheus
  `rule_files`. The critical one — `RefreshTokenReuseDetected` — should never
  fire; if it does, a stolen refresh token was replayed (the family is already
  revoked automatically; check `security_events`).
- Prometheus scrape needs the token:
  ```yaml
  authorization:
    credentials: <METRICS_TOKEN>
  ```

## 4 · Post-deploy smoke (2 minutes)

```bash
# native auth alive (expect 401 envelope, not 404):
curl -s -X POST https://<host>/api/auth/token/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"x"}'
# venue config present (as a logged-in web user, courts 1-53 by default):
#   web app → your group behaves exactly as before
# metrics flowing:
curl -s https://<host>/metrics -H "Authorization: Bearer $METRICS_TOKEN" | grep feature_events | head
```
