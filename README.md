# 🏸 RallyUp API (badminton-be-rust)

Rust/Axum backend for **RallyUp**, the Bintang Badminton group-coordination PWA.
Pairs with the frontend in [badminton-fe](https://github.com/vikasm0455/badminton-fe).

Stack: Axum + SQLx (Postgres) + Redis · email OTP (Resend) · Claude Vision OCR ·
Web Push (VAPID) · tokio scheduled jobs. All times in America/Los_Angeles.

## Run locally

Needs Postgres + Redis running locally.

```bash
cp .env.example .env     # set JWT_SECRET, ADMIN_EMAIL; keys optional in dev
cargo run                # API on :8090, auto-creates DB + runs migrations
```

Without `RESEND_API_KEY`, OTP codes are printed to the server log (dev mode).
Without `ANTHROPIC_API_KEY`, credential OCR is skipped (manual entry).

### First admin (bootstrap)

A fresh DB has no users, and login only sends an OTP to an existing account, so
seed the owner once (must match `ADMIN_EMAIL`):

```sql
INSERT INTO users (display_name, email, role, status, approved_at)
VALUES ('Your Name', 'you@example.com', 'admin', 'active', NOW());
```

Then log in with that email; the OTP is emailed (or printed to the log in dev).
From **Admin → Invites**, generate invite links for everyone else.

### Admin recovery CLI

```bash
cargo run --bin reset-admin-otp     # clears OTP rate limits/lockout for ADMIN_EMAIL
```

## Deploy (Docker)

GitHub Actions (`.github/workflows/deploy.yml`) builds and pushes
`vikasm0455/badminton-be-rust:latest` to Docker Hub on every push to `main`.

The frontend builds its own image ([badminton-fe](https://github.com/vikasm0455/badminton-fe)
→ `vikasm0455/badminton-fe:latest`) — unlike WatchWhere, the FE is **not** baked
into this image (Next.js needs its own Node runtime), so no cross-repo trigger
is needed; each repo ships independently.

On the server, this repo's `docker-compose.yml` runs the whole stack (API + FE +
Postgres + Redis + Nginx):

```bash
cp .env.example .env     # fill in production secrets
docker compose pull && docker compose up -d
```

Point a Cloudflare Tunnel (`badminton.boyishesh.com`) at `nginx` (port 8080 → 80).

### Required CI secrets

| Secret | Purpose |
|---|---|
| `DOCKER_USERNAME` | Docker Hub user (`vikasm0455`) |
| `DOCKER_TOKEN` | Docker Hub access token |

## Env vars

See [.env.example](.env.example). `DATABASE_URL`, `REDIS_URL`, and `JWT_SECRET`
are enough to boot; `RESEND_API_KEY`, `ANTHROPIC_API_KEY`, and `VAPID_SUBJECT`
enable email, OCR, and push. VAPID keys are auto-generated on first boot and
stored in the DB.
