# Hosting CTFGenerator

There are two ways to run CTFGenerator:

- **The supported platform (M6+)** — the FastAPI control plane + PostgreSQL +
  isolated workers + artifact store, deployed behind a TLS reverse proxy. **This is
  the supported product; see §0 below.**
- **The legacy standalone engine** — the stdlib `ctfgen serve` dashboard over a
  fixture/JSONL store. The rest of this document (§1 onward) is that walkthrough;
  it is the single-binary demo path, NOT the supported multi-host platform.

---

## 0. Supported platform deployment (M6+)

The supported deployment is a **single Linux control-plane host** (ASGI behind a
TLS-terminating reverse proxy) + **PostgreSQL** + **≥1 isolated worker host** +
an artifact store. Kubernetes is out of scope for V1 (compose/systemd scale).

**Reference artifacts** live in `deploy/`:
`Dockerfile.api` (the docker-FREE control-plane image — the control plane never
holds a Docker socket), `Dockerfile.worker`, `entrypoint.sh` (migrate-then-serve),
`docker-compose.yml` (a dev/demo single-host topology), `.env.example`, and
`verify-deploy.sh` (builds the image, boots it, and asserts readiness + the
no-docker-socket invariant).

**Configuration** is env-only (secrets never committed) — see
[operations/configuration.md](operations/configuration.md).

### Quick start (dev/demo, single host)

```bash
cp deploy/.env.example deploy/.env          # fill in real secrets (gitignored)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build
```

The API service runs `alembic upgrade head` then serves; wait for
`GET /api/v1/system/ready` to return 200 (its `migrations` check gates on the code
head). Then seed the first admin (one-time):

```bash
CTFGEN_DATABASE_URL=... CTFGEN_BOOTSTRAP_ADMIN_PASSWORD=... \
  ctfgen-admin bootstrap-admin --email admin@example.org --display-name Admin
```

### Production topology (multi-host)

- **Control plane** (`uvicorn ctf_generator.interfaces.api.app:app`, `.[deploy]`
  extra): behind a reverse proxy (nginx/caddy) that **terminates TLS**. Set
  `CTFGEN_API_TRUSTED_PROXY=1` (so the rate-limiter reads the real client IP from
  `X-Forwarded-For`) and leave web session cookies `Secure` (do NOT set
  `CTFGEN_WEB_COOKIE_INSECURE`). The control-plane host/image has **no Docker
  socket, no BuildKit, and never runs challenge code** (REQ-INV-010 — proven by
  `deploy/verify-deploy.sh`).
- **Worker gateway** (`uvicorn ...worker_app:worker_app`): the worker-facing API on
  its **own listener**, reachable only by workers (mutual isolation from the human
  API).
- **Worker host(s)** (`ctfgen-worker`, `.[worker]` extra): a **SEPARATE** host with
  a **rootless** container engine (Docker/Podman, ADR-004) and **`NET_ADMIN` + a
  working iptables backend (`xt_comment`)** — the M8 host-block firewall is a HARD
  FLOOR: if the host cannot enforce container→host isolation, `launch()` **refuses**
  (see [security/runtime-isolation.md](security/runtime-isolation.md)). Per-instance
  `--internal` networks; ingress reaches instances ONLY through the reverse proxy.
- **PostgreSQL** (15/16) + the artifact volume (local-FS now; S3-compatible is the
  same protocol, credential-blocked). Back up per
  [operations/backup-recovery-upgrade.md](operations/backup-recovery-upgrade.md).

**Upgrades:** `alembic upgrade head` (the entrypoint does this on deploy) — the
`/api/v1/system/ready` migration gate returns 503 until the DB matches the code
head. Rollback policy (forward-fix preferred; append-only tables never downgraded
destructively) is in the backup/recovery/upgrade doc.

---

## Legacy standalone engine (single-binary demo)

The remainder is the stdlib `ctfgen serve` dashboard — a fixture/JSONL demo, **not**
the supported platform above. Install first if you haven't:

```bash
python3 -m pip install -e .
ctfgen --version
```

## 1. Generate challenges

The fastest path to something running is `quickstart`, which generates three
deterministic sample challenges (a web challenge, a crypto challenge, and a
CVE-driven Log4Shell challenge) and prints the exact next commands:

```bash
ctfgen quickstart --output ./comp --seed my-event-001
```

For a real event you'll want more/specific challenges. Generate one by hand:

```bash
ctfgen create --output comp/invoice-drift --seed demo-001 --difficulty hard
```

Or ground one in a real, named CVE (category picks the family, CVSS picks
difficulty unless overridden):

```bash
ctfgen cve-categories
ctfgen cve-search --category scada_ics --min-cvss 8.0
ctfgen create-from-cve CVE-2021-44228 --output comp/log4shell --seed demo-001
```

Repeat `create`/`create-from-cve` for every domain and mode you want in the
competition (`ctfgen list-families` lists the 8 registered families and the
`red`/`blue`/`purple` modes each supports). Put every generated challenge
folder as an immediate subdirectory of one parent directory (e.g. `comp/`) —
that parent directory is what `catalog` and `serve --challenges-dir` scan.

## 2. Validate

Statically validate every challenge before publishing it:

```bash
ctfgen validate comp/invoice-drift
```

Optionally, if Docker is available, run full runtime validation (build, boot,
health check, run the private solver, tear down):

```bash
ctfgen validate-runtime comp/invoice-drift
```

Score a challenge's AI-resistance and optionally gate on a minimum:

```bash
ctfgen score comp/invoice-drift --min-score 80
```

## 3. Build a catalog

Scan a directory of generated challenges into a `ChallengeScoringConfig` JSON
catalog:

```bash
ctfgen catalog --challenges-dir comp --output comp/catalog.json
```

Each entry gets the challenge's folder name as `challenge_id`, default scoring
values (override `initial_value`/`minimum_value`/`decay_function`/`decay` by
hand-editing the JSON if you don't want the defaults), plus display-only
`title`/`category` fields read out of each `challenge.yaml`.

You can skip this file entirely and point `serve` at the directory directly
with `--challenges-dir` (see below) — `catalog` exists for cases where you
want to inspect/edit the scoring config before serving, or feed the same JSON
shape into `ctfgen scoreboard --challenges`.

## 4. Launch the dashboard

```bash
ctfgen serve \
  --admin-user admin \
  --admin-password 'change-me' \
  --challenges-dir comp \
  --events-file comp/events.jsonl
```

Flags:

- `--admin-user` / `--admin-password` (required) — the one admin login. The
  password is PBKDF2-hashed in memory; never printed back out.
- `--challenges-dir DIR` — scan a directory of generated challenge folders
  into the catalog in-process (what `quickstart` recommends). Alternative:
  `--challenges catalog.json` (the file `ctfgen catalog` produces).
- `--config config.json` — a `CompetitionConfig` JSON object
  (`competition_id`, `name`, `start_time`, `end_time`, optionally
  `scoring_start_time`/`freeze_time`); omit it for a permissive built-in
  year-long placeholder.
- `--events-file PATH` — persist the event log to JSONL so solves survive a
  restart; omit for in-memory only (lost on restart).
- `--public-token TOKEN` — fix the public scoreboard token; omit and one is
  generated randomly and printed once at startup (`public scoreboard token:
  ...`) — save it, it's not shown again.
- `--host` / `--port` — default `127.0.0.1:8000`.

```
$ ctfgen serve --admin-user admin --admin-password 'change-me' --challenges-dir comp
public scoreboard token: pR3q...redacted...
Serving CTFGenerator dashboard on http://127.0.0.1:8000
```

## 5. Open the browser UI

Everything is self-contained HTML/CSS/JS served inline by the stdlib
`http.server` — no external CDN, fonts, or scripts, so it works with no
network egress and a strict CSP.

- **Admin login** — open `http://127.0.0.1:8000/login`, sign in with
  `--admin-user`/`--admin-password`. On success you land on `/`, the live
  admin dashboard: team progress, the leaderboard, and the solve feed.
- **Public scoreboard** — publish
  `http://127.0.0.1:8000/public?token=<public-token>` to contestants/
  spectators. It requires only the public token (query string or
  `X-Public-Token` header) — never an admin session — and shows a *redacted*
  leaderboard (display name, rank, score, solve count only; no team ids, no
  per-challenge detail) plus a redacted solve feed at `/public/feed`.

## 6. Record solves and watch the feed

Solves are posted as events against the authenticated admin API. From a
logged-in browser session (or any client holding the session cookie *and*
the CSRF token returned by `/login`):

```bash
curl -X POST http://127.0.0.1:8000/api/event \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <csrf-token-from-login-response>" \
  --cookie "ctfgen_session=<session-cookie-from-login-response>" \
  -d '{"type": "solve", "team_id": "team-alpha", "challenge_id": "invoice-drift"}'
```

`type`, `team_id`, and `challenge_id` are required; `payload` is optional
free-form JSON. Every authenticated request (including this one) rotates the
session cookie in the response — always use the newest cookie for the next
request.

Watch progress live:

- `GET /api/progress` — per-team progress.
- `GET /api/leaderboard` — the full (non-redacted) admin leaderboard.
- `GET /api/feed?since=<seq>` — events with `seq` greater than `since`, for
  polling a live feed.
- The admin dashboard page (`/`) and the public scoreboard page (`/public`)
  both render this same data as self-refreshing HTML.

## 7. Choosing a scoring engine

```bash
ctfgen list-scoring-engines
```

```
ai_resistance
dynamic_decay
static
time_decay (default)
```

- `time_decay` (default) — value decays linearly with *elapsed competition
  time*, rewarding early solves regardless of solve count.
- `dynamic_decay` — CTFd-style: value decays as `solve_count` rises (`linear`
  or `logarithmic`, per each challenge's `decay_function`/`decay`).
- `static` — a constant value per challenge.
- `ai_resistance` — wraps another engine and applies an advisory
  per-challenge weight multiplier.

`serve` doesn't take a `--engine` flag directly; it's a `CompetitionService`
constructor field (`scoring_engine`), so `serve`'s built-in service defaults
to `time_decay`. `ctfgen scoreboard` (for computing/freezing a scoreboard from
JSON fixtures out-of-band, e.g. for a post-event report or a frozen final
snapshot) does take `--engine` and `--as-of`:

```bash
ctfgen scoreboard --events comp/events.json --challenges comp/catalog.json \
  --config comp/config.json --engine time_decay --json
```

## 8. Durable storage: the optional `[postgres]` extra

By default `serve` uses an in-memory event store, or a JSONL file with
`--events-file` (both stdlib-only, no extra to install). For a real,
concurrent-writer-safe, queryable event log, `ctf_generator.postgres_events`
provides `PostgresEventStore`, a drop-in `EventStore` implementation backed
by a `competition_events` table (`seq`, `ts`, `type`, `team_id`,
`challenge_id`, `payload jsonb`).

```bash
pip install -e '.[postgres]'
```

`ctfgen serve` does not currently expose a `--postgres-dsn` flag; wire it in
by constructing the service yourself and calling `dashboard_server.serve`:

```python
from ctf_generator import dashboard_server
from ctf_generator.postgres_events import PostgresEventStore
from ctf_generator.competition_service import CompetitionService, ChallengeCatalog
from ctf_generator.dashboard_server import AuthConfig

store = PostgresEventStore(dsn="postgresql://user:pass@host/dbname")
store.init_schema()
service = CompetitionService(store=store, catalog=ChallengeCatalog(), config=...)
auth = AuthConfig.create(admin_username="admin", password="change-me")
server = dashboard_server.serve("0.0.0.0", 8000, service=service, auth=auth)
server.serve_forever()
```

`psycopg` is only imported lazily when `PostgresEventStore` opens its own
connection from a DSN, so nothing in the core package depends on it.

## 9. Security model

- **Admin routes** (`/`, `/api/progress`, `/api/leaderboard`, `/api/feed`,
  `POST /api/event`) all require a valid, non-expired session cookie issued
  by `POST /login` after a PBKDF2 (200,000-iteration, per-user-salted)
  password check.
- **Session rotation** — state-changing `POST`s rotate the session token and
  the old token stops working immediately (carry forward the newest
  `Set-Cookie`). Idempotent `GET`s do **not** rotate — they only slide the
  expiry — so the dashboard's concurrent polls don't invalidate each other.
- **CSRF** — every `POST` additionally requires a matching `X-CSRF-Token`
  header (the token returned once by `/login`), checked with a
  constant-time comparison.
- **Response headers** — every response carries `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`; HTML
  pages additionally carry a strict `Content-Security-Policy` (self-contained,
  no external origins).
- **Cookies over TLS** — the built-in server speaks plain HTTP. When you put
  it behind a TLS-terminating proxy, pass `serve --secure-cookie` to add the
  `Secure` attribute to session cookies.
- **Public routes are a hard boundary** — `/public/scoreboard`, `/public/feed`,
  and the `/public` HTML page require only the separate public token
  (`X-Public-Token` header or `?token=`), are checked with constant-time
  comparison, and can *never* reach an admin route: the public token is a
  different secret from the admin session/CSRF tokens, and admin routes
  never accept it.
- **What the public surface exposes** — a redacted leaderboard (display
  name, rank, score, solve count) and a redacted solve feed; no team ids, no
  per-challenge admin detail.
- **Validating untrusted bundles** — `validate-runtime` runs a challenge's
  own `tests/healthcheck.py` and `private/solver.py`. By default these run on
  the host with your privileges (fine for challenges you generated). For a
  bundle you did **not** author, pass `validate-runtime --sandbox` to run
  those scripts inside an ephemeral read-only `python:3.11-slim` container
  instead of on the host.
- **MCP / Docker boundary** — if you also run `ctfgen-mcp` to let an MCP
  host draft challenge metadata, note that Docker execution, AI-agent
  evaluation, and this competition dashboard are deliberately **not**
  exposed as MCP tools. `validate-runtime`, `replay`,
  `validate-siblings --runtime`, `run-scenario --runtime`, `eval-agent`, and
  `serve` all stay CLI-only, so connecting a model host to the MCP server
  never hands it container builds, host execution, or this live
  scoreboard/admin surface.
