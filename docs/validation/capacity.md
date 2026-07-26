# Capacity / load validation (M20)

Status: **SINGLE-HOST DEPLOYMENT TARGETS MET (out-of-process, real TLS) — the
multi-host production sign-off is still its own step.** The 25×20 submission
(<500 ms) and scoreboard (<3 s) latency targets are met on the deployed stack when
the API is sized to multiple uvicorn workers (see the out-of-process section
below); instance-launch ≥99% still needs a real worker fleet.

This documents the in-process capacity harness (`scripts/loadtest.py`), the SMOKE
numbers actually measured on this host, and — bluntly, per charter §5 — exactly
which `REQ-NFR-*` targets remain **UNVERIFIED** here and why.

## The operating targets (`REQ-NFR-001..005`)

From `docs/REQUIREMENTS.md` §6:

| ID | Attribute | Target |
|---|---|---|
| REQ-NFR-001 | Concurrent teams | 25 (steady state) |
| REQ-NFR-002 | Active challenges | 20 (concurrently launchable) |
| REQ-NFR-003 | Instance launch success | ≥ 99% |
| REQ-NFR-004 | Scoreboard update latency | < 3 s |
| REQ-NFR-005 | Submission processing | < 500 ms (server-side, per submission) |

Before M20 none of these had a harness or a measured number.

## The harness (`scripts/loadtest.py`)

A self-contained stdlib + FastAPI/Starlette `TestClient` concurrency driver. It:

1. creates a **throwaway** PostgreSQL database from `$CTFGEN_TEST_DATABASE_URL`,
   migrates it to head, and seeds one competition + `--teams` teams +
   `--challenges` published, attached challenges (each with a distinct flag);
2. drives `create_app` over that **real** database through a **real ASGI
   transport** from `--teams` concurrent OS threads, each with its own
   `TestClient` (so the httpx client is never shared across threads). Every
   submitter POSTs a mix of correct/incorrect answers; `--readers` threads
   hammer `GET .../scoreboard` under that same load;
3. measures wall-clock latency per request and reports **p50 / p95 / max** for
   submission processing (REQ-NFR-005) and scoreboard reads (REQ-NFR-004),
   printed next to the targets — measured-vs-target, never pass/fail-by-redefinition;
4. drops the throwaway database.

It prints the MEASURED numbers truthfully. It does **not** move the SLOs to make
a number look good, and it prints `OVER TARGET` whenever a measured p95 exceeds
its target.

Run it:

```
CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \
  PYTHONPATH=src:tests python scripts/loadtest.py \
    --teams 8 --challenges 4 --submissions-per-team 25 --readers 3
```

`--duration N` makes each submitter loop for `N` seconds instead of a fixed count.

## What was actually measured on this host

PostgreSQL 16 in the `ctfgen_pg_epic1` container (172.20.0.2:5432), single rootful
arm64 host, single in-process control-plane app, synchronous structured JSON
logging on. Numbers vary run to run; representative observed values:

### SMOKE scale (what the gated test asserts)

`--teams 3 --challenges 2 --submissions-per-team 5 --readers 2`:

| Metric | Target | Measured (p50 / p95 / max) | Verdict |
|---|---|---|---|
| Submission processing (REQ-NFR-005) | < 500 ms | ≈ 270 / 435 / 480 ms | p95 under target |
| Scoreboard read (REQ-NFR-004) | < 3000 ms | ≈ 60 / 115 / 210 ms | p95 under target |

`tests/test_capacity_smoke_integration.py` runs exactly this scale and asserts the
latencies are recorded as real, finite, positive numbers within a **generous**
smoke bound (submission p95 < 3000 ms — deliberately NOT the 500 ms SLO — and
scoreboard p95 < 3000 ms), plus zero submit/read errors and one latency sample
per successful request. It proves the harness WORKS; it does not certify the SLO.

### At the REQ-NFR-001/002 concurrency (25 teams × 20 challenges), still in-process

`--teams 25 --challenges 20 --submissions-per-team 10 --readers 4`:

| Metric | Target | Measured (p50 / p95 / max) | Verdict |
|---|---|---|---|
| Submission processing (REQ-NFR-005) | < 500 ms | ≈ 1190 / 2050 / 4160 ms | **p95 OVER TARGET** |
| Scoreboard read (REQ-NFR-004) | < 3000 ms | ≈ 115 / 1180 / 2580 ms | p95 under target (degrading) |

This is an honest, uncomfortable result and it is reported as-is. At 25 concurrent
submitters this **in-process, single-PostgreSQL** configuration does **NOT** meet
the 500 ms submission SLO.

### Follow-up investigation + the two ceilings that were fixed

A later pass profiled the path and split the causes into *product* serialization
ceilings (fixable in code) and a *harness* artifact:

- **Product ceiling #1 — the submission advisory lock was competition-wide.**
  `SubmissionProcessingService` took a `pg_advisory_xact_lock` keyed on the
  *competition* only, held for the whole ~9–18-round-trip transaction, so **every
  submission across every team serialized** on one lock — and the harness funnels
  all 25 teams into one competition. The at-most-one-solve invariant does **not**
  depend on that lock (the `uq_solves_(competition,team,version)` UNIQUE + the
  service's SAVEPOINT retry are the authoritative backstop; the projector's
  `as_of_seq` UPSERT makes a refold idempotent). **Fixed:** the submission path now
  uses `acquire_submission_lock` keyed at `(competition, team, challenge-version)`
  (`infrastructure/database/locks.py`), so different teams/challenges — and a
  concurrent projector refold — never block each other.
- **Product ceiling #2 — the connection pool was the library default (15).**
  With ~29 concurrent request threads, threads blocked acquiring a *connection*
  before doing any work, serializing requests independently of any lock.
  **Fixed:** `DatabaseConfig` now sizes the `QueuePool` to 20 + 20 = 40 (env-tunable
  via `CTFGEN_DB_POOL_SIZE` / `CTFGEN_DB_MAX_OVERFLOW`).

- **Harness artifact — the in-process run is GIL-bound.** With those two ceilings
  removed, in-process throughput barely moved (≈29.5 → ≈33 req/s) and stayed flat
  as thread count grew 8× (3-team smoke ≈26 req/s vs 25-team ≈33 req/s). That flat
  ceiling is the signature of the **single-process GIL**: app + DB driver + load
  generator all execute Python on one interpreter, so the run saturates one core's
  Python execution (ORM hydration, per-request `json.dumps` access logging) before
  the advisory lock or the connection pool can bind. The measured p95 is therefore
  substantially a **measurement-environment** artifact of the co-located,
  single-GIL harness — not a product limit — which is exactly why capacity.md has
  always called this run a *lower bound / harness proof*, not a sign-off.

The two code fixes remove the real serialization ceilings that **would** bind in a
production topology (multiple app processes/hosts, each its own GIL; DB on its own
host); they cannot be *demonstrated* by this GIL-bound in-process harness, which is
a limitation of the harness, not of the fixes. The remaining per-submission-cost
lever — collapsing the redundant `_resolve.*` uuid look-ups (competition/team/
version are re-resolved 3–4× each across the lock/submission/solve/event steps)
into a single resolve passed down — is the identified next step; it is an invasive
change to the scoring-path repository signatures and is deliberately left for a
separate, reviewed pass rather than bundled here.

## OUT-OF-PROCESS measurement on the deployed stack (`scripts/loadtest_http.py`)

The in-process harness above could not *demonstrate* that the p95 was a GIL
artifact rather than a product limit — proving it needs a real, multi-process
client hitting a real deployment. `scripts/loadtest_http.py` does exactly that: it
provisions a competition (25 teams × 20 published+attached challenges + 25 player
memberships via the roster API) and then drives **real HTTPS submissions from
`--procs` separate OS processes** against the **supported Docker deployment**
(`deploy/`, Caddy TLS → uvicorn → PostgreSQL 16), reporting p50/p95/max.

Measured on this single 12-core rootful arm64 host, 25 teams × 20 challenges,
30 s sustained, 16 load processes:

| API sizing | Submission p95 (REQ-NFR-005, <500 ms) | Scoreboard p95 (REQ-NFR-004, <3 s) | Throughput | Errors |
|---|---|---|---|---|
| **1 uvicorn worker** (default) | ≈ **1140 ms — OVER** | ≈ 650 ms — under | ≈ 13 req/s | 0 |
| **6 uvicorn workers** (`CTFGEN_API_WORKERS=6`, pool 8+4) | ≈ **131 ms — UNDER** | ≈ 70 ms — under | ≈ **178 req/s** | 0 (5352 submissions) |

This **confirms the earlier diagnosis and closes it**: the single-interpreter p95
was **deployment sizing**, not a product serialization limit. With the reference
deployment sized to multiple uvicorn workers (added: `CTFGEN_API_WORKERS`, with the
already-present `CTFGEN_DB_POOL_SIZE`/`CTFGEN_DB_MAX_OVERFLOW` keeping N × pool under
PostgreSQL `max_connections`), the 25×20 submission and scoreboard latency targets
are **MET on the deployed stack over real TLS**, out of process, with zero errors.

Run it:

```
python scripts/loadtest_http.py all --base-url https://localhost --insecure \
  --admin-email admin@ctf.local --admin-password "$PW" \
  --admin-exec 'docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.worker-gateway.yml --env-file deploy/.env exec -T api ctfgen-admin' \
  --teams 25 --challenges 20 --duration 30 --procs 16
```

**Honest caveats on this result:** (1) a **single physical host** with one
PostgreSQL and loopback TLS — not a multi-host fleet; (2) the per-IP edge **rate
limiter was disabled** for the run (`CTFGEN_API_RATE_LIMIT=0`) because a
single-source load generator otherwise shares one token bucket — real contestants
arrive from distinct IPs, so the limiter is orthogonal to processing capacity;
(3) this measures the **submission + scoreboard** paths, not instance launch
(below). It is a real, re-runnable single-host capacity result; a multi-host
production sign-off is still its own step.

## UNVERIFIED here (charter §5 — blunt statement)

The full `REQ-NFR-001..005` targets at **production scale** are **NOT signed off**
by this harness. Specifically:

- **REQ-NFR-003 (instance launch success ≥ 99%) — UNVERIFIED.** A real launch
  needs the M8 desired→observed reconciler driving a **real isolated worker host**
  that actually starts a container. No worker runs in this in-process harness. The
  harness only probes that the instances API surface answers and reports launch
  success as UNVERIFIED — it never fabricates a ≥ 99% number.
- **REQ-NFR-005 (submission < 500 ms) and REQ-NFR-004 (scoreboard < 3 s) at 25
  steady-state teams — MET on the single-host deployment, multi-host sign-off
  PENDING.** The out-of-process run on the deployed stack (above) meets both
  targets (submission p95 ≈131 ms, scoreboard p95 ≈70 ms) once the API is sized to
  multiple uvicorn workers. What remains is the **multi-host** form — separate
  PostgreSQL host, real reverse-proxy TLS across hosts, several API replicas, and
  launched instances included — under a sustained profile.
- **REQ-NFR-001/002 (25 teams × 20 live challenges) as an end-to-end envelope —
  UNVERIFIED.** The harness seeds and drives that many teams/challenges for the
  submission + scoreboard paths, but "live challenges" in production also means 20
  launched, reachable instances, which this in-process harness does not stand up.

The production capacity sign-off (a tuned multi-host deployment, launched isolated
workers, and the ≥ 99% launch-success measurement) is **M21/M22 work**, not this
milestone. This document is the harness and its first honest data point — not the
capacity certification.
