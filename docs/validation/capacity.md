# Capacity / load validation (M20)

Status: **HARNESS PROOF + FIRST DATA POINT — NOT the production capacity sign-off.**

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
the 500 ms submission SLO. Contributing factors observed in this configuration
(NOT product-inherent, and NOT tuned here): the default 15-connection SQLAlchemy
pool throttling ~29 concurrent request threads, synchronous per-request JSON
logging to stdout, the single arm64 host running the DB + app + load generator
together, and outbox-trigger contention on the shared score projection. Tuning any
of these is deployment work, not a change to the thing under test — so this run is
recorded as a data point, not acted on here.

## UNVERIFIED here (charter §5 — blunt statement)

The full `REQ-NFR-001..005` targets at **production scale** are **NOT signed off**
by this harness. Specifically:

- **REQ-NFR-003 (instance launch success ≥ 99%) — UNVERIFIED.** A real launch
  needs the M8 desired→observed reconciler driving a **real isolated worker host**
  that actually starts a container. No worker runs in this in-process harness. The
  harness only probes that the instances API surface answers and reports launch
  success as UNVERIFIED — it never fabricates a ≥ 99% number.
- **REQ-NFR-005 (submission < 500 ms) and REQ-NFR-004 (scoreboard < 3 s) at 25
  steady-state teams — UNVERIFIED as a production sign-off.** The in-process
  single-PG measurement above is a **lower bound / harness proof**. A real sign-off
  needs the supported deployment (`docs/HOSTING.md`: separate PostgreSQL, tuned
  connection pool, reverse proxy, log shipping off the hot path, ≥ 1 isolated
  worker host) under a sustained load profile — with launched instances included.
- **REQ-NFR-001/002 (25 teams × 20 live challenges) as an end-to-end envelope —
  UNVERIFIED.** The harness seeds and drives that many teams/challenges for the
  submission + scoreboard paths, but "live challenges" in production also means 20
  launched, reachable instances, which this in-process harness does not stand up.

The production capacity sign-off (a tuned multi-host deployment, launched isolated
workers, and the ≥ 99% launch-success measurement) is **M21/M22 work**, not this
milestone. This document is the harness and its first honest data point — not the
capacity certification.
