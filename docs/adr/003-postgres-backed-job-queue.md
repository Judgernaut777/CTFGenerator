# Title: ADR-003 — Use a PostgreSQL-backed job queue for execution work

> One line: Dispatch Execution Plane jobs through explicit PostgreSQL job rows
> claimed with `FOR UPDATE SKIP LOCKED` (leases, heartbeats, retries, idempotency
> keys, dead-letter) rather than adding Redis/Celery or a cloud queue in V1.

## Status

**Accepted**

## Date

`2026-07-11`

## Context

Axis touched (per `000-template.md`): **Queue strategy** (and, by dependency, it
assumes the **Database strategy** ADR's choice of PostgreSQL as the persistence
backbone).

**Current state (grounded in the codebase map).** There is no job queue. Execution
runs **inline, in-process**: `runtime_validator._run` calls `subprocess.run` →
`docker compose build/up`, polls `tests/healthcheck.py`, runs `private/solver.py`,
then `docker compose down`. Every impure caller —`replay_validator`,
`sibling_validator`, `scenario_runtime`, `agent_eval` — independently reaches into
`runtime_validator`'s private helpers (`_run`, `_record`, `_wait_for_health`) to do
the same thing. There is no dispatch layer, no retry, no lease, and no record that a
job ran. Bundle-shipped code executes **on the host by default** (`--sandbox` is
opt-in), and generation and execution share one process.

Persistence today is fragmented and has no unifying abstraction: an append-only
JSONL log guarded by a bare `threading.Lock` (`events.py`), an optional
psycopg-backed store (`postgres_events.py`, lazy import), and ad-hoc per-bundle
`variant.json` / report files read via `pathlib`. Notably, `postgres_events.py`
already establishes that PostgreSQL via psycopg is an accepted, isolated
optional-dependency edge in this repo.

**Forces.**
- The target architecture splits execution onto **isolated worker hosts** (Execution
  Plane). Dispatch must cross a process/host boundary, which the inline model cannot
  do.
- **Highest-priority boundary:** generated vulnerable workloads must NEVER execute on
  the control plane, and the **control plane never mounts the Docker socket**. The
  queue is the hand-off point across that boundary, so its transport must not itself
  require the control plane to reach into execution.
- **V1 goal:** deliver ONE secure, persistent, fully tested end-to-end workflow before
  expanding surface area. Minimizing new operational components is therefore a
  first-class constraint.
- Initial operating targets are modest (25 concurrent teams, 20 active challenges,
  ≥99% instance launch success). This is not a high-throughput queueing problem; it is
  a **reliability and auditability** problem.
- The plan's tech baseline already mandates PostgreSQL + SQLAlchemy 2.x + Alembic for
  persistence, and explicitly states the work queue should be **PostgreSQL-backed job
  rows … (NO Redis unless proven inadequate)**.

**Invariants this decision must uphold.**
- Control plane never mounts the Docker socket; the queue must not require it to.
- Job results flow back through **explicit job-result contracts**; workers never modify
  competition-domain state directly (target package rule).
- `flags` / session-tokens / provider-keys are NEVER logged, and by extension must not
  be written into job payloads or dead-letter rows in cleartext where they would leak.
- Every privileged state change is auditable — persisted job rows contribute to that
  audit trail.

## Decision

We will implement the Execution Plane work queue as **explicit job rows in
PostgreSQL**, dispatched with transactional claiming, and we will NOT introduce
Redis, Celery, or a cloud queue for V1.

Concretely (all **planned/target**; none of this exists in the codebase today):

- **Job table.** Each unit of execution work (image build, instance launch, health
  check, runtime validation, intended-solver run) is a row with at least: `id`,
  `type`, `status` (`queued` → `claimed` → `running` → `succeeded` / `failed` /
  `dead`), `payload`, `idempotency_key`, `attempts`, `max_attempts`, `lease_expires_at`,
  `heartbeat_at`, `available_at`, timestamps, and a `result` / `error` slot.
- **Transactional claiming.** Workers claim work with
  `SELECT … FOR UPDATE SKIP LOCKED LIMIT 1` inside a transaction, flipping the row to
  `claimed`/`running` and setting a lease. `SKIP LOCKED` lets multiple isolated workers
  poll the same table concurrently without blocking each other or double-dispatching a
  row.
- **Leases + heartbeats.** A claimed row carries a `lease_expires_at`; the worker
  periodically bumps `heartbeat_at`/extends the lease while running. A sweeper requeues
  rows whose lease expired without completion (worker crash / host loss), making the
  queue self-healing.
- **Retries.** On failure a row increments `attempts` and, if `attempts < max_attempts`,
  is re-made-available (with backoff via `available_at`); otherwise it moves to
  dead-letter.
- **Idempotency keys.** A per-job `idempotency_key` ensures a re-submitted or
  retried job cannot produce duplicate side effects — aligning with the invariant that a
  correct submission creates AT MOST one solve per `(team, challenge, competition)` and
  with deterministic-rebuild guarantees.
- **Dead-letter.** Terminally failed rows land in a `dead` state (or dedicated table)
  for operator inspection rather than silent loss; audit and reconciliation read from it.
- **Direction of control.** The control plane only **writes** job rows and **reads**
  results via the job-result contract; **workers poll** PostgreSQL. The control plane
  never connects to workers and never mounts a Docker socket, preserving the
  highest-priority boundary.

This targets the plan's **v0.2-alpha (isolated execution)** stage: worker protocol,
job system, reconciliation.

## Consequences

### Positive
- **One fewer piece of infrastructure.** No Redis broker, no Celery worker/result
  backend, no separate broker to secure, back up, monitor, or version. The V1 deployment
  model already requires PostgreSQL, so the queue rides the backbone we already run.
- **Transactional correctness for free.** Claiming, state transition, and result write
  can share a DB transaction; there is no broker/DB dual-write to keep consistent.
- **Durable and auditable by construction.** Every job, attempt, lease, and dead-letter
  is a persisted row — directly serving the "every privileged state change auditable"
  invariant and RPO/RTO recovery targets (queue state is in the same backup as domain
  state).
- **Clean cross-boundary hand-off.** A poll-based table is a natural seam for isolated
  workers and keeps the control plane from ever reaching toward Docker.
- **Consolidates today's smear.** Replaces the five modules that independently call
  `runtime_validator._run` with a single dispatch contract.

### Negative
- **Not built for high throughput.** Row-polling + `SKIP LOCKED` is fine at the V1 scale
  (25 teams / 20 challenges) but would show polling overhead and table churn at
  large fan-out; this is an accepted V1 trade, revisited only if measured inadequate.
- **We implement queue semantics ourselves.** Leases, backoff, heartbeats, sweeper, and
  dead-letter are our code and our tests, not a batteries-included framework. More
  first-party surface to get right.
- **Polling latency + table maintenance.** Requires tuned poll intervals, indexes on
  `(status, available_at)`, and periodic vacuum/archival of terminal rows.
- **Payload hygiene burden.** Because payloads/results are persisted, we must ensure
  flags/tokens/provider-keys never land in job rows or dead-letter in the clear.

### Neutral
- The job schema is owned by the **infrastructure** layer and exposed to the
  **application** layer via a job/queue interface; workers consume it via the
  job-result contract and never touch competition-domain tables directly.
- Migrations for the job tables go through Alembic alongside the rest of the PG domain
  model (v0.3-alpha).
- This ADR does not decide the runtime isolation mechanism (rootless Docker/Podman +
  BuildKit) — that is a separate axis/ADR. It decides only *how work is dispatched*.
- **Revisit trigger:** if PostgreSQL job rows prove inadequate under real load
  (measured contention, latency, or throughput ceilings), a follow-on ADR may introduce
  Redis or another broker. Until such evidence exists, reintroducing a broker is
  out of scope.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| **Status quo — inline execution** (`runtime_validator._run` in-process) | Cannot cross to isolated workers; no durability, retry, lease, or audit; violates the control-plane/execution boundary that V1 requires. |
| **Redis + RQ** | Adds a second stateful service to run, secure, and back up; introduces broker/DB dual-write for job+result consistency; buys throughput we do not need at V1 scale. Rejected to minimize operational surface. |
| **Celery** (with Redis/RabbitMQ broker) | Heaviest option: broker + result backend + worker framework, its own config/version surface and failure modes; more than the modest V1 workload warrants. Rejected for the same operational-surface reason. |
| **Managed cloud queue** (e.g. SQS-style) | Contradicts the single supported V1 deployment (self-hosted, single control plane); adds a cloud dependency and egress/credential surface; ties recovery to an external service outside our PG backup/RPO story. |
| **Postgres `LISTEN/NOTIFY` only** (no explicit rows) | Notification is fire-and-forget: no durability across worker downtime, no lease/retry/dead-letter, no audit trail. Could later *augment* row-polling to cut latency, but cannot replace durable rows. |
