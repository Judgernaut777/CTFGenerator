# Title: ADR-002 — PostgreSQL is the durable source of truth

> One line: Use PostgreSQL (SQLAlchemy 2.x + Alembic) as the authoritative,
> durable persistence tier, replacing the in-memory / JSONL event store as the
> system of record.

## Status

**Accepted**

## Date

`2026-07-11`

## Context

This decision touches the **Database strategy** axis (000-template) — the row
that governs the persistence backbone and its migration path.

Current state (grounded in the codebase map):

- **No durable, unifying persistence tier exists.** The competition event log
  (`events.py`) ships two `EventStore` implementations: `InMemoryEventStore`
  (state lost on restart) and `JsonlEventStore` (one JSON object per line,
  `threading.Lock`-guarded `seq` assignment). Both assign a strictly monotonic
  `seq` from 1 and reload via `Event(**data)`.
- The `serve` subcommand wires `JsonlEventStore` only when `--events-file` is
  given, otherwise `InMemoryEventStore` — so the default live dashboard holds
  all competition state in process memory and loses it on restart.
- An alternate durable store already exists as a seed: **`postgres_events.py`**,
  a psycopg-backed `EventStore` (lazy `psycopg` import; stdlib-only at import
  time; DSN is the only real socket use in the module).
- Remaining state is scattered and file-bound: per-bundle `private/variant.json`
  and JSON report envelopes (`report_writer.py`) read ad hoc via `pathlib`;
  competition/scoreboard/challenge inputs are loose JSON fixtures loaded by
  `scoreboard.py`. There is no repository abstraction unifying them (codebase
  map smell #3).
- Schema versioning is fragmented and write-only: `SPEC_VERSION`,
  `SCHEMA_VERSION`, and `__version__` are all `"1.0"` with no consumer check and
  no migration logic (codebase map §12). Neither the JSONL event log nor any
  fixture carries a version field.

Forces:

- The plan's V1 deployment model names **PostgreSQL persistence** as the single
  supported path, and the tech baseline names **SQLAlchemy 2.x + Alembic**.
- Operating targets require durability the current stores cannot meet: **RPO 5
  min / RTO 30 min**, and **scoreboards reconstructable from persisted score
  events**. An in-memory store has an effective RPO of "everything since the
  last restart."
- Invariant: *a correct submission creates at most one solve per
  (team, challenge, competition)* — a uniqueness guarantee that a lock-serialized
  append log enforces only weakly and that belongs in a transactional store with
  a real unique constraint.

Invariants this decision must uphold: control-plane persistence must never
require the Docker socket or execute generated code; flags, session tokens, and
provider keys are **never** persisted in loggable columns.

## Decision

We will make **PostgreSQL the durable source of truth** for all control-plane
state, accessed through **SQLAlchemy 2.x** with schema migrations managed by
**Alembic**. `postgres_events.py` is the seed for the event-store adapter and
its schema.

Concretely (target, staged per release plan v0.3-alpha "persistent control
plane"):

- The authoritative persistence tier is a PostgreSQL database. The relational
  schema is owned by Alembic migrations; ad-hoc table creation is prohibited.
- The **score/solve event log is the durable ledger of record.** The
  `EventStore` protocol (`append` / `since` / `all` / `latest_seq`) is
  reimplemented over PostgreSQL, preserving the monotonic `seq` contract via a
  DB sequence / transactional assignment rather than an in-process
  `threading.Lock`. The at-most-one-solve invariant is backed by a database
  unique constraint on `(team, challenge, competition)`.
- **Scoreboards remain projections, not stored truth.** They are recomputed from
  persisted score events by the existing pure folds in `scoreboard.py`
  (`compute_scoreboard`, `compute_challenge_values`); any cached scoreboard is a
  rebuildable materialization, never authoritative. This keeps the "scoreboards
  reconstructable from persisted score events" invariant intact.
- `InMemoryEventStore` is retained for tests and offline/pure use; `JsonlEventStore`
  is demoted from a supported persistence option to a dev/export convenience. The
  authoritative store for a real competition is PostgreSQL.

This ADR covers only the **persistence backbone**. The PostgreSQL-backed *job
queue* (execution dispatch, `FOR UPDATE SKIP LOCKED`, leases, heartbeats) is the
Queue-strategy axis and is a separate ADR; it shares the same database but is a
distinct decision.

## Consequences

### Positive

- Durable state across restarts: meets the RPO 5 min / RTO 30 min targets via
  standard PostgreSQL backup/restore, which the in-memory and JSONL stores
  cannot.
- Transactional integrity: the at-most-one-solve invariant becomes a DB
  constraint instead of an in-process lock, and concurrent writers are serialized
  by the database rather than a single `threading.Lock`.
- A single migration path (Alembic) replaces the fragmented, write-only
  `SPEC_VERSION` / `SCHEMA_VERSION` stamps for control-plane tables, giving
  schema evolution a real upgrade mechanism.
- Establishes the repository/persistence seam the application layer can depend
  on (codebase map smell #3, target package `infrastructure/` implementing
  domain-owned protocols).

### Negative

- Adds a required infrastructure dependency (a running PostgreSQL instance +
  `psycopg`) to any non-trivial deployment; the zero-dependency stdlib-only
  posture of the current core no longer holds for the control plane.
- Migration burden: existing JSONL event logs must be imported into the new
  schema, and the loose JSON fixtures (`scoreboard.py` loaders) need mapping to
  tables or a documented import path.
- Operational surface grows: connection management, pooling, migration
  ordering, and backup/restore drills become part of running the platform.

### Neutral

- The `EventStore` protocol shape is unchanged; PostgreSQL is a new
  implementation behind it. Callers of `append`/`since`/`all`/`latest_seq` are
  unaffected.
- Scoreboard computation code (`scoreboard.py`, `scoring_engine.py`) is unchanged
  — it continues to fold over events; only the event *source* becomes durable.
- Future ADRs must respect that the score-event log, not any scoreboard table,
  is authoritative, and that Alembic owns the schema.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| **SQLite** as the durable store | Rejected for concurrency: the operating targets (25 concurrent teams, sub-500 ms submissions, sub-3 s scoreboard updates) demand multiple concurrent writers with row-level locking and a real work-queue path (`FOR UPDATE SKIP LOCKED`). SQLite's single-writer model and coarse locking make it a poor fit for the control plane, and it diverges from the plan's single supported PostgreSQL deployment path. |
| **Keep JSONL** (`JsonlEventStore`) as the store of record | Rejected: an append-only file guarded by a single `threading.Lock` gives no transactional integrity, no unique-constraint enforcement of the at-most-one-solve invariant, no query/index support, and no migration path. It stays as a dev/export convenience, not authoritative. |
| **Keep in-memory only** (`InMemoryEventStore`, status quo) | Rejected: state is lost on every restart (effective RPO = uptime), directly violating the RPO 5 min / RTO 30 min targets and the durability the platform requires. Retained for tests and offline use only. |
| Store scoreboards as authoritative rows | Rejected: violates the invariant that scoreboards are reconstructable projections of persisted score events. Scoreboards stay derived (rebuildable) from the event ledger. |
