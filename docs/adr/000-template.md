# ADR-000 — Architecture Decision Record Template

This is the reusable template for CTFGenerator Architecture Decision Records
(Nygard-style). Copy it to `docs/adr/NNN-<slug>.md`, fill in every section, and
open the change for review. Keep entries concise, technical, and skimmable.

An ADR captures a single significant, hard-to-reverse decision and the context
that forced it — not routine implementation detail. One decision per file.

---

## How to number ADRs

- ADRs are numbered with a zero-padded three-digit prefix: `NNN-<kebab-slug>.md`
  (e.g. `007-postgres-job-queue.md`). This file, `000-template.md`, is the
  template and is never a real decision.
- The next number is `max(existing ADR numbers) + 1`. Numbers are allocated
  sequentially and are **never reused**, even if an ADR is later superseded or
  rejected.
- Numbers are immutable once merged. A file's number never changes; its `Status`
  changes instead (see below).
- One decision per file. If a decision splits, write two ADRs and cross-link them.

---

## When an ADR is REQUIRED

Per plan section 12, an ADR is **required** before merging any change to the
following architectural axes. These are the load-bearing boundaries of the
four-plane target architecture (Author Studio, Competition Control Plane,
Execution Plane, Evaluation Lab); changing them silently is prohibited.

| Axis | Why it needs an ADR | Current state (grounded in codebase) |
|---|---|---|
| **Database strategy** | Determines the persistence backbone and migration path. | No unifying persistence layer today: JSONL append log (`events.py`, `threading.Lock`), optional psycopg store (`postgres_events.py`), and ad-hoc per-bundle `variant.json` / report files. Target: PostgreSQL + SQLAlchemy 2.x + Alembic. |
| **Queue strategy** | Governs how execution jobs are dispatched to isolated workers. | No job queue exists; execution runs inline via `runtime_validator._run` (`subprocess` → `docker compose`). Target: PostgreSQL-backed job rows (`FOR UPDATE SKIP LOCKED`, leases, heartbeats, retries, idempotency keys, dead-letter); no Redis unless proven inadequate. |
| **Authentication** | Controls access to the control plane and admin/public surfaces. | Current auth is HTTP-basic-style admin user/password + a public scoreboard token in the stdlib `dashboard_server.py` (`serve` subcommand). Target: real authN/authZ across eight roles. |
| **Worker trust model** | The highest-priority security boundary: generated vulnerable code must never run on the control plane. | Generation and execution share one process today; bundle-shipped `solver.py` / `healthcheck.py` run on the host by default (`--sandbox` is opt-in). Target: isolated workers, rootless runtime, control plane never mounts the Docker socket. |
| **Artifact storage** | Defines where published challenge bundles live and how immutability is enforced. | Files written to a caller-named output dir (`generator.create_challenge`); no storage abstraction. Target: storage interface with local-FS (dev) + S3-compatible (prod); published artifacts immutable + content-addressed. |
| **Runtime isolation** | How challenge containers are built and confined. | `runtime_validator` shells to `docker compose build/up`; optional ephemeral read-only container for scripts. Target: rootless Docker/Podman + rootless BuildKit, resource + network enforcement. |
| **API versioning** | Contract stability for the REST API and persisted schemas. | Fragmented, write-only version stamps — `SPEC_VERSION`, `SCHEMA_VERSION`, `__version__` all `"1.0"`, with no negotiation, no consumer check, no migration (see codebase map §12). No REST API exists yet. |
| **Plugin model** | How challenge families are registered and how safety contracts are enforced. | `families.py` is a central import hub with a by-convention "templates must not import families" circular-import contract; validation contract is entangled with the registry. Target: explicit family SDK / registry boundary. |
| **Scoring model** | Determines competition scores and their reconstructability from persisted events. | Pluggable engines in `scoring_engine.py` (`static`, `dynamic_decay`, `time_decay` default, `ai_resistance`) over `scoreboard.py` folds; static AI-resistance scoring in `score.py`. | 

If a change touches any row above, land the ADR first (or in the same change) and
reference it in the PR. Changes that do not touch these axes do not need an ADR.

---

# Title: ADR-NNN — <short imperative decision phrase>

> One line: the decision, stated as a claim (e.g. "Use PostgreSQL job rows with
> `SKIP LOCKED` as the execution work queue").

## Status

One of: **Proposed** · **Accepted** · **Superseded**.

- **Proposed** — under review, not yet binding.
- **Accepted** — the decision in force.
- **Superseded** — replaced. State by which: `Superseded by ADR-NNN`. The
  superseding ADR should link back with `Supersedes ADR-NNN`.

(Optional: **Rejected** for a proposal that was considered and declined but is
worth recording so it is not re-litigated.)

## Date

`YYYY-MM-DD` — the date the status last changed (e.g. the date it was Accepted).

## Context

The forces at play: the problem, constraints, and relevant current-state facts.
Ground current-behavior claims in the codebase; label planned/target behavior
explicitly. State which of the required axes above this decision touches, and any
plan invariants it must uphold (e.g. "control plane never mounts the Docker
socket", "identical (generator version, spec, family version, seed) ⇒ identical
artifacts", "flags/session-tokens/provider-keys never logged").

## Decision

The change being made, stated plainly and actively ("We will…"). Specific enough
that a reader can tell whether a later change conforms to or violates it. Include
the concrete mechanism (interfaces, tables, boundaries) where it clarifies.

## Consequences

What becomes true after this decision. Split into three:

### Positive
- What this enables or simplifies.

### Negative
- Costs, new constraints, migration burden, or capabilities given up.

### Neutral
- Follow-on work, things now merely different, or facts future ADRs must respect.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| <option A> | <reason> |
| <option B> | <reason> |

Include the status-quo / "do nothing" option where relevant. Naming a rejected
alternative here prevents it from being silently reintroduced later.
