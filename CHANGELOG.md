# Changelog

All notable changes to CTFGenerator are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release CI enforces that every tagged version has an entry here (see
`.github/workflows/release.yml`).

## [Unreleased]

### Added — Milestone 18: Supported deployment + packaging

- `deploy/`: `Dockerfile.api`, `Dockerfile.worker`, a compose stack
  (`docker-compose.yml`), `entrypoint.sh`, and `verify-deploy.sh` (LEAD
  Docker-verification). `docs/HOSTING.md` documents the single supported
  topology: one control plane (no Docker socket), PostgreSQL, one or more
  isolated worker hosts, reverse-proxy TLS termination, and local-FS or
  S3-compatible artifact storage.

### Added — Milestone 17: Backup, restore, DR, upgrades

- `scripts/backup.sh` and `application/backup/` restore-verification harness
  (`verify.py`): `verify_restore(...)` runs read-only integrity checks over a
  *restored* control-plane database (schema, ledger/audit rows, scoreboard
  projection) and returns a `VerificationReport`. Scope is honest — it verifies
  restore **integrity**, not the RPO/RTO time/loss SLOs, which are a deployment
  cadence + recovery-drill concern (M20).

### Added — Milestone 16: Observability + incident operations

- `observability/`: structured JSON logging (`logging.py`) with a redaction
  policy (`secrets.py`) so flags, session tokens, and provider API keys are
  never logged.
- Durable, append-only, tamper-evident `audit_events` log (`domain/audit/`,
  migration `0014_audit_events`) for every privileged state change; admin/
  support-only `audit` router read (`AUDIT_READ`, SYSTEM scope), filterable and
  cursor-paginated.

### Added — Milestone 15: Evaluation Lab

- **Measured** agent evaluation as isolated jobs: `evaluations` router enqueues a
  PENDING `EvalRun` (never run on the control plane) that `workers/eval_runner.py`
  executes on a worker; `application/evaluation` records an allow-listed advisory
  projection (`solved`, `steps`, sanitized notes, adversarial `step_delta`).
  Migration `0013_eval_runs`. This measured signal is DISTINCT from the advisory
  `score.py` heuristic and from the `ai_resistance` competition-scoring engine.

### Added — Milestone 14: Challenge SDK + product depth

- `sdk/` package: an explicit family/plugin registration boundary
  (`plugins.py` registry, `adapter.py`, `scaffold.py`, `lint.py`), replacing the
  convention-only "templates must not import `families`" contract. Documented in
  `docs/CHALLENGE_SDK.md`.

### Added — Milestone 13: Supported CLI + MCP finalization

- `interfaces/cli/` command groups (`commands/`, `admin.py`, `client.py`,
  `platform.py`, `output.py`) call the shared `application/*` services rather than
  inlining orchestration — the CLI and API now share one application layer. MCP
  server retained as pure, workspace-sandboxed tools only (no Docker/subprocess/
  execution imports).

### Added — Milestone 12: Contestant portal

- `interfaces/web/contestant.py`: a contestant portal (published-challenge list,
  team-scoped instance access, flag submission, personal/team standing) distinct
  from the organizer surface. Private solvers/flags are never served; authorization
  reuses the API's per-competition scoping.

### Added — Milestone 11: Organizer web application

- `interfaces/web/` (`router.py`, `views.py`, `templates/`): a server-rendered
  organizer portal over the application services — competitions, teams,
  publications, and the operator instance-ops views. Every route is authz-scoped so
  a web response is never weaker than the API's 403; no external CDN. Integration
  test `tests/test_web_instances_ops_integration.py`.

### Added — Milestone 10: Authentication + authorization

- Local password auth + sessions with a `DbAuthenticator` swapped in behind the M9
  auth seam (PBKDF2 hashing, hash-only session tokens); `auth`/`users` routers.
- Per-competition role scoping + team tenancy closing the IDOR deferral, and a
  denied-action audit trail. `Permission` enum + `ROLE_PERMISSIONS` +
  `require_permission` enforced on every privileged route.
- OIDC authorization-code + PKCE federation (`oidc` router). Migrations
  `0011_auth`, `0012_oidc_login_transactions`. ADR-007 (authentication/sessions),
  ADR-008 (OIDC federation).

### Added — Milestone 9: Production API + application services

- FastAPI control plane at `/api/v1` (`interfaces/api/app.py`, `create_app`
  factory): `ctfgen.error` envelope, request-id / access-log / rate-limit
  middleware, cursor pagination, principal-scoped idempotency, row-locked ETag
  concurrency, and an `Authenticator` Protocol auth seam (later filled by M10).
- Routers for the contestant loop, organizer/ops surfaces (instances, builds,
  publications, jobs, system), and a worker HTTP transport whose auth plane is
  DISJOINT from human auth (`worker_id` only ever from the worker credential).
  CLI and API share the same `application/*` services.

### Added — Milestone 8: Hardened execution plane + instance lifecycle

- Quotas/scheduling + a runtime-backend Protocol + a secure `ContainerPolicy`; a
  `WorkerJobService` that authenticates and checks trust/drain/quarantine/scope
  before every queue verb (`worker_id` derived from the credential).
- Instance lifecycle: six aggregates + a 14-state machine + a desired-vs-observed
  reconciler (generation-gated, idempotent). Migrations `0009_scheduling_quotas`,
  `0010_instances`.
- Concrete `DockerRuntimeBackend`: `ContainerPolicy` → docker flags, a
  capability-detected **host-block** hard floor (iptables `INPUT DROP` + `DOCKER-USER`)
  that REFUSES launch if unenforceable, per-worker reap, fail-safe rule teardown;
  plus the `ctfgen-worker` executable. Isolation was proven by an INDEPENDENT escape
  agent. Rootless/userns/AppArmor/custom-seccomp are capability-gated on this host
  (`docs/security/runtime-isolation.md`).

### Added — Milestone 7: Worker orchestration + transactional submission processing

- PostgreSQL job queue (`FOR UPDATE SKIP LOCKED`, leases, retries, dead-letter,
  idempotency keys) with worker identity/trust (scoped short-lived credentials;
  `authenticate()` → `AuthenticatedWorker` + `require_scope`). Migrations
  `0006_jobs`, `0007_workers`.
- Transactional submission-processing service: a correct submission establishes
  `solved_at` **by construction** with at-most-one solve per (team, challenge,
  competition). Gap-safe transactional-outbox projector — migration
  `0008_score_projection` co-commits an outbox row via an AFTER-INSERT trigger and
  refolds the scoreboard from persisted score events (no sequence cursor). ADR-003
  (PostgreSQL-backed job queue).

### Added — Milestone 6 (Step 3): Competition aggregate (the canonical pattern)

- First persisted aggregate, establishing the reference pattern for every
  aggregate that follows (Users → Teams → Challenge* → Submission/Solve/…).
  Strict layering: domain `CompetitionConfig` → `CompetitionRepository` protocol
  → infrastructure repository → SQLAlchemy → PostgreSQL. **ORM objects never
  leave infrastructure**; repositories return frozen domain dataclasses.
- `infrastructure/database/models.py`: `Competition` ORM (surrogate uuid PK,
  `slug` ← domain `competition_id` UNIQUE, timestamptz times, `status`,
  `created_at`) with CHECK constraints encoding the domain invariants
  (`end_time > start_time`, freeze within `[start,end]`, non-empty name, status
  enum) and a `status` index.
- `infrastructure/database/mappers.py`: ORM↔domain conversion. `default_scoring`
  is normalized out to a future `competition_challenges` table, so the mapper
  **raises rather than silently dropping it**. Naive datetimes are coerced to
  UTC; round-trips preserve the instant.
- `infrastructure/database/competition_repository.py`:
  `SqlAlchemyCompetitionRepository` (add / get / list / update — no delete or
  archive). Operates within the caller's session (flush, never commit);
  duplicate slug surfaces `IntegrityError`; `update` of a missing row raises
  `LookupError` and never mutates id/slug/created_at/status.
- `CompetitionRepository` protocol gained `update`.
- Alembic migration `0002_competitions` (revises `0001_baseline`), reversible.
- `tests/test_competition_repository_integration.py`: 12 Docker-gated tests
  (round-trip, list, mutable-update + immutable-preservation, missing-update,
  duplicate slug, CHECK violation, rollback, UTC/timezone instant,
  default_scoring guard, migration up/down, detached-session safety).
- **Verified against real postgres:16 in Docker — all 15 DB integration tests
  pass** (12 new + 3 existing). Built by a 6-agent ultracode workflow (ORM,
  repo, migration, design review, tests, adversarial review) and lead-verified;
  the review + lead run resolved a constraint-name divergence between model and
  migration and an over-strict timezone assertion. Host stdlib suite unchanged
  (775 tests, 15 skip). Follow-up noted: force session `TimeZone=UTC` on the
  engine for fully deterministic timestamptz rendering.

### Added — Milestone 6 (Step 2): persistence infrastructure (no entities yet)

- New `ctf_generator.infrastructure.database` package: `DatabaseConfig`
  (DSN from `CTFGEN_DATABASE_URL` env, never a committed config), a declarative
  `Base` with an explicit constraint-naming convention (stable Alembic names),
  `Database` with a `session_scope()` unit-of-work (commit on success, rollback
  on any exception, always close), and a generic `SqlAlchemyRepository` base.
- **Alembic** operational: `alembic.ini` (no URL — env-sourced), `alembic/env.py`
  targeting `Base.metadata`, and an empty `0001_baseline` migration so
  `upgrade head` / `downgrade base` round-trip cleanly, anchoring the chain for
  the first aggregate.
- **PostgreSQL integration tests** (`tests/test_database_integration.py`):
  create an isolated throwaway database, verify engine connect, session-scope
  commit + rollback, and Alembic upgrade→downgrade. Docker-gated — they SKIP
  when the `db` extra or `CTFGEN_TEST_DATABASE_URL` is absent, so the stdlib-only
  host suite stays green (763 tests, 3 skipped). Wired into CI nightly with a
  `postgres:16` service.
- New `db` extra (`sqlalchemy>=2`, `alembic`, `psycopg`). Importing the database
  package pulls in SQLAlchemy, so it is confined to DB-backed paths — the domain
  layer and generator core never import it (enforced by the boundary test).
- **Verified against real postgres:16 in Docker**: all three integration tests
  pass. Adversarially reviewed; a lead Docker run caught a test-harness bug where
  `str(URL)` masked the DB password (fixed) and applied two robustness fixes
  (atomic `DROP … WITH (FORCE)`, admin engine pinned to the maintenance DB).
- No entities, no business logic, no change to the generator core or any
  existing behavior.

### Changed — Milestone 5 (increment 1): layered package skeleton + domain layer

- Introduced the target package layering
  (`domain` / `application` / `infrastructure` / `interfaces` / `workers`) with
  documented intent in each package `__init__`.
- Moved the pure challenge/competition/scoring/submission value types into
  `ctf_generator.domain.challenges.models` (the domain layer's first real
  tenant). `ctf_generator.models` is now a **compatibility shim** re-exporting
  them, so all ~40 existing import sites keep working unchanged and class
  identity is preserved.
- New CI guardrail `tests/test_architecture_boundaries.py` parses the AST of
  every `domain` module and fails if it imports framework/IO (`http`, `socket`,
  `subprocess`, `urllib`, `fastapi`, `sqlalchemy`, `psycopg`, `anthropic`,
  `openai`, `mcp`, …) or any infrastructure/effectful package — enforcing
  `docs/architecture/dependency-rules.md`.
- Remaining M5 work (later increments): move competition/scoring/families into
  their domain modules, split the 1389-line `cli.py` by command group under
  `interfaces/cli`, and extract shared application services once the API
  (M8/M10) gives them a second consumer (avoiding pass-through-only seams now).

### Added — Milestone 4: schema & family contracts

- New `ctf_generator.schema` module centralizes schema **identity, semantic
  versioning, compatibility, and migration**. Replaces three independent
  hard-coded `"1.0"` stamps that no consumer read (risk R-03) with real
  contracts: `check_compatible` rejects an incompatible major (or a
  newer-than-supported minor), and `migrate` upgrades older documents through a
  registered chain.
- Challenge specs are now **stamped and versioned** (`ctfgen.challenge-spec`
  1.1): `spec_to_dict` stamps, `spec_from_dict` migrates + rejects an unknown
  major (also at the MCP `build_spec`/`validate_spec` boundary). A pre-M4,
  unstamped `spec.json` still loads (assumed 1.0). New `load_spec_document`
  returns the parsed spec **and the verbatim original** so a caller can retain
  exactly what a user submitted (preserve-original-spec requirement).
- **Family capability contract**: `Family` gained a per-family `version`
  (independent of the generator version — closes the R-12 residual) plus a
  capability declaration (maintenance tier, supported modes/difficulties/
  architectures, isolation level, required ports, memory/cpu/build estimates,
  internet requirement, CVE-fidelity support) and a schema-stamped
  `metadata()`. Values grounded in each family's rendered compose. The build
  manifest now records `family_version`.
- Tests: `tests/test_schema_versioning.py` (semver, compatibility, migration,
  spec stamping/round-trip/reject-future-major, preserve-original, per-family
  metadata, manifest family_version). Golden fixtures regenerated; all families
  remain deterministic.
- Scope note: the execution-plane interface contracts the plan also lists under
  M4 (runtime-backend, artifact-store, job, and worker-result protocols) are
  deferred to land **with their consumers** in M7/M8, per the "no isolated
  framework code without a complete workflow" rule.

### Added — Milestone 3: filesystem & generation hardening

- New `ctf_generator.build` module is the single choke point that turns a
  family's rendered `{path: content}` mapping into an on-disk bundle safely.
  `generator.create_challenge` now routes through it, so **every** entry point
  (CLI `create`/`create-from-cve`, MCP tools) is hardened uniformly — not just
  the MCP workspace seam.
- **Path safety**: renderer paths are validated (no absolute, no `..`, no
  control/bidi-confusable chars, no reserved names, bounded length) and rejected
  case-insensitively if they would forge the build marker or a manifest;
  duplicate normalized paths (case-insensitive) are rejected.
- **Atomic publish**: builds are written to a temporary sibling directory and
  published with a move-aside + `os.replace`, so a failed or interrupted build
  can never replace or destroy a valid one; failed builds are retained under a
  unique `*.ctfgen-failed-*` directory for diagnosis.
- **Managed-deletion guard**: a `.ctfgen-build` ownership marker is written into
  every build; `--force` regeneration refuses to delete any non-empty directory
  that is not a CTFGenerator-managed build, a symlink, or a dangerous root
  (`/`, `$HOME`, cwd, shallow system paths).
- **Limits**: aggregate size (64 MiB) and file count (2000) are enforced.
- **Cryptographic manifests**: every build emits a `private/manifest.json`
  (SHA-256 of every file, seed, spec hash, generator/spec versions) and, when a
  public surface exists, a `public/manifest.json` containing **only** public
  file hashes — the seed (which deterministically derives the flag) and spec
  hash are never placed in a player-facing artifact.
- Adversarial test suite `tests/test_build_hardening.py` covering traversal,
  absolute paths, symlink escape, dangerous force targets, unmarked-directory
  deletion, duplicate/case-collision paths, oversized/over-count output,
  interrupted builds, partial-publish restore, and Unicode-confusable paths.
  Golden baseline fixtures regenerated to include the manifests; all 8 families
  remain deterministic. An adversarial security review of the module was run and
  its findings (incl. a seed-in-public-manifest leak) fixed before landing.

### Added — productization foundation (Milestones 0–2, security & ADRs)

- **Baseline golden fixtures** for all 8 challenge families across 2 seeds
  (`tests/fixtures/baseline/`) plus a regression test
  (`tests/test_baseline_fixtures.py`) that rebuilds each challenge in-process and
  asserts byte-for-byte agreement — enforcing the deterministic-rebuild invariant
  and the no-private-content-in-public invariant. Determinism confirmed for every
  family.
- **Current-system documentation** (Milestone 0): `docs/current-system.md`,
  `docs/current-cli.md`, `docs/current-schemas.md`, `docs/architecture/current.md`,
  `docs/risk-register.md`, and an ADR template `docs/adr/000-template.md`.
- **Product scope documentation** (Milestone 1): `docs/PRODUCT.md`,
  `docs/REQUIREMENTS.md`, `docs/SUPPORT_MATRIX.md`, `docs/RELEASE_CRITERIA.md`,
  `docs/MATURITY.md`.
- **Security workstream** (plan §7): `SECURITY.md` and
  `docs/security/{threat-model,runtime-isolation,secret-management,incident-response,responsible-disclosure}.md`.
- **Architecture Decision Records** for the load-bearing decisions:
  control/execution-plane boundary (ADR-001), PostgreSQL persistence (ADR-002),
  PostgreSQL-backed job queue (ADR-003), rootless container runtime (ADR-004),
  and package dependency boundaries (ADR-005), plus `docs/architecture/dependency-rules.md`.
- **CI foundation** (Milestone 2): `.github/workflows/{pr,nightly,release}.yml`
  with required gates (unit tests on 3.11/3.12, compileall, package build,
  deterministic-generation golden check, secret scan) and informational gates
  (ruff lint/format, mypy, bandit, pip-audit) that are promoted to required as
  the code is cleaned during the M5 refactor. Release builds produce checksums
  and a CycloneDX SBOM.
- Tooling config for ruff, mypy, and pytest in `pyproject.toml`, and a `ci`
  optional-dependency group.

### Notes

- No changes to the generator, families, or any runtime behavior in this
  foundation increment — the existing test suite remains green (712 tests).

## [0.1.0]

- Initial deterministic CTF generator/validator with 8 challenge families,
  static + Docker runtime validation, scoring, scenario engine, agent-eval
  harness, CVE sourcing, stdlib dashboard, and MCP server. See `README.md` and
  `docs/ARCHITECTURE.md` for the as-built system.
