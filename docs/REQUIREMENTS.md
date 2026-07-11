# CTFGenerator V1 Requirements

**Milestone 1 deliverable.** This document enumerates V1 functional requirements grouped by
plane/area, each with a stable ID so later tasks can map to them, plus non-functional operating
targets and the product invariants expressed as testable requirements.

Scope note: CTFGenerator V1 is a **self-hosted platform** for generating, validating, deploying, and
operating reproducible cybersecurity challenges. AI-resistance evaluation is a differentiating
subsystem, not the product definition. Everything here targets the single supported V1 deployment
model (one control plane, PostgreSQL, isolated workers, containerized workloads, reverse proxy + TLS,
local-FS or S3 artifact storage, web UI + REST API + CLI).

## Conventions

- **Current** = behavior that exists today (grounded in the codebase map). **Target/Planned** =
  behavior to be built; explicitly labeled.
- ID prefixes: `REQ-GEN` (Author Studio), `REQ-COMP` (Competition Control Plane), `REQ-EXEC`
  (Execution Plane), `REQ-EVAL` (Evaluation Lab), `REQ-PLAT` (cross-cutting platform:
  persistence, auth, interfaces, deployment), `REQ-NFR` (non-functional), `REQ-INV` (invariants).
- **Delivered by** references the release stage/milestone that ships the requirement:
  v0.1-alpha (reliable generator), v0.2-alpha (isolated execution), v0.3-alpha (persistent control
  plane), v0.4-beta (complete workflow), v0.5-beta (quality + evaluation), v1.0 (hardening/GA).
- The four planes map to the four target subsystems: Author Studio, Competition Control Plane,
  Execution Plane, Evaluation Lab.

---

## 1. Author Studio (`REQ-GEN-*`)

Spec authoring, family/CVE/seed selection, generation, validation, review, approval, publication,
version history. Most generation/validation machinery exists today at the CLI/MCP layer; the Studio
workflow (review/approval/publication/history) is the planned wrapper over it.

| ID | Requirement | State | Delivered by |
|---|---|---|---|
| REQ-GEN-001 | Deterministically render a self-contained challenge bundle from `(family, seed, difficulty, title, mode, cve_refs)`. Current: `ctfgen create` / `generator.create_challenge`, writing a family-defined `Family.required_files` set plus `challenge.yaml`. | Current | v0.1-alpha |
| REQ-GEN-002 | Produce a structured, validated `ChallengeSpec` before rendering code, via deterministic backend and optional LLM backends. Current: `ctfgen spec` (`deterministic\|anthropic\|openai`); LLM emits only `_LLM_SCHEMA` pedagogical fields (title, learning_objectives, checkpoints). | Current | v0.1-alpha |
| REQ-GEN-003 | Enforce the LLM/human boundary: authors/models supply only pedagogical metadata; `ai_resistance`, `dynamic_variation`, category, flags, routes, and exploit code are set deterministically server-side. Current: `_LLM_SCHEMA`, `mcp_server` `design_challenge` prompt, `AIResistance` never LLM-set. | Current | v0.1-alpha |
| REQ-GEN-004 | Ground a challenge in a real CVE (snapshot or NVD source): search/show/categories, then generate a themed spec. Current: `ctfgen cve-search`/`cve-show`/`cve-categories`/`create-from-cve`; `cve_blueprint.spec_from_cve` with `content_hash` stamped into `cve_content_hash`. | Current | v0.1-alpha |
| REQ-GEN-005 | Statically validate a bundle: required files, compose markers, YAML markers (`meta:`, `ai_resistance:`, `dynamic_variation:`, `checkpoints:`), scenario sanity. Current: `ctfgen validate` / `validate_challenge`. | Current | v0.1-alpha |
| REQ-GEN-006 | Validate spec structure independent of rendering (title, family membership, difficulty, seed, ≥1 objective, `checkpoints ≥ min_solver_steps`, CVE-ref format, mode ∈ family.modes). Current: `spec_generator.validate_spec`. | Current | v0.1-alpha |
| REQ-GEN-007 | Score a bundle on AI-resistance dimensions with weighted total, band, and integrity gates. Current: `ctfgen score` / `score.py` (5–6 dimensions, bands strong/good/moderate/weak, flag-leak/embedded-flag gates force `weak`). | Current | v0.1-alpha / v0.5-beta |
| REQ-GEN-008 | Generate sibling variants and verify they differ meaningfully (changed tokens), optionally with runtime + cross-replay. Current: `ctfgen validate-siblings` / `sibling_validator`. | Current | v0.1-alpha |
| REQ-GEN-009 | Enumerate producible families and per-family metadata. Current: `ctfgen list-families`, MCP `list_families`/`family_info`/`spec_schema`. | Current | v0.1-alpha |
| REQ-GEN-010 | Persist every generation/validation/score run as a versioned JSON report envelope (`schema_version`, `generator_version`, command, subject, status, result) and index them. Current: `report_writer.build_report`/`write_report`, `ctfgen report-index`. | Current | v0.1-alpha |
| REQ-GEN-011 | Provide a documented Family SDK / plugin interface so families register without editing a central hub. Current: templates expose a module interface but `families.py` imports every template (manual circular-import contract). Target: explicit registry/plugin boundary. | Target | v0.1-alpha |
| REQ-GEN-012 | Version the spec/bundle schema with an enforced, consumer-read version and migration path. Current: three write-only `"1.0"` constants (`SPEC_VERSION`, `SCHEMA_VERSION`, `__version__`); `spec.json`/`variant.json`/events carry no version; no consumer validates version. Target: real schema versioning. | Target | v0.1-alpha |
| REQ-GEN-013 | Studio review/approval workflow: an author-submitted challenge is reviewable, approved by a Reviewer role, and only then publishable. Target: no review/approval state exists today. | Target | v0.4-beta |
| REQ-GEN-014 | Publish an approved challenge as an immutable, content-addressed artifact version with retained version history. Target: current output is a plain directory tree with no immutability/versioning guarantee. | Target | v0.3-alpha / v0.4-beta |
| REQ-GEN-015 | Quality gates block publication of a challenge that fails static, runtime, sibling, or score thresholds. Current: individual gates exist as CLI exit codes; no publication gate wiring. Target: composed publication gate. | Target | v0.1-alpha / v0.5-beta |

---

## 2. Competition Control Plane (`REQ-COMP-*`)

Auth, competitions, teams, publication, submissions, scoring, scoreboards, reports, audit. **Never
executes generated challenge code; never has Docker socket access.** Scoring math and the dashboard
exist today at fixture/stdlib level; the persistent, authenticated, multi-role control plane is the
planned build.

| ID | Requirement | State | Delivered by |
|---|---|---|---|
| REQ-COMP-001 | Compute a competition scoreboard from persisted score events using pluggable scoring engines. Current: `ctfgen scoreboard` / `scoreboard.compute_scoreboard`; engines `static`/`dynamic_decay`/`time_decay` (default)/`ai_resistance`. | Current (fixtures) | v0.3-alpha |
| REQ-COMP-002 | Support retroactive dynamic decay, single first-blood per challenge, deterministic ordering, and frozen snapshots (`as-of`/`freeze_time`). Current: `compute_scoreboard`, `CompetitionConfig.freeze_time`. | Current | v0.3-alpha |
| REQ-COMP-003 | Validate competition/challenge scoring config (time ordering, value bounds, decay function ∈ static/linear/logarithmic, bonus bounds). Current: `scoring_engine.validate_competition_config`. | Current | v0.3-alpha |
| REQ-COMP-004 | Record competition activity as an append-only, monotonic-`seq`, JSONL-or-Postgres event log. Current: `events.py` (`InMemoryEventStore`/`JsonlEventStore`, lock-serialized seq), optional `postgres_events.py`. | Current | v0.3-alpha |
| REQ-COMP-005 | Serve a live admin dashboard + public scoreboard/feed with session login and rotating public token. Current: `ctfgen serve` / `dashboard_server.py` (stdlib `ThreadingHTTPServer`, inline UI, no CDN). | Current | v0.4-beta |
| REQ-COMP-006 | Scan generated challenges into a scoring catalog consumable by the control plane. Current: `ctfgen catalog` / `serve --challenges-dir`. | Current | v0.3-alpha |
| REQ-COMP-007 | Provide the eight user roles (Platform owner, Operator, Event administrator, Challenge author, Reviewer, Team captain, Contestant, Observer) with role-scoped authorization. Current: only a single admin user/password + a public token exist. Target: full RBAC. | Target | v0.3-alpha |
| REQ-COMP-008 | Persist the full competition domain model (competitions, teams, memberships, challenge publications, submissions, score events, audit) in PostgreSQL with migrations. Current: no relational domain model; state is JSONL/files. Target: PG + SQLAlchemy 2.x + Alembic. | Target | v0.3-alpha |
| REQ-COMP-009 | Accept contestant flag submissions, validate against the per-instance flag, and record at most one solve per `(team, challenge, competition)`. Current: submission/solve dataclasses (`Submission`, `SolveEvent`, `solve_event_from_submission`) exist but no live submission endpoint. Target: submission API. | Target | v0.3-alpha |
| REQ-COMP-010 | Enforce competition lifecycle windows (start/end/scoring-start/freeze) on submission acceptance and scoreboard visibility. Current: config fields exist and validate; not enforced against a live submission path. | Target | v0.3-alpha |
| REQ-COMP-011 | Contestant portal (challenge list, instance access, submission, personal/team standing) distinct from the admin surface. Target: only combined admin dashboard exists today. | Target | v0.4-beta |
| REQ-COMP-012 | Live operations view for administrators (instance status, launch health, submission stream). Target. | Target | v0.4-beta |
| REQ-COMP-013 | Every privileged/admin state change (score override, publication, competition config change) is recorded to an immutable audit trail with an explicit reason for admin score changes. Target: no audit trail today. | Target | v0.3-alpha / v0.4-beta |
| REQ-COMP-014 | Post-event reports (final standings, solve timelines, per-challenge stats) reconstructable from persisted score events. Target. | Target | v0.4-beta |
| REQ-COMP-015 | The control plane process/deployment holds no Docker socket, no BuildKit access, and never imports execution modules. Current: `mcp_server` already documents this boundary; the `serve`/dashboard path is stdlib-only. Target: enforce as a deployment invariant (see REQ-INV-010). | Current (partial) / Target | v0.2-alpha / v0.3-alpha |

---

## 3. Execution Plane (`REQ-EXEC-*`)

Image builds, instance launch, health checks, runtime validation, intended solver, network
isolation, resource enforcement, log collection, expiration, cleanup — on **isolated workers**. All
execution logic exists today but runs inline (host, by default) from validators; the isolated
worker/job boundary is the planned build.

| ID | Requirement | State | Delivered by |
|---|---|---|---|
| REQ-EXEC-001 | Build, launch, health-check, run the intended solver against, and tear down a bundle. Current: `ctfgen validate-runtime` / `runtime_validator` (`docker compose build/up`, poll `tests/healthcheck.py`, run `private/solver.py`, `down`). | Current | v0.2-alpha |
| REQ-EXEC-002 | Optionally run bundle-shipped scripts inside an ephemeral read-only container instead of on the host. Current: `validate-runtime --sandbox` (ephemeral read-only `python:3.11-slim`). Note: non-sandbox default executes bundle code on the host with caller privileges (a CLI-only, warned operation). | Current | v0.2-alpha |
| REQ-EXEC-003 | Prove instance uniqueness/non-transfer by replaying one instance's solver against a sibling. Current: `ctfgen replay` / `replay_validator.cross_replay`. | Current | v0.2-alpha |
| REQ-EXEC-004 | Support non-HTTP/non-8080 families declaring their own invocation via `private/runtime.json`. Current: `runtime_validator._load_runtime_manifest`. | Current | v0.2-alpha |
| REQ-EXEC-005 | Run the live-adversarial scenario timeline against a running instance. Current: `ctfgen run-scenario --runtime` / `scenario_runtime.run_live_scenario`; offline deterministic engine (`scenario.py`) by default. | Current | v0.2-alpha |
| REQ-EXEC-006 | Emit compose topology with container hardening (`no-new-privileges`, `cap_drop: [ALL]`, `mem_limit`, `pids_limit`, internal-only networks, flag via `${CTFGEN_FLAG}`). Current: rendered `docker-compose.yml`; validator checks markers. | Current | v0.2-alpha |
| REQ-EXEC-007 | Provide a defined worker↔control-plane job protocol: control plane enqueues execution jobs; isolated workers claim, run, and report results via an explicit job-result contract; workers never mutate competition-domain state directly. Current: `runtime_validator`/`replay_validator`/`sibling_validator`/`scenario_runtime`/`agent_eval` each reach into `runtime_validator` private helpers inline — no worker boundary. Target: worker protocol. | Target | v0.2-alpha |
| REQ-EXEC-008 | Back the job queue with PostgreSQL job rows (`FOR UPDATE SKIP LOCKED`, leases, heartbeats, retries, idempotency keys, dead-letter). Target: no job system today. No Redis unless proven inadequate. | Target | v0.2-alpha |
| REQ-EXEC-009 | Use rootless Docker/Podman + rootless BuildKit on isolated worker hosts. Current: `runtime_validator` shells `docker compose` on host. Target: rootless runtime on workers. | Target | v0.2-alpha |
| REQ-EXEC-010 | Enforce per-instance network isolation, resource limits, and per-team instance separation at launch. Current: compose-level hardening only. Target: enforced isolation + team-scoped instances. | Target | v0.2-alpha |
| REQ-EXEC-011 | Manage instance lifecycle: launch → health → expiration → cleanup, with reconciliation of orphaned/failed instances. Current: single-shot validate-runtime up/down. Target: lifecycle + reconciliation loop. | Target | v0.2-alpha |
| REQ-EXEC-012 | Collect and persist per-instance logs for operators without exposing private solver/flag material to contestants. Current: `report.logs` printed to stdout. Target: durable log collection. | Target | v0.2-alpha |

---

## 4. Evaluation Lab (`REQ-EVAL-*`)

Scripted/adaptive agent baselines, cross-seed/cross-family generalization, human benchmark
ingestion, difficulty analysis, quality reports. Core harness exists today; the lab
(benchmarks, aggregation, difficulty analysis) is planned.

| ID | Requirement | State | Delivered by |
|---|---|---|---|
| REQ-EVAL-001 | Run an AI-agent evaluation against a live instance, reporting solved/steps/notes. Current: `ctfgen eval-agent` / `agent_eval.run_agent_eval` (lazy anthropic/openai, provider-agnostic tools). | Current | v0.5-beta |
| REQ-EVAL-002 | Run an adversarial-delta evaluation (same eval with scenario engine off then on) reporting `success_dropped`/`step_delta`. Current: `eval-agent --adversarial` / `agent_eval.run_adversarial_delta`. | Current | v0.5-beta |
| REQ-EVAL-003 | Blend static AI-resistance score with agent-eval outcomes. Current: `score.score_with_agent_eval` (`static`, `agent_eval`, `blended_score`). | Current | v0.5-beta |
| REQ-EVAL-004 | Measure cross-seed / cross-family generalization (does a solver/technique transfer across siblings and families). Current: cross-replay proves non-transfer for one pair; no aggregate generalization report. Target. | Target | v0.5-beta |
| REQ-EVAL-005 | Ingest human benchmark results (solve times/success) to calibrate difficulty. Target: no human-benchmark ingestion today. | Target | v0.5-beta |
| REQ-EVAL-006 | Produce per-challenge difficulty analysis and quality reports aggregating score, agent-eval, sibling, and human data. Target. | Target | v0.5-beta |

---

## 5. Cross-cutting Platform (`REQ-PLAT-*`)

Persistence, auth, interfaces, deployment, and the refactor destination structure.

| ID | Requirement | State | Delivered by |
|---|---|---|---|
| REQ-PLAT-001 | Refactor into `src/ctf_generator/{domain,application,infrastructure,interfaces,workers}` with strict dependency rules: domain imports no http/docker/postgres/mcp/LLM/framework code; application depends only on domain interfaces; infrastructure implements them; interfaces call application services. Current: flat ~35-module package; `cli.py` is a 1389-line god-module inlining orchestration. Target. | Target | v0.1-alpha → v0.3-alpha |
| REQ-PLAT-002 | CLI and REST API share the same application services; no business logic in route handlers or arg parsers. Current: logic lives in `cli.py`; no REST API. Target. | Target | v0.3-alpha |
| REQ-PLAT-003 | Provide a REST API (FastAPI or comparable maintained ASGI, Pydantic-style validation, production ASGI server) as a first-class V1 interface. Current: none. Target. | Target | v0.3-alpha |
| REQ-PLAT-004 | Provide a web UI (Author Studio + admin + contestant portal). Current: only the stdlib dashboard. Target. | Target | v0.4-beta |
| REQ-PLAT-005 | Keep a supported CLI covering the organizer + author workflow. Current: `ctfgen` with ~20 subcommands. Retain over refactor. | Current | v0.3-alpha |
| REQ-PLAT-006 | Keep the MCP server exposing only pure, side-effect-bounded, workspace-sandboxed tools; never expose Docker/host-exec tools; CVE access snapshot-only over MCP. Current: `mcp_server.py` enforces this (no import of `scenario_runtime`/`agent_eval`/`dashboard_server`/`subprocess`; `_resolve_in_workspace` sandbox). Retain. | Current | v0.1-alpha |
| REQ-PLAT-007 | Persist all state in PostgreSQL via SQLAlchemy 2.x + Alembic migrations. Current: scattered JSONL/files + optional psycopg event store; no unified repository abstraction. Target. | Target | v0.3-alpha |
| REQ-PLAT-008 | Artifact storage behind an interface with local-FS (dev) and S3-compatible (prod) backends; published artifacts immutable + content-addressed. Current: bundles written to plain directories. Target. | Target | v0.3-alpha / v0.4-beta |
| REQ-PLAT-009 | Structured JSON logging across services, with a strict redaction policy (see REQ-INV-011). Current: ad hoc stdout/stderr prints. Target. | Target | v0.3-alpha |
| REQ-PLAT-010 | Single supported deployment: one control plane, ≥1 isolated worker host, reverse proxy + TLS, PostgreSQL, artifact storage. Current: `serve` is plain HTTP; `--secure-cookie` only meaningful behind a TLS-terminating proxy. Target: documented, reproducible deployment. | Target | v0.4-beta |
| REQ-PLAT-011 | CI, filesystem-write hardening, deterministic-generation checks, and release artifacts as a repeatable pipeline. Current: 709 unit tests; `compileall` + Docker gates; MCP workspace sandbox. Target: full CI + release artifacts. | Current (partial) / Target | v0.1-alpha |
| REQ-PLAT-012 | V1 explicitly excludes: public multi-tenant SaaS, billing, marketplace, Kubernetes operator, multi-region, untrusted control-plane plugins, arbitrary contestant Dockerfiles, SAML, full cyber-range sim, AI-generated vulnerable code, autonomous unrestricted AI defense. Non-goal guardrail. | Constraint | all |

---

## 6. Non-Functional Requirements — Operating Targets (`REQ-NFR-*`)

Initial V1 operating envelope. These are **target** SLOs; current fixture/stdlib components are not
yet load- or durability-tested against them.

| ID | Attribute | Target | Notes |
|---|---|---|---|
| REQ-NFR-001 | Concurrent teams | 25 | Steady-state per competition. |
| REQ-NFR-002 | Active challenges | 20 | Concurrently launchable/published. |
| REQ-NFR-003 | Instance launch success | ≥ 99% | Execution-plane launch reliability. |
| REQ-NFR-004 | Scoreboard update latency | < 3 s | Solve event → visible standings. |
| REQ-NFR-005 | Submission processing | < 500 ms | Server-side, per submission. |
| REQ-NFR-006 | Recovery Point Objective (RPO) | ≤ 5 min | Max tolerable data loss. |
| REQ-NFR-007 | Recovery Time Objective (RTO) | ≤ 30 min | Max tolerable restore time. |
| REQ-NFR-008 | Public flag leakage | 0 | No flag reachable via any public/contestant surface. See REQ-INV-004. |
| REQ-NFR-009 | Deterministic-rebuild failure | 0 | Same `(generator version, spec, family version, seed)` always rebuilds identically. See REQ-INV-001. |

V1.0 additionally requires an external security review, a recovery drill validating REQ-NFR-006/007,
upgrade + capacity testing against REQ-NFR-001..005, and 4 production-quality categories.

---

## 7. Product Invariants as Testable Requirements (`REQ-INV-*`)

These must hold at all times and each must have an automated test. "Current basis" cites where the
codebase already partially supports the invariant; "Target" invariants require the planned
persistence/execution/authz layers.

| ID | Invariant (testable statement) | Current basis | Delivered by |
|---|---|---|---|
| REQ-INV-001 | Identical `(generator version, spec, family version, seed)` ⇒ byte-identical artifacts. Test: regenerate twice, diff trees. | Deterministic renderers; `meta_mapping()` uses no wall-clock; conditional serializers keep default specs byte-identical. | v0.1-alpha |
| REQ-INV-002 | Generated file paths cannot escape the build/output directory. Test: adversarial spec/output cannot write outside root. | MCP `_resolve_in_workspace` rejects absolute-outside/`..` (`WorkspaceError`). Generalize to all writers. | v0.1-alpha |
| REQ-INV-003 | Private files (flag, solver, variant ground-truth, solution, timeline) never appear in public artifacts. Test: scan published artifact for `private/` content and flag string. | Trust-boundary split: flag only via `${CTFGEN_FLAG}` env, `private/` never player-facing; score.py integrity gate flags leaks. | v0.1-alpha |
| REQ-INV-004 | The flag is never served on any public/contestant surface; reachable only by exploiting the service. Test: crawl public routes/dashboard, assert flag absent. | Flag injected at runtime; not in `public/`; `score.py` forces `weak` band on public-file leakage. | v0.1-alpha / v0.4-beta |
| REQ-INV-005 | Build output is atomic — a failed generation leaves no partial bundle. Test: inject mid-render failure, assert no partial dir. | Target — current writer writes files incrementally (`force=True` rmtrees first). | v0.1-alpha |
| REQ-INV-006 | Published versions are immutable and content-addressed. Test: attempt to overwrite a published version → rejected. | Target — no publication/immutability layer today. | v0.3-alpha / v0.4-beta |
| REQ-INV-007 | A correct submission creates at most one solve per `(team, challenge, competition)`. Test: replay duplicate correct submissions → one solve. | `SolveEvent`/`solve_event_from_submission` model; single first-blood in scoreboard. Uniqueness enforcement is Target (needs PG constraint). | v0.3-alpha |
| REQ-INV-008 | Scoreboards are fully reconstructable from persisted score events. Test: rebuild scoreboard from event log, compare. | `scoreboard.compute_scoreboard` is a pure fold over events; `events.py` append-only monotonic seq. | v0.3-alpha |
| REQ-INV-009 | Admin score changes require an explicit recorded reason. Test: score override without reason → rejected + audited. | Target — no admin override path/audit today. | v0.3-alpha / v0.4-beta |
| REQ-INV-010 | The control plane never mounts the Docker socket and never imports execution modules. Test: static import check + deployment assertion. | `mcp_server` already avoids `subprocess`/execution imports; control-plane process must do the same. | v0.2-alpha / v0.3-alpha |
| REQ-INV-011 | Flags, session tokens, and provider API keys are never written to logs. Test: run flows with instrumented log sink, assert secret patterns absent. | Target — current code prints logs/tokens to stdout (e.g. `serve` prints the public token once by design). Needs redaction policy. | v0.3-alpha |
| REQ-INV-012 | Private solvers are never served to contestants. Test: contestant-scoped fetch of any `private/` path → denied. | `private/` is operator-side by construction; enforcement at the serving layer is Target. | v0.4-beta |
| REQ-INV-013 | One team cannot access another team's instance. Test: cross-team instance access → denied. | Target — per-team instance isolation is part of the execution/authz build. | v0.2-alpha / v0.3-alpha |
| REQ-INV-014 | Every privileged state change is auditable. Test: each privileged mutation emits an immutable audit record. | Target — no audit trail today. | v0.3-alpha |
| REQ-INV-015 | Layer dependency rule holds: `domain` imports no http/docker/postgres/mcp/LLM/framework code. Test: import-linter / static dependency check in CI. | Target — flat package today; enforced after REQ-PLAT-001. | v0.1-alpha → v0.3-alpha |

---

## 8. Traceability summary

| Group | IDs | Primary plane/subsystem | Earliest milestone |
|---|---|---|---|
| Author Studio | REQ-GEN-001..015 | Author Studio | v0.1-alpha |
| Control Plane | REQ-COMP-001..015 | Competition Control Plane | v0.3-alpha |
| Execution | REQ-EXEC-001..012 | Execution Plane | v0.2-alpha |
| Evaluation | REQ-EVAL-001..006 | Evaluation Lab | v0.5-beta |
| Platform | REQ-PLAT-001..012 | Cross-cutting | v0.1-alpha |
| Non-functional | REQ-NFR-001..009 | All planes | v0.4-beta / v1.0 |
| Invariants | REQ-INV-001..015 | All planes | v0.1-alpha onward |
