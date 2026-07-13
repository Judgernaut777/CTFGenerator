# CTFGenerator — Product Definition

> Milestone 1 deliverable. Product statement, user roles, four-plane architecture,
> primary workflows, V1 deployment model, and V1 non-goals. Grounded in the current
> codebase; every forward-looking item is labelled **(planned)** / **(target)**.

## 1. Product statement

CTFGenerator is a **self-hosted platform for instructors, security teams, and CTF
organizers to generate, validate, deploy, and operate reproducible cybersecurity
challenges.**

AI-resistance evaluation is a **differentiating subsystem, not the whole product.**
The product is the full lifecycle — author a challenge, prove it is solvable and
reproducible, publish an immutable version, run a real competition against isolated
per-team instances, score submissions, and produce audit-grade reports. The
AI-resistance machinery (variant uniqueness, sibling/replay non-transfer, the
live-adversarial scenario engine, the agent-eval harness) is what makes those
challenges hold up against LLM-assisted solvers — a quality dimension layered on top
of an operable competition platform, not a replacement for it.

"AI-resistance" resolves to **three distinct signals**, not one number: (1) the
`score.py` output is an **advisory heuristic** static quality signal (Experimental);
(2) the Evaluation Lab produces a **measured** agent-eval outcome per challenge version
(`EvalRun`); and (3) the competition-points **multiplier** is the `ai_resistance`
scoring engine. They are computed by different subsystems and must not be conflated.

### Current vs. target in one line

- **Current (M6+ platform):** the deterministic generator/validator/scorer core
  (pure-Python, stdlib-only) plus the layered platform that milestones M7–M18 shipped —
  a FastAPI control plane at `/api/v1`, PostgreSQL + Alembic persistence, auth/RBAC +
  OIDC, organizer + contestant web portals, an isolated worker + PostgreSQL job queue,
  an evaluation lab, audit/observability, backup/restore/DR tooling, and a supported
  docker deploy stack — with the hard boundary keeping generated vulnerable code off the
  control plane enforced (ADR-001). The `ctfgen` CLI and MCP server (pure tools only) are
  retained over the same application services.
- **Target (v1.0):** the same platform through its hardening pass — external security
  review, recovery drill validating RPO/RTO, capacity testing at the operating targets,
  and four production-quality challenge categories (M20–M22).

---

## 2. User roles

Eight roles. Each names *who* acts and *what* they do. Permission enforcement **is
shipped** (M10): `domain/identity` defines the role set, and a fine-grained `Permission`
enum + `ROLE_PERMISSIONS` + `require_permission` dependency gate every privileged route
(`interfaces/api/deps.py`), with per-competition role scoping, denied-action audit, and
OIDC federation (ADR-007, ADR-008). The conceptual roles below map onto the enforced
`VALID_ROLES` (`player`, `captain`, `author`, `organizer`, `admin`, `observer`, `judge`,
`support`).

| # | Role | What they do |
|---|------|--------------|
| 1 | **Platform owner** | Owns the deployment; sets global policy, licensing, and the highest-privilege configuration. |
| 2 | **Operator** | Runs and maintains the deployment — control plane, worker hosts, storage, backups, upgrades. |
| 3 | **Event administrator** | Configures a competition: teams, schedule/windows, which challenge versions are published, scoring config. |
| 4 | **Challenge author** | Authors specs, picks family/CVE/seed, generates and validates challenges, submits them for review. |
| 5 | **Reviewer** | Reviews authored challenges (solvability, quality, AI-resistance) and approves/rejects publication. |
| 6 | **Team captain** | Manages a team's roster and its access to launched challenge instances during an event. |
| 7 | **Contestant** | Solves published challenges against their team's isolated instances and submits flags. |
| 8 | **Observer** | Read-only spectator of public scoreboard and feed; no instance or private-artifact access. |

---

## 3. Four-plane product architecture (target)

The architecture splits into four planes with a **non-negotiable boundary: generated
vulnerable workloads must NEVER execute on the control plane, which never mounts the
Docker socket.** Today all of this runs in one process; the plane split is the
refactor destination.

### 3.1 Author Studio
Spec authoring, family/CVE/seed selection, generation, validation, review, approval,
publication, and version history.

| Responsibility | Current grounding | Target |
|---|---|---|
| Draft a structured spec before rendering | `ctfgen spec` / MCP `build_spec` → validated `ChallengeSpec`; LLM emits only pedagogical text (`_LLM_SCHEMA`: title/objectives/checkpoints) | Same, behind an application service + web UI |
| Deterministic generation | `ctfgen create` / `create-from-cve`; `generator.create_challenge` renders a bundle from `(family, seed, spec)` | Unchanged core; invoked as a job |
| Family / CVE / seed selection | `list-families`, `cve-search`/`cve-show`/`cve-categories`; `cve_blueprint.spec_from_cve` | Web pickers over the same registry/source |
| Static + quality validation | `ctfgen validate` (`validate_challenge`), `ctfgen score` (`score_challenge`, AI-resistance dimensions + bands) | Gated review workflow |
| Review / approval / publication | **(planned)** — no review or approval state exists today | Reviewer approval → immutable published version |
| Version history | Shipped — `schema.py` `check_compatible`/`migrate`/`register_migration`; `challenge_versions` router; content-addressed immutable published versions in `infrastructure/artifacts` | Reviewer-gated *approval* over the same versions (still planned, REQ-GEN-013) |

### 3.2 Competition Control Plane
Auth, competitions, teams, publication, instance orchestration, submissions, scoring,
scoreboards, reports, audit. **NEVER executes generated challenge code; NEVER has
Docker socket access.**

| Responsibility | Current grounding | Target |
|---|---|---|
| Competitions / teams / config | `CompetitionConfig`, `ChallengeScoringConfig`; `serve` builds a `CompetitionService` | PostgreSQL domain model + migrations |
| Auth | dashboard `AuthConfig` (single admin + public token) | Role-based authz for the 8 roles |
| Submissions → solves | `Submission`/`SolveEvent`; at most one solve per correct submission (`solve_event_from_submission`) | Enforced one-solve-per `(team,challenge,competition)` |
| Scoring | `scoring_engine.py` (static/dynamic_decay/**time_decay** default/ai_resistance), `scoreboard.compute_scoreboard` | Same engines behind the service |
| Event log | `events.py` (`InMemory`/`Jsonl` stores) + optional `postgres_events.py` | PostgreSQL as the durable store |
| Scoreboards / feed | `serve` → `/public/scoreboard`, `/public/feed`; `scoreboard` CLI | Reconstructable from persisted score events |
| Reports / audit | `report_writer.py` envelope (`schema_version 1.0`), `report-index` table/HTML | Every privileged state change auditable |
| Instance orchestration | **Shipped** — control plane dispatches launch/build jobs to the isolated worker via the PG job queue (`jobs`/`builds` routers, `application/instances` lifecycle + reconciler); never runs them itself | Job dispatch + reconciliation |

### 3.3 Execution Plane
Image builds, instance launch, health checks, runtime validation, intended solver
execution, network isolation, resource enforcement, log collection, expiration, and
cleanup. **Runs on ISOLATED workers.**

| Responsibility | Current grounding | Target |
|---|---|---|
| Build + launch + teardown | `runtime_validator.py`: `docker compose build/up`, health poll, solver run, `down` | Rootless Docker/Podman + rootless BuildKit on isolated workers |
| Health checks | `tests/healthcheck.py` probe of `/healthz`; `runtime.json` overrides for non-HTTP families | Unchanged probe contract |
| Runtime + non-transfer validation | `validate-runtime`, `replay` (`cross_replay`), `validate-siblings --runtime/--cross-replay` | Runs only as isolated jobs |
| Untrusted-code isolation | `--sandbox` runs healthcheck/solver in an ephemeral read-only container; compose hardening (`no-new-privileges`, `cap_drop: [ALL]`, `mem_limit`, `pids_limit`, `internal: true` nets) | Sandbox mandatory on isolated hosts; resource + network enforcement |
| Log collection / expiration / cleanup | teardown + `report.logs` (generator path) | Shipped — instance lifecycle + expiration + reconciliation (`application/instances` 14-state machine + desired-vs-observed reconciler) |

> **Boundary note:** today `runtime_validator._run` shells out to Docker and runs
> bundle-shipped `solver.py`/`healthcheck.py` **on the host by default** (`--sandbox`
> opt-in) — a `validate-runtime` WARNING says so. The target moves all of this onto
> isolated workers reached only via a job-result contract.

### 3.4 Evaluation Lab
Scripted/adaptive agent baselines, cross-seed/cross-family generalization, human
benchmark ingestion, difficulty analysis, and quality reports.

| Responsibility | Current grounding | Target |
|---|---|---|
| Agent baselines | `agent_eval.py`; `eval-agent [--adversarial]` (baseline vs. scenario-on delta) | Managed eval runs as jobs |
| Live-adversarial scenarios | `scenario.py` engine + `scenario_runtime.py`; `run-scenario [--runtime]` | Scored generalization signal |
| Generalization / non-transfer | `replay`, `validate-siblings` (`changed_tokens`, cross-replay) | Cross-seed/cross-family batteries |
| Difficulty / quality reports | `score.py` **advisory heuristic** dimensions + bands (distinct from the measured `EvalRun`); `score_with_agent_eval` blended score | Human-benchmark ingestion + aggregated report **(planned)** |

---

## 4. Primary workflows — the §14 end-to-end vertical slice

The **highest-priority objective is ONE secure, persistent, fully-tested end-to-end
organizer + contestant workflow** before any family/integration expansion. The
current CLI already demonstrates the offline spine of this slice; the persistent,
multi-user, isolated-execution version is the V1 target.

### 4.1 Organizer workflow

| Step | Target action | Current grounding |
|---|---|---|
| 1 | Author drafts + generates a challenge | `ctfgen spec` → `ctfgen create` (or `create-from-cve`) |
| 2 | Validate statically + score quality | `ctfgen validate`; `ctfgen score --min-score` |
| 3 | Prove solvable + reproducible on a worker | `ctfgen validate-runtime` (target: `--sandbox` on isolated host) |
| 4 | Prove non-transfer across siblings | `ctfgen validate-siblings --runtime --cross-replay`, `ctfgen replay` |
| 5 | Reviewer approves → publish immutable version | **(planned)** review/approval + content-addressed immutable versions |
| 6 | Assemble a competition catalog | `ctfgen catalog` → `ChallengeScoringConfig` JSON |
| 7 | Configure competition, teams, windows | `CompetitionConfig`; `serve --config/--challenges/--challenges-dir` |
| 8 | Launch per-team instances | Shipped — control plane dispatches launch jobs to isolated workers via the PG job queue (`instances` router + `application/instances`) |
| 9 | Operate live: scoreboard, feed, audit | `ctfgen serve` admin dashboard + `/public/scoreboard` + `/public/feed` |
| 10 | Produce reports | `report_writer` envelopes; `ctfgen report-index --html` |

`ctfgen quickstart` renders web + crypto + a CVE-driven (`CVE-2021-44228`) sample and
prints the exact `catalog`/`serve` follow-up commands — the fastest path through
steps 1–7 today.

### 4.2 Contestant workflow

| Step | Target action | Current grounding |
|---|---|---|
| 1 | Join team, see published challenges | **Shipped** — contestant portal (`interfaces/web/contestant.py`); see `docs/web/contestant-portal.md` |
| 2 | Receive an isolated instance | **Shipped** — team-scoped instance via the `instances` router (cross-team access denied; `tests/test_team_isolation_integration.py`) |
| 3 | Read the brief + tiered hints | bundle `public/description.md`, `public/hints.yaml` |
| 4 | Exploit the live service for the flag | flag injected at runtime via `${CTFGEN_FLAG:-}`, never in `public/` |
| 5 | Submit the flag | `Submission` → at most one `SolveEvent` per correct submit |
| 6 | Watch the scoreboard | `/public/scoreboard`, `/public/feed` |

**Trust boundary (enforced by the bundle layout today):** contestants receive only
`public/` + service source + `challenge.yaml`; everything under `private/` (flag,
`solver.py`, `variant.json`, `solution.md`, scenario timeline) is operator/grader-side
and is never served to contestants.

---

## 5. V1 deployment model (single supported path)

One supported topology. Anything else is a V1 non-goal.

| Component | V1 choice |
|---|---|
| Control plane | Single deployment; **never** mounts the Docker socket |
| Persistence | PostgreSQL |
| Workers | One or more **isolated** worker hosts running containerized challenge workloads |
| Runtime | Rootless Docker/Podman + rootless BuildKit on the workers **(planned)** |
| Work queue | Shipped — PostgreSQL-backed job rows: `FOR UPDATE SKIP LOCKED`, leases, heartbeats, retries, idempotency keys, dead-letter (**no Redis** unless proven inadequate) |
| Ingress | Reverse proxy with TLS (control plane server is plain HTTP; `--secure-cookie` only meaningful behind TLS termination) |
| Artifact storage | Local-FS backend + published artifacts **immutable + content-addressed** shipped (`infrastructure/artifacts`); S3-compatible (prod) backend still planned (Protocol defined) |
| Interfaces | Shipped — organizer + contestant web apps at `/app` (M11/M12), the REST API at `/api/v1`, and the supported `ctfgen <area> <verb>` CLI, all over shared application services (the legacy stdlib `serve` dashboard still ships but is not the product) |

**Tech baseline (target, unless a repo constraint makes one unsuitable):** Python
3.12; FastAPI-or-comparable ASGI framework; Pydantic-style validation; SQLAlchemy 2.x
+ Alembic; production ASGI server; structured JSON logging. The current core is
Python 3.11, stdlib-only.

**Initial operating targets:** 25 concurrent teams; 20 active challenges; ≥99%
instance launch success; scoreboard update <3s; submission processing <500ms
server-side; RPO 5min; RTO 30min; zero public flag leakage; zero deterministic-rebuild
failures.

---

## 6. V1 non-goals (explicit)

Out of scope for V1 — do not build, do not design around:

- Public multi-tenant SaaS
- Billing
- Challenge marketplace
- Kubernetes operator
- Multi-region deployment
- Arbitrary untrusted control-plane plugins
- Arbitrary contestant-supplied Dockerfiles
- Enterprise SAML
- Full cyber-range topology simulation
- AI-generated vulnerable code (the LLM authors only pedagogical metadata; vuln code
  stays deterministic and server-side)
- Autonomous, unrestricted AI defense (the live-adversarial engine is scripted;
  `live_adversarial_engine` is an unwired Phase-5 knob)
- Dozens of shallow challenge categories (V1 targets a small set of production-quality
  categories, not breadth)

---

## 7. Key invariants this product upholds

- Identical `(generator version, spec, family version, seed)` ⇒ identical artifacts.
- Generated paths cannot escape the build dir; MCP write tools sandbox `output_dir`
  to a workspace root (`_resolve_in_workspace`, `CTFGEN_MCP_WORKSPACE`).
- Private files never appear in public artifacts; the flag is never in `public/`.
- Published versions are immutable **(planned)**; a correct submission creates at most
  one solve per `(team, challenge, competition)`.
- Scoreboards are reconstructable from persisted score events; admin score changes
  require an explicit reason **(planned)**.
- The control plane never mounts the Docker socket; one team cannot access another
  team's instance **(planned)**.
- Flags, session tokens, and provider keys are never logged; private solvers are never
  served to contestants; every privileged state change is auditable.
