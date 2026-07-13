# Subsystem Maturity & Stability Tiers

**Version:** 0.1.0 (M6+ platform) · **Status date:** 2026-07-13

This document defines the stability tiers used across CTFGenerator and classifies
every current subsystem and challenge family by tier. It reflects the codebase **as
it exists today**; forward-looking notes are labelled **(planned)** and are not
guarantees.

Milestones M6–M18 have landed the layered platform on top of the original flat
generator package: a domain/application/infrastructure/interfaces/workers layering,
a FastAPI control plane at `/api/v1`, PostgreSQL + Alembic persistence, auth/RBAC,
organizer + contestant web portals, an isolated worker + PG job queue, an evaluation
lab, audit/observability, and a supported docker deploy stack. The subsystem table
below now classifies those layered subsystems alongside the original generator core.
These are 0.x subsystems: they are functional and tested, but their interface/behavior
stability is tiered conservatively (most sit at **Beta**) until the v1.0 hardening pass.

CTFGenerator is a self-hosted platform for generating, validating, deploying, and
operating reproducible cybersecurity challenges. AI-resistance evaluation is one
differentiating subsystem, not the whole product; its maturity is tracked
independently below.

---

## Stability tiers

| Tier | Support guarantee | Breaking changes | UI/CLI/docs labeling |
|---|---|---|---|
| **Stable** | Supported for production use. Interface, on-disk shapes, and documented exit codes are held compatible within a minor series. | Only on a documented major/minor bump with migration notes. | No label required. |
| **Beta** | Usable and tested, on a path to Stable. Behavior is largely settled but details may still move. | Permitted between minor releases; called out in release notes. | SHOULD be marked "beta" in docs. |
| **Experimental** | Available for evaluation only. No compatibility promise; may change shape, be renamed, or be removed. Not recommended for unattended production use. | Any release, without notice. | **MUST** be labeled experimental in UI, CLI, and docs (see rule below). |
| **Deprecated** | Still present but scheduled for removal; superseded by a named replacement. | Removal in a future release after a deprecation window. | MUST be marked deprecated with the replacement named. |

**Note on 0.x semantics:** the whole product is pre-1.0. "Stable" here means *most
mature and safe to depend on within 0.x*, not a 1.0-level API contract. Schema
versioning is now **enforced**, not advisory: `schema.py` gives every serialized spec
a schema identifier (`ctfgen.challenge-spec`), `check_compatible` rejects an unknown
major, and `migrate` upgrades older documents forward at load (including at the MCP
`build_spec`/`validate_spec` boundary). The score.py AI-resistance **bands and
dimension weights** remain not-stable (see the AI-resistance note below).

---

## Rule: experimental features must be labeled

Any subsystem, family, flag, or metric classified **Experimental** MUST be labeled
as such everywhere it is surfaced:

- **CLI** — help text / command output for the feature identifies it as experimental.
- **UI** — the dashboard surface exposing it marks it experimental.
- **Docs** — the reference section for it carries an experimental tag.

The label is a hard requirement, not a courtesy: experimental features carry no
compatibility promise, so users must be able to see the tier at the point of use.

---

## Subsystem classification (0.1.0)

Tiers below describe *interface and behavioral stability*, not code correctness.
Track designations (e.g. "production-track") indicate the intended destination, not
the current tier.

| Subsystem | Modules | Tier | Notes |
|---|---|---|---|
| Deterministic generator | `generator.py`, `spec_generator.py` (deterministic backend), `models.py`, `families.py`, `yaml_writer.py`, `templates/*` | **Stable** | Most mature subsystem. Core invariant: identical (generator version, spec, family, seed) ⇒ identical artifacts. Pure, stdlib-only, no Docker. Deterministic `--backend deterministic` only. |
| Static validation | `validator.py` (`validate_challenge`) | **Stable** | Pure artifact checks: required files, compose markers, yaml markers, scenario-timeline sanity. |
| Spec model & JSON round-trip | `models.py`, `spec_generator.py` (`spec_to_dict`/`spec_from_dict`/`validate_spec`) | **Stable** | `spec.json` shape stable; note it carries no embedded version field today. |
| CLI surface (core commands) | `cli.py` — `create`, `spec` (deterministic), `validate`, `list-families`, `catalog`, `quickstart` | **Stable** | Documented flags, exit codes, and stdout/stderr conventions. |
| MCP server (pure tools) | `mcp_server.py` | **Stable** | Only side-effect-bounded, deterministic tools exposed; workspace-sandboxed writes; snapshot-only CVE access; never imports Docker/subprocess/agent-eval/dashboard. |
| Report envelope & index | `report_writer.py`, `report_index.py` | **Stable** | `SCHEMA_VERSION = "1.0"` envelope; JSON + self-contained HTML index. |
| CVE sourcing — snapshot | `cve_source.py` (`SnapshotCveSource`), `cve_blueprint.py` | **Stable** | Offline bundled fixture backend; `create-from-cve`/`cve-search`/`cve-show` on `--source snapshot`. |
| CVE sourcing — NVD (live) | `cve_source.py` (`NvdCveSource`, `CachingCveSource`) | **Beta** | Network-effectful `--source nvd`; depends on external NVD 2.0 availability and shape. Snapshot path is the supported default. |
| Runtime validation (Docker) | `runtime_validator.py` | **Beta** | Builds/launches bundle, health-checks, runs intended solver, tears down. Executes bundle code **on the host by default**; `--sandbox` is opt-in. Isolation is not yet a hardened boundary (see execution-plane target below). |
| Sibling / replay validation | `sibling_validator.py`, `replay_validator.py` | **Beta** | Reuses `runtime_validator` internals; proves variant uniqueness / non-transfer. |
| Scoring engines & scoreboard | `scoring_engine.py`, `scoreboard.py`, `score.py` (competition scoring path) | **Beta** | Pluggable engines (`time_decay` default); pure folds over solve events. Config validation present. |
| Competition event log | `events.py` (`InMemoryEventStore`, `JsonlEventStore`) | **Beta** | Append-only, lock-serialized JSONL/in-memory. No schema-version field on records. |
| Competition event log — Postgres | `postgres_events.py` | **Experimental** | Optional `psycopg`-backed durable store; lazy dep; not the default persistence path. Durable control-plane persistence is **(planned, v0.3-alpha)**. |
| Scenario engine (offline) | `scenario.py` | **Experimental** | Pure scripted trigger/response timeline; `run-scenario` offline. Condition DSL and event shapes may change. Live-adversarial knob `live_adversarial_engine` is unwired. |
| Scenario runtime (Docker) | `scenario_runtime.py` | **Experimental** | Docker/HTTP glue for `run-scenario --runtime`; reaches into `runtime_validator` privates. |
| Dashboard server | `dashboard_server.py`, `dashboard_ui.py` | **Experimental** | Hand-rolled stdlib `ThreadingHTTPServer` admin dashboard + public scoreboard (`serve`). Plain HTTP; `--secure-cookie` only meaningful behind a TLS proxy. **(planned)** replacement by a maintained ASGI stack. |
| Dashboard authentication | `dashboard_server.py` (session login, token rotation, `AuthConfig`) | **Experimental** | Bespoke session/cookie/token auth in the hand-rolled server. Not hardened for untrusted exposure; deploy behind a reverse proxy only. |
| Agent-eval harness | `agent_eval.py` | **Experimental** | LLM tool-using agent driven against a live Docker instance (`eval-agent`, `--adversarial`). Network + Docker + provider-key dependent. |
| AI-resistance signals (three distinct things) | `score.py` (advisory heuristic); `application/evaluation` + `agent_eval.py` (measured eval); `scoring_engine.py` `AIResistanceWeightedEngine` (`name="ai_resistance"`, competition multiplier) | **Experimental** | M19 settles the naming into three DISTINCT signals, not one metric: (1) `score.py` output is an **advisory heuristic** static quality signal derived from bundle heuristics (Experimental; its docstring already says "advisory heuristic only"); (2) the Evaluation Lab produces a **measured** agent-eval outcome per version (`EvalRun`); (3) the competition-points **multiplier** is the `ai_resistance` scoring engine. The advisory heuristic's bands and dimension weights are **not stable**; the blended-score contract is not stable. |
| LLM spec backends | `spec_generator.py` (`AnthropicSpecBackend`, `OpenAISpecBackend`) | **Experimental** | Network-effectful `spec --backend anthropic\|openai`; LLM emits pedagogical text only. Optional provider deps. |

### Layered platform subsystems (M6–M18)

The subsystems below were built by milestones M7–M18 on top of the generator core.
They are functional and tested (host + Docker PG integration suites) but are tiered
**Beta** as 0.x subsystems: usable and settled in shape, still ahead of the v1.0
hardening/external-review pass. The hard control/execution boundary (ADR-001) holds —
the control-plane API never mounts the Docker socket and never imports execution
modules.

| Subsystem | Modules | Tier | Notes |
|---|---|---|---|
| Layered core (domain/application) | `domain/*`, `application/*` | **Beta** | Pure domain layer + application services; dependency rule enforced by `tests/test_architecture_boundaries.py`. CLI and API share these services. |
| Persistence | `infrastructure/database/*`, `alembic/*` | **Beta** | SQLAlchemy 2.x, per-aggregate repositories, unit-of-work session scope; Alembic chain to head `0014_audit_events`. ORM objects never leave infrastructure. |
| Control-plane API | `interfaces/api/*` (FastAPI `/api/v1`, 18 routers) | **Beta** | Request-id/access-log/rate-limit middleware, cursor pagination, ETag concurrency, principal-scoped idempotency. No Docker socket, no execution imports. |
| Auth / RBAC | `interfaces/api/deps.py` (`Permission`, `ROLE_PERMISSIONS`, `require_permission`), `db_authenticator.py`, `auth`/`oidc`/`users` routers | **Beta** | Local password + sessions (hash-only tokens), per-competition role scoping, denied-action audit; OIDC auth-code+PKCE federation (ADR-007, ADR-008). |
| Workers / job queue | `workers/*`, `application/jobs`, `domain/work`, `jobs`/`builds` routers | **Beta** | PG job queue (`FOR UPDATE SKIP LOCKED`, leases, retries, dead-letter, idempotency; migration `0006_jobs`). Worker drives the plane through one `WorkerControlPlaneClient` seam; ADR-003. |
| Execution runtime (isolated) | `infrastructure/runtime` (`DockerRuntimeBackend`), `workers/worker.py` | **Beta** | Host-block (iptables DROP) capability-gated hard floor, per-worker reap, compose hardening; isolation proven by an independent escape agent (M8). Rootless/userns still capability-gated on the current host — see `docs/security/runtime-isolation.md`. |
| Instance lifecycle | `application/instances`, `instances` router | **Beta** | 14-state machine + desired-vs-observed reconciler; team-scoped operator view (public fields only). |
| Organizer web | `interfaces/web/router.py`, `views.py`, `templates/*` | **Beta** | Server-rendered organizer portal (competitions/teams/publications/instance ops), authz-scoped to match the API's 403s. No external CDN. |
| Contestant portal | `interfaces/web/contestant.py` | **Beta** | Contestant challenge list / instance access / submission / standing; private solvers never served. See `docs/web/contestant-portal.md`. |
| Challenge SDK | `sdk/*` (`plugins.py`, `adapter.py`, `scaffold.py`, `lint.py`) | **Beta** | Documented family/plugin registration boundary (`docs/CHALLENGE_SDK.md`); replaces the convention-only template contract. |
| Evaluation Lab (measured) | `application/evaluation`, `evaluations` router, `workers/eval_runner.py` | **Experimental** | **Measured** agent eval as isolated PENDING `EvalRun` jobs + adversarial-delta. Distinct from the advisory `score.py` heuristic. Aggregate generalization/difficulty reports still thin. |
| Audit trail | `domain/audit`, `audit` router, migration `0014_audit_events` | **Beta** | Append-only, tamper-evident privileged-action log; admin/support-only read (`AUDIT_READ`). |
| Observability | `observability/logging.py`, `observability/secrets.py` | **Beta** | Structured JSON logging with secret redaction (flags/tokens/provider-keys never logged). |
| Backup / restore / DR | `scripts/backup.sh`, `application/backup/verify.py` | **Experimental** | Restore-**integrity** verification harness + backup script. Verifies a backup restores to a consistent state; does NOT yet measure RPO/RTO SLOs (M20 recovery drill). |
| Supported deploy stack | `deploy/*` (`Dockerfile.api`, `Dockerfile.worker`, `docker-compose.yml`, `verify-deploy.sh`), `docs/HOSTING.md` | **Beta** | The single supported deployment topology; reverse proxy + TLS is an operator responsibility. |

---

## Challenge family classification (0.1.0)

All eight families render deterministically and pass static validation. Tiering here
reflects **content maturity and validation depth**, per the productization plan's
distinction between production-track and experimental domains. Every family listed as
Experimental is subject to the labeling rule above.

| Family | Category | Modes | Track / Tier |
|---|---|---|---|
| `web_business_logic_tenant_export` | web | red | **Production-track** — reference family (API + Redis + async worker), fullest test surface (`validate_solver.py`, `validate_variant.py`). |
| `network_lateral_pivot` | network | red, purple | **Production-track** — red+purple, detection-notes/checkpoint grading. |
| `cloud_metadata_ssrf` | cloud | red | **Production-track**. |
| `forensics_incident_triage` | forensics | (blue-leaning) | **Production-track** — blue-category grading path. |
| `crypto_token_forgery` | crypto | red | **Experimental** — single-service template family. |
| `binary_heap_exploit` | binary | red | **Experimental** — likely non-HTTP (`runtime.json`) invocation; runtime path less exercised. |
| `mobile_insecure_storage` | mobile | red | **Experimental**. |
| `scada_ics_modbus_takeover` | scada_ics | red | **Experimental** — Modbus/non-HTTP invocation. |

Per-family default live-adversarial scenarios exist only for `crypto_token_forgery`,
`cloud_metadata_ssrf`, `network_lateral_pivot`, and `web_business_logic_tenant_export`;
those scenarios inherit the **Experimental** scenario-engine tier regardless of the
family's own track.

---

## Plane split — status

The productization plan splits the system into four planes — Author Studio,
Competition Control Plane, Execution Plane, and Evaluation Lab — with a hard boundary:
generated vulnerable workloads must **never** execute on the control plane, and the
control plane must never mount the Docker socket. That split is now **built**: the
isolated worker + PG job queue (M7/M8), the control-plane API (M9), and the evaluation
lab (M15) run generated workloads only on isolated workers reached through the
`WorkerControlPlaneClient` seam, and the boundary is enforced by ADR-001 plus the
architecture-boundary test. The original CLI-only execution helpers
(`runtime_validator`, `scenario_runtime`, sibling/replay, `agent_eval`) remain as the
author-side, host-executing tools they always were — the worker path is the isolated,
control-plane-driven route.

Remaining toward **Stable**: the layered platform subsystems are tiered **Beta** and
promote to Stable only after the v1.0 hardening pass (external security review, recovery
drill validating RPO/RTO, capacity testing) — **(planned)** across M20–M22. Rootless
Docker/Podman + rootless BuildKit on workers remains capability-gated on the current
host (see `docs/security/runtime-isolation.md`).
