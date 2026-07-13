# CTFGenerator V1 Support Matrix

Milestone 1 deliverable; reconciled 2026-07-13 for the M6+ platform. Defines what the V1
platform officially supports, what is experimental, and what is explicitly out of scope.
"Current" = behavior grounded in the present codebase — the deterministic generator core
**plus** the layered platform shipped by M7–M18 (FastAPI control plane at `/api/v1`,
PostgreSQL + Alembic, auth/RBAC + OIDC, organizer + contestant web, isolated worker + PG
job queue, evaluation lab, audit/observability, backup/DR tooling, supported docker
deploy). "Target" / "Planned" marks the remaining v1.0 hardening (external review,
recovery drill, capacity testing) and the few items still unbuilt (e.g. the S3 artifact
backend, rootless worker runtime on this host).

> Scope: V1 is a **single supported deployment path**. Anything not listed here is
> unsupported by definition. See [Unsupported Configurations](#unsupported-configurations-v1-non-goals).

---

## Platform status summary

| Aspect | Current (M6+ platform) | Target (v1.0 hardening) |
|---|---|---|
| Form factor | FastAPI control plane (`/api/v1`) + organizer/contestant web + isolated worker; `ctfgen` CLI + MCP server retained over shared application services | Same topology, hardened + capacity-tested |
| Language runtime | Python 3.11 (stdlib-only generator core); platform deps (FastAPI, SQLAlchemy, psycopg) lazy/optional-extra | Python 3.12 |
| Persistence | PostgreSQL via SQLAlchemy 2.x + Alembic (`infrastructure/database/`, head `0014_audit_events`) | Same, migration/upgrade path tested across versions |
| Web serving | ASGI (FastAPI) app; reverse-proxy TLS termination is an operator responsibility (`deploy/`, `docs/HOSTING.md`) | Same, under the supported deployment |
| Challenge execution | Isolated worker + PG job queue (`workers/`, ADR-003); control plane never mounts the Docker socket (ADR-001) | Rootless Docker/Podman + rootless BuildKit on workers (capability-gated on this host) |

---

## Host operating system

Target deployment is Linux only. macOS/Windows are developer-convenience only (no support).

| OS / distribution | Role | Status |
|---|---|---|
| Ubuntu 22.04 LTS / 24.04 LTS (x86-64) | Control plane + worker | **Target: supported** |
| Debian 12 (x86-64) | Control plane + worker | **Target: supported** |
| ARM64 (aarch64) Linux | Control plane + worker | **Target: best-effort** (core is pure-Python; container base images must have arm64 variants) |
| Other systemd-based Linux | Any | Planned: unofficial / community |
| macOS, Windows (incl. WSL) | Local dev only | Unsupported for production |

The generator/validator core is stdlib-only Python and OS-agnostic; the OS constraint comes
from the **container runtime and worker isolation**, not the Python code.

---

## Python version

| Component | Current | Target (V1) |
|---|---|---|
| Generator / validator core | 3.11 (stdlib-only) | 3.12 |
| Optional deps (`anthropic`, `openai`, `psycopg`, `mcp`) | lazy-imported, 3.11 | 3.12 |
| Sandbox / runtime-validation container base | `python:3.11-slim` (see `runtime_validator.py` `sandbox=True`) | Planned: 3.12-slim |

Only one minor version is targeted per release. 3.13 is not evaluated for V1.

---

## Deployment model (V1)

**Single supported path** (built; hardening in v1.0):

- One control-plane deployment (API + web UI + CLI share one application layer).
- PostgreSQL for persistence.
- One or more **isolated** worker hosts running containerized challenge workloads.
- Reverse proxy terminating TLS in front of the control plane.
- Local-filesystem **or** S3-compatible artifact storage.
- REST API + web UI + supported CLI (`ctfgen`).

**Hard boundary:** generated vulnerable challenge workloads NEVER execute on the control
plane, and the control plane NEVER has Docker socket access. All build/launch/health/solve
work runs on isolated workers.

Current state: the control/worker split is **built** (M7/M8). The control plane
dispatches launch/build jobs onto the PostgreSQL job queue; the isolated worker
(`workers/worker.py`) claims them and drives `DockerRuntimeBackend`, reaching the control
plane only through the `WorkerControlPlaneClient` seam. The control plane holds no Docker
socket (ADR-001). The original CLI helpers (`runtime_validator.py`, `replay_validator.py`,
`sibling_validator.py`, `scenario_runtime.py`, `agent_eval.py`) remain as author-side
tools that still shell out to `docker compose` on the host — they are not the deployed
execution path. Rootless Docker/Podman + rootless BuildKit on workers is capability-gated
on the current host (see `docs/security/runtime-isolation.md`).

---

## Container runtimes (worker hosts)

| Runtime | Status | Notes |
|---|---|---|
| Rootless Docker | **Target: supported** | Primary. Current code shells out to `docker compose` (rootful, in-process). |
| Rootless Podman | **Target: supported** | Docker-compatible CLI surface. |
| Rootless BuildKit | **Target: supported** | Image builds on workers. |
| Rootful Docker / root daemon | Dev only | Reflects current in-process behavior; **not** a supported V1 worker config. |
| Kubernetes / OCI orchestrators | Unsupported (non-goal) | No K8s operator in V1. |

Generated `docker-compose.yml` already carries hardening today: `no-new-privileges`,
`cap_drop: [ALL]`, `mem_limit`, `pids_limit`, and internal-only services on an
`internal: true` network with no published port. The flag is injected at runtime via
`${CTFGEN_FLAG:-}` and is never baked into public artifacts.

---

## Artifact storage backends

| Backend | Status | Notes |
|---|---|---|
| Local filesystem | **Supported** (current + target dev default) | Generation writes self-contained bundles to `--output`; reports written per-run as JSON. |
| S3-compatible object storage | **Target: supported (prod)** | Planned storage interface; published artifacts are immutable + content-addressed. |
| Any other backend | Unsupported | Non-goal for V1. |

Planned invariants for published artifacts: immutable, content-addressed, atomic build
output, private files (`private/solver.py`, `variant.json`, flag, `solution.md`) never
included in public artifacts. Today the public/private split is enforced by the
family renderer + validator (public = `public/` + service source + `challenge.yaml`;
everything under `private/` is operator-side).

---

## Database (PostgreSQL)

| Item | Current | Target (V1) |
|---|---|---|
| Primary store | PostgreSQL (`infrastructure/database/`) — required for the platform | PostgreSQL (required) |
| Legacy store | `events.py` JSONL / `postgres_events.py` retained for the CLI-only path | Superseded by the domain model |
| Migrations | Alembic chain to head `0014_audit_events` | Reversible/tested across versions |
| ORM / access | SQLAlchemy 2.x, per-aggregate repositories (ORM never leaves infrastructure) | Same |

| PostgreSQL version | Status |
|---|---|
| PostgreSQL 15 | **Target: supported** |
| PostgreSQL 16 | **Target: supported** |
| PostgreSQL 14 | Planned: minimum acceptable |
| < 14 | Unsupported |

Planned work queue is **PostgreSQL-backed job rows** (`FOR UPDATE SKIP LOCKED`, leases,
heartbeats, retries, idempotency keys, dead-letter). No Redis in V1 unless PostgreSQL is
proven inadequate.

---

## Challenge categories & maturity

Eight families exist today across eight domains, wired in `families.py`. Maturity tiers
below reflect the productization plan's intent to ship a small number of
production-quality categories rather than many shallow ones.

| Category | Family (current) | Modes | Tier |
|---|---|---|---|
| Web | `web_business_logic_tenant_export` | red | **Production-track** |
| Network | `network_lateral_pivot` | red, purple | **Production-track** |
| Cloud | `cloud_metadata_ssrf` | red | **Production-track** |
| Forensics | `forensics_incident_triage` | (blue-oriented) | **Production-track** |
| Crypto | `crypto_token_forgery` | red | Experimental |
| Binary | `binary_heap_exploit` | red | Experimental |
| Mobile | `mobile_insecure_storage` | red | Experimental |
| SCADA/ICS | `scada_ics_modbus_takeover` | red | Experimental |

Notes:
- Modes are `red` / `blue` / `purple` (`ChallengeSpec.mode`; per-family `Family.modes`).
- **Production-track** = the four categories intended to reach production quality for V1
  (external review, deterministic-rebuild guarantees, runtime-validated solvers).
- **Experimental** families generate and statically validate today, but are not part of
  the V1 production-quality guarantee. `binary` / `scada_ics` are the likely non-HTTP
  (`private/runtime.json`) families and carry higher runtime-validation risk.
- Live-adversarial scenario defaults exist only for `crypto_token_forgery`,
  `cloud_metadata_ssrf`, `network_lateral_pivot`, and `web_business_logic_tenant_export`.
- **Non-goal:** dozens of shallow categories; AI-generated vulnerable code.

---

## Browser support (web UI)

Current: `serve` renders a self-contained admin dashboard + public scoreboard
(`dashboard_ui.py`) with **no external CDN**, inline HTML/CSS only; `report-index --html`
emits a self-contained static dashboard. Target: an ASGI-served web UI for Author Studio,
Competition Control, and the contestant portal.

| Browser | Status |
|---|---|
| Chrome / Chromium (latest 2) | **Supported** |
| Firefox (latest 2) | **Supported** |
| Edge (Chromium, latest 2) | **Supported** |
| Safari (latest 2) | **Target: supported** |
| Mobile browsers (responsive) | Planned: best-effort |
| Internet Explorer / legacy | Unsupported |

No specific browser API dependency exists in the current inline pages; support is defined
by test coverage, not runtime gating.

---

## Minimum host targets

Sizing for the initial operating targets (25 concurrent teams, 20 active challenges).
Planned; not benchmarked in the current codebase.

### Control plane host (no challenge execution, no Docker socket)

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| Memory | 4 GB | 8 GB |
| Storage | 20 GB SSD (DB + artifacts if local-FS) | 50 GB+ SSD |

### Worker host (container builds + challenge instances)

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 4 vCPU | 8+ vCPU |
| Memory | 8 GB | 16 GB+ |
| Storage | 40 GB SSD (images + build cache + instance layers) | 100 GB+ SSD |

### PostgreSQL host

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| Memory | 4 GB | 8 GB |
| Storage | 20 GB SSD | 50 GB+ SSD (with WAL headroom) |

Per-instance limits (`mem_limit`, `pids_limit`) are already declared in generated
`docker-compose.yml`; aggregate worker sizing must budget for concurrent instances.

---

## Unsupported configurations (V1 non-goals)

Explicitly out of scope for V1:

- Public multi-tenant SaaS; billing; challenge marketplace.
- Kubernetes operator / orchestrator integration; multi-region deployment.
- Arbitrary untrusted control-plane plugins.
- Arbitrary contestant-supplied Dockerfiles / images.
- Enterprise SAML / external IdP federation.
- Full cyber-range topology simulation.
- AI-generated vulnerable code (the LLM emits only pedagogical metadata —
  `title`, `learning_objectives`, `checkpoints`; all code/flags/`ai_resistance` are
  deterministic).
- Autonomous, unrestricted AI defense (the `live_adversarial_engine` knob exists but the
  runtime is scripted/replayable, not autonomous).
- Dozens of shallow challenge categories.
- Control plane with Docker socket access, or running generated challenge workloads on the
  control plane (violates the highest-priority security boundary).
- Redis-backed queue (PostgreSQL job rows are the V1 queue).
- Databases other than PostgreSQL; storage backends other than local-FS or S3-compatible.
- Windows / macOS as production hosts.

---

## Cross-cutting V1 guarantees (target)

- Identical `(generator version, spec, family version, seed)` ⇒ identical artifacts
  (deterministic rebuild; ZERO deterministic-rebuild failures).
- ZERO public flag leakage; flags/session-tokens/provider-keys never logged.
- Generated paths cannot escape the build directory.
- Published versions are immutable; private solvers never served to contestants.
- Control plane never mounts the Docker socket.

Schema versioning is now **enforced** (M4, `schema.py`): serialized specs carry a schema
identifier (`ctfgen.challenge-spec`), `check_compatible` rejects an unknown major, and
`migrate` upgrades older documents forward at load. The AI-resistance heuristic's bands
and dimension weights (`score.py`) remain **not stable** and are labeled Experimental.
