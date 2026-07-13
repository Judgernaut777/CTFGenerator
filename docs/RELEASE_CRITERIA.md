# Release Criteria

Milestone 1 deliverable. Defines, per release stage, the **required capabilities** that must ship and the **security release gates / release blockers** that must all clear before the stage can be tagged. Also defines entry/exit checklists for the **internal-alpha** and **closed-beta** gates.

- Every criterion is a checkbox. A stage is releasable only when **all** its capability boxes and **all** applicable security gate boxes are checked.
- **Reconciliation (2026-07-13):** milestones M6–M18 have **implemented** most of the v0.1→v0.4 capability scope — the layered platform, PostgreSQL persistence, control-plane API, auth/RBAC + OIDC, organizer + contestant web, isolated worker + PG job queue, evaluation lab, audit/observability, backup/DR tooling, and the supported deploy stack. The boxes below, however, track **formal release-gate sign-off** (each capability verified and each security gate cleared for a tagged release), which is the job of the M20–M22 validation/qualification program. They therefore remain **unchecked**: implemented ≠ release-qualified. Where a capability is now built, it is noted inline rather than by ticking the box.
- "Current" (in this doc) means the M6+ platform codebase as of 2026-07-13; the generator core remains pure-Python/stdlib. Release stages and their scope come from the productization plan's stable facts.
- **M20 validation evidence:** the executed-evidence artifacts that the M22 qualification pass will adjudicate these gates against now live under [`validation/`](validation/README.md) — the recovery drill (RTO), the security-gate → test map (S1–S9), the deterministic-conformance suite, the full-stack e2e flow, coverage measurement, the capacity smoke, and the honest AI-resistance report. Producing this evidence is M20; ticking the boxes below remains M22.

---

## 0. Baseline (current, 2026-07-11)

For reference — what exists today and is the foundation the stages build on.

- [x] Deterministic generator + static validator (`generator.create_challenge`, `validator.validate_challenge`), pure/stdlib core
- [x] Runtime, sibling, and replay validation via Docker (`runtime_validator`, `sibling_validator`, `replay_validator`) — **CLI-only**
- [x] Scoring subsystem (`score.py`, `scoring_engine.py`, `scoreboard.py`) and event log (`events.py`, optional `postgres_events.py`)
- [x] Stdlib `http.server` dashboard (`dashboard_server.py`, `dashboard_ui.py`) via `ctfgen serve`
- [x] MCP server exposing pure/deterministic tools only (`mcp_server.py`); never imports `runtime_validator`/`scenario_runtime`/`agent_eval`/`subprocess`
- [x] 8 families across 8 domains; red/blue/purple modes; CVE sourcing (snapshot + NVD)
- [x] Host unit suite green (grown from the original 709 to the M6+ platform's host + Docker-gated PostgreSQL integration suites)

Several original baseline gaps have since been **closed** by M4–M18: schema versioning is enforced (`schema.py` — identifier + `check_compatible` + `migrate`, no longer write-only stamps); execution now runs on isolated workers driven by the control plane over the PG job queue (the host-executing CLI helpers remain author-side tools); the control plane is an ASGI (FastAPI) app with real auth/RBAC + OIDC (TLS termination is the reverse proxy's job). The residual gaps this document still tracks toward v1.0 are the **verification** ones: formal security-gate sign-off, the recovery drill (RPO/RTO), capacity testing, and rootless worker runtime on the deployment host (capability-gated today).

---

## Security release gates (apply to every stage)

These are the standing **release blockers**. No stage may be tagged with any of these unresolved. The applicability column notes the earliest stage each becomes enforceable given the plane it protects.

| # | Gate (blocker if unresolved) | Enforceable from |
|---|---|---|
| S1 | No unresolved **critical or high authz failures** (one team cannot access another team's instance; role checks on every privileged action) | v0.3-alpha |
| S2 | No **container escape** from a challenge workload to the worker host or beyond | v0.2-alpha |
| S3 | No **cross-team access** (instance, submission, or data of one team reachable by another) | v0.3-alpha |
| S4 | No **flag leakage** — flags never in public artifacts, never served to contestants, only reachable by exploiting the service | v0.1-alpha |
| S5 | No **secret leakage** — flags, session tokens, and provider/API keys NEVER logged or emitted in reports/artifacts | v0.1-alpha |
| S6 | **Destructive path handling** safe — generated paths cannot escape the build dir; `force=True` recursive delete constrained to the sandboxed workspace root | v0.1-alpha |
| S7 | No **unauthenticated admin endpoints** — every admin/control-plane mutation requires authentication and authorization | v0.3-alpha |
| S8 | No **unrecoverable DB corruption** path — migrations reversible/tested; scoreboards reconstructable from persisted score events; backup/restore verified | v0.3-alpha |
| S9 | **Control plane never executes generated challenge code and never mounts the Docker socket** (highest-priority boundary) | v0.2-alpha |

Notes grounding S4/S5/S6 in current behavior: the trust boundary already keeps the flag out of `public/` (injected at runtime via `${CTFGEN_FLAG:-}`), and `score.py` integrity gates force `band = "weak"` on an embedded/leaked flag; the MCP `_resolve_in_workspace` sandbox already blocks `..`/absolute-outside writes and constrains the `force`/`rmtree` primitive. These are the seeds the stage gates harden into hard blockers.

---

## v0.1-alpha — Reliable generator

Scope: CI, filesystem hardening, deterministic generation, schema versioning, family SDK, quality gates, release artifacts.

### Required capabilities

- [ ] CI pipeline runs unit tests + `compileall` + Docker validation on every change
- [ ] Deterministic generation invariant enforced: identical (generator version, spec, family version, seed) => byte-identical artifacts (**partly current** — generation is deterministic; needs an explicit rebuild-equality check)
- [ ] Filesystem hardening: generated paths provably cannot escape the build dir; atomic build output; `force` delete constrained (**partly current** via MCP `_resolve_in_workspace`; extend to all write paths)
- [ ] Schema versioning that is **read and enforced**, not a write-only stamp — spec/report/variant carry a version and a migration/compat check exists (**target**; today `SPEC_VERSION`/`SCHEMA_VERSION` are advisory only, no consumer reads them)
- [ ] Family SDK: documented, structural family/plugin interface (replaces the convention-only "templates must not import `families`" contract)
- [ ] Quality gates codified (static validation, sibling uniqueness, score thresholds) as blocking checks
- [ ] Reproducible release artifacts published (installable `ctfgen`, versioned)

### Security release gates

- [ ] **S4** flag leakage — validator/score confirm no flag in `public/` or in the served bundle
- [ ] **S5** secret leakage — no flag/token/provider-key in logs, reports, or artifacts
- [ ] **S6** destructive path handling — path-escape and `force`-delete containment verified by tests

---

## v0.2-alpha — Isolated execution

Scope: worker protocol, job system, rootless runtime, resource limits, instance lifecycle, reconciliation.

### Required capabilities

- [ ] Worker protocol defined: explicit job-result contract; workers never modify competition-domain state directly (**target**; today `runtime_validator._run` is called inline from validators/`agent_eval`/`scenario_runtime`)
- [ ] PostgreSQL-backed job system: job rows with `FOR UPDATE SKIP LOCKED`, leases, heartbeats, retries, idempotency keys, dead-letter (no Redis)
- [ ] Rootless Docker/Podman + rootless BuildKit runtime on isolated workers
- [ ] Resource enforcement (mem/pids/cpu) and network isolation for instances (**partly current** — compose renders `no-new-privileges`, `cap_drop: [ALL]`, `mem_limit`, `pids_limit`, `internal: true` networks)
- [ ] Instance lifecycle: build, launch, health check, expiration, cleanup; reconciliation of orphaned instances
- [ ] Untrusted bundle code (`solver.py`/`healthcheck.py`) runs **only** inside isolated workers, never on host by default (**target**; today host execution is the default and `--sandbox` is opt-in)

### Security release gates

- [ ] **S2** container escape — isolation verified; no workload breakout to worker host
- [ ] **S9** control plane never executes challenge code / never mounts Docker socket — execution confined to isolated workers
- [ ] **S4**, **S5**, **S6** remain green

---

## v0.3-alpha — Persistent control plane

Scope: PostgreSQL domain model, migrations, production API, authz, immutable versions, submissions, score events.

### Required capabilities

- [ ] PostgreSQL domain model (SQLAlchemy 2.x + Alembic migrations)
- [ ] Production ASGI API (FastAPI or comparable); CLI and API share the same application services
- [ ] AuthN/AuthZ across the eight roles (owner, operator, event admin, author, reviewer, team captain, contestant, observer)
- [ ] Immutable, content-addressed published versions (published artifacts never mutate)
- [ ] Submission handling: a correct submission creates **at most one** solve per (team, challenge, competition)
- [ ] Persisted score events; scoreboards reconstructable from them; admin score changes require an explicit reason
- [ ] Audit trail: every privileged state change is auditable

### Security release gates

- [ ] **S1** no critical/high authz failures
- [ ] **S3** no cross-team access to instances/submissions/data
- [ ] **S7** no unauthenticated admin endpoints
- [ ] **S8** no unrecoverable DB corruption — migrations tested/reversible, scoreboard reconstructable, backup/restore verified
- [ ] **S9** control-plane boundary holds under the new API surface
- [ ] **S2**, **S4**, **S5**, **S6** remain green

---

## v0.4-beta — Complete workflow

Scope: admin UI, contestant portal, live ops, reports, deployment.

### Required capabilities

- [ ] Admin/organizer web UI (Author Studio + Competition Control Plane surfaces)
- [ ] Contestant portal (challenge access, submission, scoreboard; private solvers never served)
- [ ] Live-ops: instance orchestration, health, scoreboard feed under load
- [ ] Reports (validation, scoring, run reports) surfaced through the UI/API
- [ ] Supported single-path deployment: reverse proxy + TLS, PostgreSQL, isolated worker host(s), local-FS or S3-compatible artifact storage
- [ ] One end-to-end organizer + contestant workflow fully wired (highest-priority objective)

### Operating targets to demonstrate

- [ ] 25 concurrent teams; 20 active challenges
- [ ] >=99% instance launch success; scoreboard update <3s; submission processing <500ms server-side

### Security release gates

- [ ] **All S1–S9 green** under the full UI/API/worker deployment
- [ ] Zero public flag leakage confirmed end-to-end (S4/S5)
- [ ] TLS-terminated ingress; session cookies secured (supersedes current plain-HTTP `serve`)

---

## v0.5-beta — Quality + evaluation

Scope: Evaluation Lab productization (agent baselines, generalization, difficulty analysis, quality reports).

### Required capabilities

- [ ] Scripted + adaptive agent baselines run as managed jobs on isolated workers (`agent_eval` productized)
- [ ] Cross-seed / cross-family generalization measurement (sibling/replay + agent eval)
- [ ] Human benchmark ingestion and difficulty analysis
- [ ] Quality reports integrated into Author Studio review/approval flow

### Security release gates

- [ ] Evaluation workloads run only on isolated workers (**S2**, **S9**)
- [ ] Provider/API keys used by eval never logged (**S5**)
- [ ] **All S1–S9 remain green**

---

## v1.0 — Production

Scope: external security review, recovery drill, upgrade/capacity testing, four production-quality categories.

### Required capabilities

- [ ] External security review completed; findings resolved (no open critical/high)
- [ ] Recovery drill executed: RPO 5min, RTO 30min demonstrated
- [ ] Upgrade path tested (schema migration + artifact compatibility across versions)
- [ ] Capacity testing at the operating targets sustained
- [ ] Four production-quality challenge categories (not dozens of shallow ones)

### Security release gates (all must be green; any unresolved = release blocker)

- [ ] **S1** no unresolved critical/high authz failures
- [ ] **S2** no container escape
- [ ] **S3** no cross-team access
- [ ] **S4** no flag leakage (zero public flag leakage target met)
- [ ] **S5** no secret leakage (flags/tokens/provider-keys)
- [ ] **S6** destructive path handling safe
- [ ] **S7** no unauthenticated admin endpoints
- [ ] **S8** no unrecoverable DB corruption (recovery drill passed)
- [ ] **S9** control plane never executes challenge code / never mounts Docker socket
- [ ] Zero deterministic-rebuild failures confirmed at release

---

## Internal-alpha gate (checklists)

Purpose: first internal-only exercise of the isolated-execution + control-plane spine (roughly the v0.2–v0.3 boundary). Internal operators only; no external contestants.

### Entry criteria

- [ ] v0.1-alpha capabilities complete; CI green
- [ ] Security gates **S4**, **S5**, **S6** green
- [ ] Worker protocol + job system available in a test deployment (v0.2-alpha)
- [ ] Bundle code executes only on isolated workers, never on the control-plane host
- [ ] Test PostgreSQL instance with migrations applied
- [ ] Named internal operators and a rollback plan

### Exit criteria

- [ ] One challenge generated, published (immutable/content-addressed), launched on a worker, solved via intended solver, scored, and shown on a scoreboard — end to end
- [ ] **S2** (container escape) and **S9** (control-plane boundary / no Docker socket) verified in this deployment
- [ ] No critical/high authz finding (**S1**) in the exercised surface
- [ ] Instance lifecycle proven: launch, health check, expiration, cleanup, reconciliation of an orphaned instance
- [ ] Flags/tokens/provider-keys absent from all logs and reports (**S5**)
- [ ] Findings triaged; blockers fixed or explicitly deferred with owner

---

## Closed-beta gate (checklists)

Purpose: first run with real external organizers + contestants on a supported single-path deployment (roughly v0.4-beta). Invitation-only.

### Entry criteria

- [ ] Internal-alpha exit criteria all met
- [ ] v0.4-beta capabilities complete: admin UI + contestant portal + live ops + reports
- [ ] Supported deployment stood up: reverse proxy + TLS, PostgreSQL, isolated worker(s), artifact storage (local-FS or S3-compatible)
- [ ] **All S1–S9 green** in the beta deployment
- [ ] Backup/restore tested; RPO/RTO plan in place (**S8**)
- [ ] Private solvers confirmed non-served; contestants scoped to their own team's instances (**S3**)
- [ ] Incident-response and rollback runbook ready

### Exit criteria

- [ ] A real competition run at target scale: 25 concurrent teams, 20 active challenges
- [ ] >=99% instance launch success; scoreboard update <3s; submission processing <500ms server-side sustained
- [ ] At-most-one solve per (team, challenge, competition) held under real submissions
- [ ] Scoreboard reconstructed from persisted score events and matched live state
- [ ] Zero public flag leakage and zero deterministic-rebuild failures observed
- [ ] No unresolved critical/high security finding across **S1–S9**
- [ ] Recovery drill (RPO 5min / RTO 30min) rehearsed at least once
- [ ] Beta findings logged and gated into the v1.0 external-review scope
