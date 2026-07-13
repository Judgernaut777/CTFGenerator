# Release Criteria

Milestone 1 deliverable. Defines, per release stage, the **required capabilities** that must ship and the **security release gates / release blockers** that must all clear before the stage can be tagged. Also defines entry/exit checklists for the **internal-alpha** and **closed-beta** gates.

- Every criterion is a checkbox. A stage is releasable only when **all** its capability boxes and **all** applicable security gate boxes are checked.
- **Reconciliation (2026-07-13):** milestones M6–M18 have **implemented** most of the v0.1→v0.4 capability scope — the layered platform, PostgreSQL persistence, control-plane API, auth/RBAC + OIDC, organizer + contestant web, isolated worker + PG job queue, evaluation lab, audit/observability, backup/DR tooling, and the supported deploy stack. The boxes track **formal release-gate sign-off** (each capability verified and each security gate cleared), which is the job of the M20–M22 validation/qualification program. Implemented ≠ release-qualified.
- **M22 sign-off pass (2026-07-13 — this reconciliation):** the capstone qualification pass has now run. Boxes are ticked **only** where a specific executed, re-runnable artifact directly proves them, with an inline evidence cite (host tests, or `integration-gated` tests run against the M22 host's live PostgreSQL @`172.20.0.2:5432` + Docker). Everything ticked was re-executed here: 184 host tests OK (conformance/security/SDK) and 118 PG-integration tests OK (authz/submission/instance-lifecycle/ledger/restore/migration-drift/publications/worker). Every remaining box is left **unchecked** with an inline `(UNVERIFIED: …)` reason — production-scale capacity (25 teams / 20 challenges / ≥99% launch / sustained <3s/<500ms; in-process 25×20 submission p95 measured **over target ≈2050 ms**), a real TLS/multi-host deployment, a real external closed beta, the distributed-worker bundle-launch flow (`build_challenge` unbuilt), continuous RPO/PITR (only baseline RPO + measured RTO exist), and an external security review. **The OVERALL v1.0 gate is NOT met.** The authoritative adjudication — every QUALIFIED verdict, its artifact, and every NOT-QUALIFIED gap — is [`RELEASE_QUALIFICATION.md`](RELEASE_QUALIFICATION.md).
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

- [x] CI pipeline runs unit tests + `compileall` + Docker validation on every change — `.github/workflows/pr.yml`; host suite green (184 host tests OK, M22)
- [x] Deterministic generation invariant enforced: identical (generator version, spec, family version, seed) => byte-identical artifacts — `test_conformance_suite` (host; `test_same_seed_produces_byte_identical_tree_and_provenance` + no-wall-clock-in-provenance, 52 OK)
- [x] Filesystem hardening: generated paths provably cannot escape the build dir; atomic build output; `force` delete constrained — `test_build_hardening` + `test_mcp_server` (host, S6; M3 routes all entry points through `build.py`)
- [x] Schema versioning that is **read and enforced**, not a write-only stamp — spec/report/variant carry a version and a migration/compat check exists — `test_schema_versioning` (host; M4 `schema.py` `check_compatible`/`migrate`)
- [x] Family SDK: documented, structural family/plugin interface (replaces the convention-only "templates must not import `families`" contract) — `test_sdk_plugins`/`test_sdk_facade`/`test_sdk_lint` (host; M14 `sdk/`)
- [x] Quality gates codified (static validation, sibling uniqueness, score thresholds) as blocking checks — `test_conformance_suite` (aggregates sibling/replay/schema/baseline, host) + `test_score` integrity demotion (host); run in `pr.yml`
- [ ] Reproducible release artifacts published (installable `ctfgen`, versioned) (UNVERIFIED: reproducible-build byte-equality is proven by `test_baseline_fixtures`, but the **publish** step — a versioned installable pushed to an index — is a release action with no executed artifact in the evidence base)

### Security release gates

- [x] **S4** flag leakage — validator/score confirm no flag in `public/` or in the served bundle — `test_public_flag_leak` + `test_score` integrity demotion (host)
- [x] **S5** secret leakage — no flag/token/provider-key in logs, reports, or artifacts — `test_logging_redaction` (host)
- [x] **S6** destructive path handling — path-escape and `force`-delete containment verified by tests — `test_build_hardening` + `test_mcp_server` (host)

---

## v0.2-alpha — Isolated execution

Scope: worker protocol, job system, rootless runtime, resource limits, instance lifecycle, reconciliation.

### Required capabilities

- [x] Worker protocol defined: explicit job-result contract; workers never modify competition-domain state directly — `test_worker_job_service_integration` + `test_worker_loop_integration` (integration-gated; M7 supersedes the inline-`_run` state noted below)
- [x] PostgreSQL-backed job system: job rows with `FOR UPDATE SKIP LOCKED`, leases, heartbeats, retries, idempotency keys, dead-letter (no Redis) — `test_worker_job_service_integration` + `test_worker_repository_integration` (integration-gated)
- [ ] Rootless Docker/Podman + rootless BuildKit runtime on isolated workers (UNVERIFIED: rootless/userns/BuildKit is capability-gated on this rootful arm64 host — `docs/security/runtime-isolation.md`; the per-container hardening is enforced/asserted but the rootless outer layer is not exercisable here)
- [x] Resource enforcement (mem/pids/cpu) and network isolation for instances — `test_docker_backend_integration` (strict policy, all caps dropped, noexec tmpfs) + `test_team_isolation_integration` (network isolation) (integration-gated, Docker + host-block firewall)
- [x] Instance lifecycle: build, launch, health check, expiration, cleanup; reconciliation of orphaned instances — `test_instance_lifecycle_integration` (reserve→launch, expiry release, reconciler drift incl. orphaned endpoint) + `test_docker_backend_integration` (health + `destroy` leaves nothing) (integration-gated)
- [ ] Untrusted bundle code (`solver.py`/`healthcheck.py`) runs **only** inside isolated workers, never on host by default (UNVERIFIED: the **control plane** never executing bundle code is proven by S9, but the distributed-worker bundle-launch flow is UNBUILT — `build_challenge`; author-side host execution is still the default, `--sandbox` opt-in)

### Security release gates

- [x] **S2** container escape — isolation verified; no workload breakout to worker host — `test_docker_backend_integration` + `test_team_isolation_integration` (integration-gated, Docker + host-block firewall)
- [x] **S9** control plane never executes challenge code / never mounts Docker socket — execution confined to isolated workers — `test_mcp_server` + `test_architecture_boundaries` (host, static) + `test_docker_backend_integration` (integration-gated, runtime)
- [x] **S4**, **S5**, **S6** remain green — `test_public_flag_leak` / `test_logging_redaction` / `test_build_hardening` (host)

---

## v0.3-alpha — Persistent control plane

Scope: PostgreSQL domain model, migrations, production API, authz, immutable versions, submissions, score events.

### Required capabilities

- [x] PostgreSQL domain model (SQLAlchemy 2.x + Alembic migrations) — `test_competition_repository_integration` + `test_migration_drift_integration` (no autogenerate drift; clean full downgrade) (integration-gated)
- [x] Production ASGI API (FastAPI or comparable); CLI and API share the same application services — `test_api_*_integration` (authz/auth/instances/publications/submissions) + `test_e2e_flow_integration` (integration-gated)
- [x] AuthN/AuthZ across the eight roles (owner, operator, event admin, author, reviewer, team captain, contestant, observer) — `test_api_authz_scoping_integration` + `test_api_auth_integration` (integration-gated)
- [x] Immutable, content-addressed published versions (published artifacts never mutate) — `test_api_publications_integration` + `alpha_sim` `published_content_addressed_immutable` invariant (integration-gated)
- [x] Submission handling: a correct submission creates **at most one** solve per (team, challenge, competition) — `test_submission_processing_integration` (solved-by-construction) + e2e/alpha_sim exactly-one-solve (integration-gated)
- [x] Persisted score events; scoreboards reconstructable from them — `test_score_projection_integration` (outbox refold) + `test_restore_verify_integration` scoreboard parity (integration-gated). **(The "admin score changes require an explicit reason" sub-clause is UNVERIFIED — no executed test of a reason-required admin score adjustment exists; generic audit-reason round-tripping is covered separately by `test_audit_repository_integration`.)**
- [x] Audit trail: every privileged state change is auditable — `test_audit_repository_integration` + `test_api_audit_integration` + `test_ledger_repository_integration` (append-only trigger) (integration-gated)

### Security release gates

- [x] **S1** no critical/high authz failures — `test_api_authz_scoping_integration` + `test_api_instances_integration` (integration-gated)
- [x] **S3** no cross-team access to instances/submissions/data — `test_api_authz_scoping_integration` + `test_team_isolation_integration` (integration-gated)
- [x] **S7** no unauthenticated admin endpoints — `test_api_auth_integration` + `test_api_instances_integration` + `test_web_security` (integration-gated)
- [x] **S8** no unrecoverable DB corruption — migrations tested/reversible, scoreboard reconstructable, backup/restore verified — `test_migration_drift_integration` + `test_ledger_repository_integration` + `test_restore_verify_integration` (integration-gated; restore round-trip also needs `pg_dump`/`pg_restore`)
- [x] **S9** control-plane boundary holds under the new API surface — `test_mcp_server` + `test_architecture_boundaries` (host) + `test_docker_backend_integration` (integration-gated)
- [x] **S2**, **S4**, **S5**, **S6** remain green — `test_docker_backend_integration`/`test_team_isolation_integration` (integration-gated) + `test_public_flag_leak`/`test_logging_redaction`/`test_build_hardening` (host)

---

## v0.4-beta — Complete workflow

Scope: admin UI, contestant portal, live ops, reports, deployment.

### Required capabilities

- [x] Admin/organizer web UI (Author Studio + Competition Control Plane surfaces) — `test_web_competition_write_integration`/`test_web_publication_write_integration`/`test_web_instances_ops_integration`/`test_web_jobs_ops_integration` (integration-gated)
- [x] Contestant portal (challenge access, submission, scoreboard; private solvers never served) — `test_web_contestant_reads_integration`/`test_web_contestant_submit_integration`/`test_web_contestant_download_integration` + `test_public_flag_leak` (integration-gated + host)
- [ ] Live-ops: instance orchestration, health, scoreboard feed under load (UNVERIFIED: orchestration/health surfaces are exercised by `test_web_instances_ops_integration`, but the **under-load** claim is production-scale — only smoke-scale ran, `validation/capacity.md`)
- [ ] Reports (validation, scoring, run reports) surfaced through the UI/API (UNVERIFIED: scoring/scoreboard surfaces are tested (`test_web_scoreboard_view_integration`/`test_api_scoreboard_integration`), but the full validation+run-report surface has no single executed report test in the evidence base)
- [ ] Supported single-path deployment: reverse proxy + TLS, PostgreSQL, isolated worker host(s), local-FS or S3-compatible artifact storage (UNVERIFIED: no real reverse-proxy + TLS deployment was stood up on this host — v1.0 blocker)
- [ ] One end-to-end organizer + contestant workflow fully wired (highest-priority objective) (UNVERIFIED: the submit→score→scoreboard spine is proven over real PG (`test_e2e_flow_integration`), but the joined flow that **launches the published bundle on a worker** is UNBUILT — `build_challenge`; composite, not one unbroken flow)

### Operating targets to demonstrate

- [ ] 25 concurrent teams; 20 active challenges (UNVERIFIED: production scale; only smoke-scale executed — `validation/capacity.md`)
- [ ] >=99% instance launch success; scoreboard update <3s; submission processing <500ms server-side (UNVERIFIED: at the 25×20 target scale in-process submission p95 measured **over target ≈2050 ms** (`validation/capacity.md`); scoreboard smoke within target; **≥99% launch success has no evidence** — `build_challenge` unbuilt)

### Security release gates

- [ ] **All S1–S9 green** under the full UI/API/worker deployment (UNVERIFIED: S1–S9 are green in the PG/Docker integration env — see v0.3 — but the production-deployment sweep under a TLS reverse proxy + real fleet was not run)
- [x] Zero public flag leakage confirmed end-to-end (S4/S5) — `test_public_flag_leak` + `test_logging_redaction` (host) + `test_conformance_suite` byte-stability
- [ ] TLS-terminated ingress; session cookies secured (supersedes current plain-HTTP `serve`) (UNVERIFIED: no real TLS ingress stood up on this host — v1.0 blocker)

---

## v0.5-beta — Quality + evaluation

Scope: Evaluation Lab productization (agent baselines, generalization, difficulty analysis, quality reports).

### Required capabilities

- [ ] Scripted + adaptive agent baselines run as managed jobs on isolated workers (`agent_eval` productized) (UNVERIFIED: the eval job path is exercised (`test_eval_runner_integration`/`test_eval_run_service_integration`), but **adaptive/LLM** eval and the distributed run are UNVERIFIED — `validation/ai-resistance.md`)
- [ ] Cross-seed / cross-family generalization measurement (sibling/replay + agent eval) (UNVERIFIED: cross-seed replay/sibling uniqueness is proven (`test_conformance_suite`), but generalization **measurement via agent eval** is UNVERIFIED — `validation/ai-resistance.md`)
- [ ] Human benchmark ingestion and difficulty analysis (UNVERIFIED: no executed artifact for human-benchmark ingestion in the evidence base)
- [ ] Quality reports integrated into Author Studio review/approval flow (UNVERIFIED: no executed artifact wiring quality reports into the review/approval flow in the evidence base)

### Security release gates

- [x] Evaluation workloads run only on isolated workers (**S2**, **S9**) — `test_eval_run_service_integration` (`EvalRun` enqueued PENDING, never run on the control plane) + S9 boundary `test_mcp_server`/`test_architecture_boundaries` (host) + S2 `test_docker_backend_integration` (integration-gated)
- [x] Provider/API keys used by eval never logged (**S5**) — `test_logging_redaction` (host; redacts every secret class incl. provider keys)
- [x] **All S1–S9 remain green** — S4/S5/S6/S9-static host + S1/S2/S3/S7/S8/S9-runtime integration-gated (see v0.3 cites)

---

## v1.0 — Production

Scope: external security review, recovery drill, upgrade/capacity testing, four production-quality categories.

### Required capabilities

- [ ] External security review completed; findings resolved (no open critical/high) (UNVERIFIED: all S1–S9 evidence here is self-run; an independent external security assessment is out of scope and required before v1.0 — v1.0 blocker)
- [ ] Recovery drill executed: RPO 5min, RTO 30min demonstrated (UNVERIFIED: **RTO** was rehearsed vs live PG (`recovery_drill.sh` + `test_recovery_drill_integration`), but continuous **RPO ≤5 min** is UNVERIFIED — no WAL archiving/PITR on this host)
- [x] Upgrade path tested (schema migration + artifact compatibility across versions) — `test_migration_drift_integration` (0001→0014 no autogenerate drift; clean full downgrade) + `test_schema_versioning` (spec/manifest compat + `migrate`) (integration-gated + host)
- [ ] Capacity testing at the operating targets sustained (UNVERIFIED: only smoke-scale executed; 25×20 submission p95 measured **over target ≈2050 ms** — `validation/capacity.md` — v1.0 blocker)
- [ ] Four production-quality challenge categories (not dozens of shallow ones) (UNVERIFIED: 8 deterministic families ship, but the "production-quality" curation bar is not adjudicated by an executed artifact)

### Security release gates (all must be green; any unresolved = release blocker)

- [ ] **S1** no unresolved critical/high authz failures (UNVERIFIED at v1.0: proven at integration scale (`test_api_authz_scoping_integration`, see v0.3), but the **production-deployment** sweep under TLS/real fleet + external review is a v1.0 blocker — `RELEASE_QUALIFICATION.md`)
- [ ] **S2** no container escape (UNVERIFIED at v1.0: proven at integration scale (`test_docker_backend_integration`/`test_team_isolation_integration`, see v0.3); production-deployment sweep + rootless outer layer UNVERIFIED)
- [ ] **S3** no cross-team access (UNVERIFIED at v1.0: proven at integration scale (see v0.3); production-deployment sweep UNVERIFIED)
- [ ] **S4** no flag leakage (zero public flag leakage target met) (UNVERIFIED at v1.0: proven on host (`test_public_flag_leak`); full production end-to-end sweep UNVERIFIED)
- [ ] **S5** no secret leakage (flags/tokens/provider-keys) (UNVERIFIED at v1.0: proven on host (`test_logging_redaction`); full production sweep UNVERIFIED)
- [ ] **S6** destructive path handling safe (UNVERIFIED at v1.0: proven on host (`test_build_hardening`); production sweep UNVERIFIED)
- [ ] **S7** no unauthenticated admin endpoints (UNVERIFIED at v1.0: proven at integration scale (see v0.3); production-deployment sweep UNVERIFIED)
- [ ] **S8** no unrecoverable DB corruption (recovery drill passed) (UNVERIFIED at v1.0: migrations/restore/reconstruction proven (see v0.3) + RTO drill executed, but continuous **RPO** UNVERIFIED — no WAL/PITR)
- [ ] **S9** control plane never executes challenge code / never mounts Docker socket (UNVERIFIED at v1.0: proven host+integration (see v0.3); production-deployment sweep UNVERIFIED)
- [x] Zero deterministic-rebuild failures confirmed at release — `test_conformance_suite` (host; byte-identical rebuild + baseline goldens, 52 OK)

---

## Internal-alpha gate (checklists)

Purpose: first internal-only exercise of the isolated-execution + control-plane spine (roughly the v0.2–v0.3 boundary). Internal operators only; no external contestants.

### Entry criteria

- [ ] v0.1-alpha capabilities complete; CI green (UNVERIFIED: CI is green (`pr.yml`), but formal per-capability v0.1 sign-off is incomplete — the "release artifacts published" box remains unchecked)
- [x] Security gates **S4**, **S5**, **S6** green — `test_public_flag_leak`/`test_logging_redaction`/`test_build_hardening` (host)
- [x] Worker protocol + job system available in a test deployment (v0.2-alpha) — `test_worker_job_service_integration`/`test_worker_repository_integration`/`test_worker_loop_integration` (integration-gated)
- [x] Bundle code executes only on isolated workers, never on the control-plane host — S9 boundary `test_mcp_server`/`test_architecture_boundaries` (host; no `subprocess`/`docker`/`runtime_validator`, never mounts the Docker socket)
- [x] Test PostgreSQL instance with migrations applied — `alpha_sim.py`/`test_migration_drift_integration` (fresh DB, `alembic upgrade head` 0001→0014 vs live PG) (integration-gated)
- [ ] Named internal operators and a rollback plan (UNVERIFIED: the sim authenticates a named operator, but named-operator designation + rollback-runbook adoption is an operational sign-off, not an executed artifact)

### Exit criteria

- [ ] One challenge generated, published (immutable/content-addressed), launched on a worker, solved via intended solver, scored, and shown on a scoreboard — end to end (UNVERIFIED: composite — Half A generate→publish→submit→solve→score→scoreboard is proven over real PG (`alpha_sim.py`/`test_alpha_sim_integration`, **launches nothing**) and Half B real container launch+isolation is proven (`test_docker_backend_integration`, **benign image, not the bundle**); the **joined bundle-launch flow is UNVERIFIED** — `build_challenge` unbuilt)
- [x] **S2** (container escape) and **S9** (control-plane boundary / no Docker socket) verified in this deployment — `test_docker_backend_integration`/`test_team_isolation_integration` (integration-gated) + `test_mcp_server`/`test_architecture_boundaries` (host)
- [x] No critical/high authz finding (**S1**) in the exercised surface — `test_api_authz_scoping_integration` (integration-gated)
- [x] Instance lifecycle proven: launch, health check, expiration, cleanup, reconciliation of an orphaned instance — `test_instance_lifecycle_integration` + `test_docker_backend_integration` (integration-gated)
- [x] Flags/tokens/provider-keys absent from all logs and reports (**S5**) — `test_logging_redaction` (host) + `test_alpha_sim_integration` first-party sim-log scan (integration-gated)
- [x] Findings triaged; blockers fixed or explicitly deferred with owner — `validation/internal-alpha-report.md` Findings table (A-1/A-2 deferred with owner)

---

## Closed-beta gate (checklists)

Purpose: first run with real external organizers + contestants on a supported single-path deployment (roughly v0.4-beta). Invitation-only.

### Entry criteria

- [ ] Internal-alpha exit criteria all met (UNVERIFIED: the internal-alpha exit composite X1 — joined bundle-launch on a worker — is UNVERIFIED (`build_challenge` unbuilt); the other alpha exit items are met)
- [ ] v0.4-beta capabilities complete: admin UI + contestant portal + live ops + reports (UNVERIFIED: admin UI + contestant portal are exercised by web integration tests, but "live ops under load" and the full report surface are UNVERIFIED — see v0.4-beta)
- [ ] Supported deployment stood up: reverse proxy + TLS, PostgreSQL, isolated worker(s), artifact storage (local-FS or S3-compatible) (UNVERIFIED: no real reverse-proxy + TLS deployment was stood up — v1.0 blocker)
- [ ] **All S1–S9 green** in the beta deployment (UNVERIFIED: S1–S9 are green in the PG/Docker integration env, but the production **beta-deployment** sweep under TLS/real fleet was not run)
- [ ] Backup/restore tested; RPO/RTO plan in place (**S8**) (UNVERIFIED: backup/restore round-trip + RTO drill executed (`test_restore_verify_integration`/`recovery_drill.sh`), but continuous **RPO ≤5 min** is not in place — no WAL/PITR)
- [x] Private solvers confirmed non-served; contestants scoped to their own team's instances (**S3**) — `test_public_flag_leak` (host) + `test_api_authz_scoping_integration`/`test_team_isolation_integration` (integration-gated)
- [ ] Incident-response and rollback runbook ready (UNVERIFIED: runbooks exist in `docs/operations/`, but rehearsal/readiness is a process sign-off, not an executed test)

### Exit criteria

- [ ] A real competition run at target scale: 25 concurrent teams, 20 active challenges (UNVERIFIED: production scale; only smoke-scale executed — `validation/capacity.md`)
- [ ] >=99% instance launch success; scoreboard update <3s; submission processing <500ms server-side sustained (UNVERIFIED: 25×20 submission p95 measured **over target ≈2050 ms** in-process; scoreboard smoke within target; **≥99% launch success has no evidence** — `build_challenge` unbuilt)
- [x] At-most-one solve per (team, challenge, competition) held under real submissions — `test_submission_processing_integration` (solved-by-construction) + `test_alpha_sim_integration` exactly-one-solve (integration-gated; at simulation scale)
- [x] Scoreboard reconstructed from persisted score events and matched live state — `test_restore_verify_integration` scoreboard parity + `test_score_projection_integration` refold (integration-gated)
- [x] Zero public flag leakage and zero deterministic-rebuild failures observed — `test_public_flag_leak` (host) + `test_conformance_suite` byte-stability (host, 52 OK)
- [ ] No unresolved critical/high security finding across **S1–S9** (UNVERIFIED: none found in the executed integration surface, but the production-deployment S1–S9 sweep + external review are UNVERIFIED — v1.0 blockers)
- [x] Recovery drill (RPO 5min / RTO 30min) rehearsed at least once — `scripts/recovery_drill.sh` + `test_recovery_drill_integration` (RTO measured vs ≤30 min SLO, negative controls) (integration-gated; **RPO ≤5 min continuous is baseline-only / UNVERIFIED** — no WAL/PITR)
- [ ] Beta findings logged and gated into the v1.0 external-review scope (UNVERIFIED: requires a real external closed beta — none was run)
