# Consolidated gate-status matrix (M21)

The single at-a-glance readiness view for release sign-off, grounded **only** in
evidence executed on the M21 simulation host (single rootful arm64 box; Docker +
PostgreSQL @`172.20.0.2:5432` both real and available). It rolls up three
sources:

- the per-gate security mapping in [security-checklist.md](security-checklist.md)
  (the authoritative S1–S9 → test mapping; this doc does **not** redefine it),
- the internal-alpha per-item detail in
  [internal-alpha-report.md](internal-alpha-report.md),
- the closed-beta per-item detail in
  [closed-beta-report.md](closed-beta-report.md).

**This matrix is evidence for M22 to adjudicate. It does NOT tick any
`RELEASE_CRITERIA.md` box.** Formal sign-off is M22's job. Where evidence does
not exist or this host cannot produce it, the cell reads **UNVERIFIED** with a
reason — never a silent pass.

Status vocabulary:

- **PASS** — asserted by a host test that runs with no PostgreSQL/Docker/network.
- **GATED-PASS** — real assertions that PASS in the integration env (PG and/or
  Docker), executed on this host during M21; they SKIP in the default `pr.yml`
  host run. Re-runnable by anyone with the same env.
- **MET-by-sim** — the checklist item is demonstrated by an M21 simulation run or
  a reused M20 artifact, at simulation (single-host, sub-production) scale.
- **PARTIAL** — some sub-items met by evidence, others UNVERIFIED on this host.
- **UNVERIFIED** — no executed evidence here; the reason is stated. Not a failure
  claim — an honest gap for M22+.

---

## Security gates S1–S9

Each row cross-references [security-checklist.md](security-checklist.md) for the
exact test methods. The "M21 result" column is what actually executed on this
host during the M21 dry-run (test counts are the module-group runs, not per-gate).

| # | Guarantee | Executed test (see security-checklist.md) | Where it runs | M21 result |
|---|---|---|---|---|
| **S1** | No critical/high authz failure; role checks on every privileged action; no cross-competition action | `test_api_authz_scoping_integration`, `test_api_instances_integration` | PG-gated | **GATED-PASS** — ran here vs live PG (43 tests incl. auth/web, OK) |
| **S2** | No container escape from workload to worker host or beyond | `test_team_isolation_integration`, `test_docker_backend_integration` | Docker-gated (+ host-block firewall) | **GATED-PASS** — ran here w/ real container launch (20 tests, OK) |
| **S3** | No cross-team access (instance/submission/data) | `test_api_authz_scoping_integration` (API) + `test_team_isolation_integration` (network) | PG-gated + Docker-gated | **GATED-PASS** — both planes executed here (in the 43 + 20 runs, OK) |
| **S4** | No flag leakage — flags absent from public artifacts, not served to contestants | `test_public_flag_leak`, `test_score` (integrity demotion) | host | **PASS** — in host run (79 tests, OK) |
| **S5** | No secret leakage — flags/session tokens/API keys never logged or emitted | `test_logging_redaction` | host | **PASS** — in host run (79 tests, OK) |
| **S6** | Destructive path handling safe — no build-dir escape; `force`/rmtree constrained to sandbox root | `test_build_hardening`, `test_mcp_server` | host | **PASS** — in host run (79 tests, OK) |
| **S7** | No unauthenticated admin endpoints — every control-plane mutation needs authn + authz | `test_api_auth_integration`, `test_api_instances_integration`, `test_web_security` | PG-gated | **GATED-PASS** — ran here vs live PG (in the 43-test run, OK) |
| **S8** | No unrecoverable DB corruption — migrations reversible/tested; scoreboard reconstructable from score events; backup/restore verified; ledgers append-only | `test_ledger_repository_integration`, `test_restore_verify_integration`, `test_migration_drift_integration` | PG-gated (restore also needs `pg_dump`/`pg_restore`) | **GATED-PASS** — ran here vs live PG (38 tests, OK) |
| **S9** | Control plane never executes generated code / never mounts the Docker socket | `test_mcp_server`, `test_architecture_boundaries` (static) + `test_docker_backend_integration` (runtime) | host (static) + Docker-gated (runtime) | **PASS** (static, host run) + **GATED-PASS** (runtime, Docker run) |

Mapping integrity is itself guarded: `test_security_validation_meta` (host, 6
tests, OK here) fails if any cited module disappears or a gate drops out of the
checklist. **No S-gate is left without an executed test.** Every S1–S9 test/where-it-runs
claim above was substantiated by opening `security-checklist.md` and running the
cited modules on this host during M21 (self-verified; nothing marked UNKNOWN).

Standing UNVERIFIED caveats carried up from `security-checklist.md` (not host
gaps introduced here):

- **S2/S3 (network)** — the escape guarantee holds only where the host-block
  firewall capability is present; on a host lacking it the isolated launch
  refuses by design and the test SKIPS. Rootless/userns hardening remains
  capability-gated on this rootful arm64 host (`../security/runtime-isolation.md`).
- **S8 (backup/restore)** — round-trip additionally needs `pg_dump`/`pg_restore`;
  absent both, `test_restore_verify_integration` SKIPS.
- The Docker-gated escape tests demonstrate isolation of a **worker container**,
  not the published bundle launched by the real distributed build pipeline (see
  the v1.0 blockers below).

**Security S-gates verdict:** all nine substantiated by executed tests on this
host — S4/S5/S6/S9(static) PASS on the host, S1/S2/S3/S7/S8/S9(runtime)
GATED-PASS in the PG/Docker env. No S-gate is UNVERIFIED **on this host**; the
production-deployment S1–S9 sweep (TLS reverse proxy, real fleet, external scope)
is a separate v1.0 blocker below.

---

## Internal-alpha gate (summary)

Per-item evidence lives in
[internal-alpha-report.md](internal-alpha-report.md). Summary roll-up:

| Internal-alpha item | Status | Grounding |
|---|---|---|
| v0.1-alpha capabilities complete; CI green | **MET-by-sim** | host suite green; conformance 52 OK |
| Entry: S4/S5/S6 green | **PASS** | host security run (79 OK) |
| Entry: worker protocol + job system in a test deployment | **GATED-PASS** | instance-lifecycle + docker-backend integration executed here |
| Entry: bundle code runs only on isolated workers, never control-plane host | **PASS** (static) + **GATED-PASS** (runtime) | S9 static boundary + Docker runtime |
| Entry: test PostgreSQL with migrations applied | **GATED-PASS** | migration-drift + all PG integration ran vs live PG |
| Entry: named internal operators + rollback plan | **UNVERIFIED** | process/runbook artifact, not an executed test — see report |
| Exit: one challenge generated→published→launched→solved→scored→scoreboard, e2e | **MET-by-sim (composite; worker-launch of the published bundle UNVERIFIED)** | Half A: generate→publish→submit→solve→score→scoreboard over real PG (`test_e2e_flow_integration`, `alpha_sim.py` — scores the flag, **launches nothing**); Half B: real container launch + isolation (`test_docker_backend_integration`, benign image, **not the bundle**). Joined bundle-launch flow UNVERIFIED (`build_challenge` unbuilt) |
| Exit: S2 + S9 verified in this deployment | **GATED-PASS** | Docker escape + boundary tests (20 OK) |
| Exit: no critical/high authz (S1) in exercised surface | **GATED-PASS** | authz-scoping integration (in 43 OK) |
| Exit: instance lifecycle — launch/health/expiration/cleanup/reconciliation | **GATED-PASS** | `test_instance_lifecycle_integration` (in 34 OK) |
| Exit: flags/tokens/keys absent from logs+reports (S5) | **PASS** | `test_logging_redaction` (host) |
| Exit: findings triaged; blockers fixed or deferred with owner | **MET-by-sim** | recorded in report |

**Internal-alpha verdict: MET-by-simulation, with one PARTIAL** — every
technical exit criterion is backed by an executed test on this host at
simulation scale. The single non-technical entry item (named operators +
rollback plan) is **UNVERIFIED** as an executed artifact and is an
organizational, not a code, gap. Distinction from production: the e2e/alpha
spine launches **no** worker or instance — it scores a submitted flag over real
PG; the container-launch half is a **separate** Docker test using a benign image,
and the joined flow that launches the **published bundle** on a worker is
**UNVERIFIED** (`build_challenge` unbuilt — see blockers).

---

## Closed-beta gate (summary)

Per-item evidence lives in
[closed-beta-report.md](closed-beta-report.md). Summary roll-up:

| Closed-beta item | Status | Grounding |
|---|---|---|
| Entry: internal-alpha exit all met | **MET-by-sim** | rolls up the section above |
| Entry: v0.4-beta capabilities (admin UI + contestant portal + live ops + reports) | **MET-by-sim** | shipped M11–M16; exercised by suites, not by a live beta |
| Entry: supported deployment (reverse proxy + **TLS**, PG, isolated workers, artifact storage) | **UNVERIFIED** | no real TLS reverse proxy stood up on this host |
| Entry: **all S1–S9 green in the beta deployment** | **PARTIAL** | S1–S9 green here in the PG/Docker env; the *production beta deployment* sweep is UNVERIFIED |
| Entry: backup/restore tested; RPO/RTO plan | **PARTIAL** | RTO drill executed (`recovery_drill.sh`); continuous RPO ≤5 min UNVERIFIED (no WAL/PITR) |
| Entry: private solvers non-served; contestants scoped to own team (S3) | **GATED-PASS** | S4 (host) + S3 (PG+Docker) |
| Entry: incident-response + rollback runbook | **PARTIAL** | runbooks exist in `../operations/`; rehearsal is process, not a test |
| Exit: real competition at target scale — **25 teams, 20 challenges** | **UNVERIFIED** | only smoke-scale executed (`capacity.md`); production scale → M22+ |
| Exit: ≥99% launch success; scoreboard <3s; submission <500ms sustained | **PARTIAL** (latency) + **UNVERIFIED** (≥99% launch) | scoreboard smoke p50/p95 within target; submission p95 at the 25×20 target scale measured **OVER target ≈2050 ms** in-process (`capacity.md`); sustained production numbers UNVERIFIED; **≥99% launch success has no evidence on this host** (`build_challenge` unbuilt) |
| Exit: at-most-one solve per (team,challenge,competition) under real submissions | **GATED-PASS** | enforced-by-construction; e2e + submission tests (34 OK) — at sim scale |
| Exit: scoreboard reconstructed from score events, matched live | **GATED-PASS** | restore-verify scoreboard parity (S8, 38 OK) |
| Exit: zero public flag leak + zero deterministic-rebuild failures | **PASS** | S4 (host) + conformance byte-stability (52 OK) |
| Exit: no unresolved critical/high finding across S1–S9 | **PARTIAL** | none in the executed surface here; production-deployment scope UNVERIFIED |
| Exit: recovery drill (RPO 5min / RTO 30min) rehearsed once | **PARTIAL** | RTO rehearsed vs live PG; RPO-continuous UNVERIFIED |
| Exit: beta findings gated into v1.0 external-review scope | **UNVERIFIED** | requires a real external beta |

**Closed-beta verdict: PARTIAL.** The security, isolation, determinism,
uniqueness, and reconstruction guarantees are all backed by executed evidence on
this host. What genuinely cannot be produced here — a real TLS deployment,
production-scale load, real external organizers/contestants, and continuous
RPO — is UNVERIFIED and listed below.

---

## What blocks v1.0 sign-off

The honest list of items **no evidence on this host can close**. These are M22 +
beyond scope. Each is a real gap, not a soft caveat.

1. **Distributed-worker bundle launch.** The `build_challenge` pipeline is UNBUILT
   (`../evaluation/eval-worker-limitations.md`, `e2e.md`). All launch evidence
   here uses a **local** worker over real PG; the published, content-addressed
   bundle executing on a real remote worker fleet is UNVERIFIED.
2. **Production-scale capacity.** Only smoke-scale load ran (`capacity.md`). The
   beta exit target — 25 concurrent teams, 20 active challenges, ≥99% launch
   success, scoreboard <3s / submission <500ms **sustained** — is UNVERIFIED.
3. **TLS reverse-proxy deployment.** No real reverse proxy + TLS was stood up;
   the "supported deployment" entry criterion and the production S1–S9 sweep
   against it are UNVERIFIED.
4. **Real external closed beta.** No real external organizers/contestants ran a
   competition; beta findings feeding the v1.0 external-review scope are
   UNVERIFIED.
5. **Continuous RPO / PITR.** RTO was rehearsed against live PG, but continuous
   backup (RPO ≤5 min via WAL/PITR) is UNVERIFIED on this host (no WAL archiving).
6. **External security review.** All S1–S9 evidence here is self-run; an
   independent external security assessment is out of scope for M21 and required
   before v1.0.

Everything above is stated so M22 can adjudicate `RELEASE_CRITERIA.md` against
real evidence and real gaps — not against optimistic checkmarks.
