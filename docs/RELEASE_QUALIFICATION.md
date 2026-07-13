# Release Qualification — final adjudication (M22)

The authoritative, capstone sign-off pass. It adjudicates the release gates in
[`RELEASE_CRITERIA.md`](RELEASE_CRITERIA.md) against the **executed evidence**
produced by the M20 validation program and the M21 alpha/beta simulations
([`validation/README.md`](validation/README.md)). It is documentation only: M22
changes no code, test, schema, migration, fixture, or scoring math. It records
what the evidence proves, cites the re-runnable artifact for every QUALIFIED
verdict, and names — bluntly — everything that is **NOT** qualified.

**No false qualification.** A gate or capability is marked QUALIFIED **only**
where a specific, re-runnable executed artifact directly proves it (an M20
validation module, an M21 simulation, or a passing test suite). Where evidence is
integration-gated or single-host, that is stated in the verdict, not softened.
Where no executed artifact exists, the row reads **NOT-QUALIFIED / UNVERIFIED**
with the reason — never a silent pass.

All evidence in this document was executed on **one single rootful arm64 host**
with Docker and PostgreSQL 16 (`ctfgen_pg_epic1 @172.20.0.2:5432`) both real and
available. Vocabulary carried up from
[`validation/gate-status.md`](validation/gate-status.md):

- **QUALIFIED (host)** — proven by a test that runs in the default host suite
  (`pr.yml`, `python -m unittest`; no PostgreSQL/Docker/network).
- **QUALIFIED (integration-gated)** — proven by a real assertion that PASSES in
  the PG and/or Docker integration env and was executed on this host during
  M20/M21, but `skipUnless`-SKIPS in the default host run. Re-runnable by anyone
  with the same env.
- **NOT-QUALIFIED / UNVERIFIED** — no executed evidence on this host; reason
  stated. An honest gap, not a failure claim.

---

## 1. Executive verdict

**On executed single-host evidence, the product is qualified to the
internal-alpha stage (MET-by-simulation, with one composite seam UNVERIFIED) and
to a PARTIAL closed-beta readiness. It is NOT qualified to closed-beta exit and
it is NOT qualified to v1.0.**

**v1.0 is NOT fully release-qualified.** This is the plain, load-bearing
statement of this document. What IS proven is credited precisely below; nothing
here should be read to imply more.

The outstanding v1.0 blockers — each a real gap that no evidence on this host can
close — are:

1. **Production-scale capacity is UNVERIFIED.** The beta/v1.0 target (25 concurrent
   teams, 20 active challenges, ≥99% launch success, scoreboard <3 s / submission
   <500 ms **sustained**) is not met on this host. At the 25×20 concurrency the
   in-process, single-PostgreSQL submission p95 was measured **OVER target
   (≈2050 ms vs the 500 ms SLO)** — reported honestly, not softened
   ([`validation/capacity.md`](validation/capacity.md)).
2. **A real TLS / multi-host deployment run is UNVERIFIED.** No reverse proxy +
   TLS ingress and no S3-compatible artifact backend were stood up; all API
   evidence drives the ASGI app in-process (Starlette `TestClient`, no real
   socket).
3. **A real EXTERNAL closed beta is UNVERIFIED.** No real external organizers or
   contestants ran a competition; this is a social/operational process, not
   simulable on one host.
4. **The distributed-worker bundle-launch flow is UNVERIFIED.** The
   `build_challenge` pipeline (full-bundle delivery + worker-side image build) is
   **UNBUILT** ([`evaluation/eval-worker-limitations.md`](evaluation/eval-worker-limitations.md),
   [`validation/e2e.md`](validation/e2e.md)); ≥99% launch-success has no evidence.
5. **Continuous RPO / PITR is UNVERIFIED.** RTO was measured by a real drill
   (≈1.7 s vs the ≤30 min SLO); continuous RPO ≤5 min needs WAL archiving / PITR,
   not configured on this host — only a `pg_dump` baseline RPO exists
   ([`operations/backup-recovery-upgrade.md §5`](operations/backup-recovery-upgrade.md)).
6. **An external security review is UNVERIFIED.** All S1–S9 evidence here is
   self-run; an independent external assessment is required for v1.0 and is out of
   scope here.

Until all six are closed against real evidence, **v1.0 remains unsigned.** The
platform is implemented and internally validated at simulation scale; it is not
production release-qualified.

---

## 2. Security gates S1–S9

Grounded in [`validation/security-checklist.md`](validation/security-checklist.md)
(the authoritative gate→test map, guarded by
`tests/test_security_validation_meta.py`) and the M21 roll-up in
[`validation/gate-status.md`](validation/gate-status.md). Every S-gate is
substantiated by an executed test; none is left untested. The caveat column
states honestly that these run in the integration env, **not** against a
production deployment.

| Gate | Verdict | Exact executed test | Caveat |
|---|---|---|---|
| **S1** — no critical/high authz failure; role checks on every privileged action; no cross-competition action | **QUALIFIED (integration-gated)** | `tests/test_api_authz_scoping_integration.py` (`test_organizer_of_a_is_denied_every_scoped_write_in_b`, positive control `test_organizer_of_a_still_authorized_in_a`), `tests/test_api_instances_integration.py` (`test_contestant_is_forbidden_everywhere`) | PASSES vs live PG (in the 43-test run); SKIPS on host `pr.yml`. Verified in the integration env, not a production deployment. |
| **S2** — no container escape from workload to worker host or beyond | **QUALIFIED (integration-gated)** | `tests/test_team_isolation_integration.py` (`test_isolated_container_cannot_reach_host_bound_service`, `test_metadata_and_internet_egress_is_denied` + non-vacuous positive controls), `tests/test_docker_backend_integration.py` (`test_strict_policy_hardening_takes_effect`, `test_writable_tmpfs_is_noexec`) | PASSES with real container launch (in the 20-test Docker run). Requires the host-block **firewall capability**; where absent the isolated launch refuses by design and the test SKIPS. Proves isolation of a **worker container**, not the published bundle. Rootless/userns hardening remains capability-gated on this rootful arm64 host. |
| **S3** — no cross-team access (instance/submission/data) | **QUALIFIED (integration-gated)** | `tests/test_api_authz_scoping_integration.py` (`test_red_a_confined_to_red_in_a_and_absent_in_b`) + `tests/test_team_isolation_integration.py` (`test_cross_team_isolation_with_positive_control`) | Both API-scoping (PG) and network (Docker+firewall) planes PASS in the integration env; SKIP on host. Not a production-deployment sweep. |
| **S4** — no flag leakage (flags absent from public artifacts, not served to contestants) | **QUALIFIED (host)** | `tests/test_public_flag_leak.py` (`test_no_family_mode_leaks_its_flag_into_public`), `tests/test_score.py` (`test_flag_leaked_into_public_is_demoted`, `test_stub_solver_that_embeds_flag_is_demoted`) | Runs and asserts in the host suite (79-test run). |
| **S5** — no secret leakage (flags/session tokens/API keys never logged or emitted) | **QUALIFIED (host)** | `tests/test_logging_redaction.py` (`test_no_secret_class_reaches_the_emitted_output`, `test_exception_traceback_is_redacted`, `test_shapeless_secrets_in_message_text_are_redacted`, `test_secret_redacted_on_the_real_worker_logger`) | Host suite. Additionally re-asserted by the alpha sim's own log scan (`test_no_secret_leaks_into_the_sim_log`). |
| **S6** — destructive path handling safe (no build-dir escape; `force`/rmtree constrained to sandbox root) | **QUALIFIED (host)** | `tests/test_build_hardening.py` (`PathValidationTests`, `DeletionGuardTests`, `SymlinkEscapeTests`), `tests/test_mcp_server.py` (`test_create_challenge_rejects_parent_traversal`, `test_create_challenge_rejects_absolute_outside_root`) | Host suite. |
| **S7** — no unauthenticated admin endpoints (every control-plane mutation needs authn + authz) | **QUALIFIED (integration-gated)** | `tests/test_api_auth_integration.py` (`test_missing_bearer_on_me_is_401`, `test_wrong_password_and_unknown_email_are_indistinguishable`), `tests/test_api_instances_integration.py` (`test_contestant_is_forbidden_everywhere`), `tests/test_web_security.py` (`WebLoginCsrfTests`, `WebCsrfTests`) | PASSES vs live PG; SKIPS on host. Integration env, not a production deployment. |
| **S8** — no unrecoverable DB corruption (migrations reversible/tested; scoreboard reconstructable; backup/restore verified; ledgers append-only) | **QUALIFIED (integration-gated)** | `tests/test_ledger_repository_integration.py` (append-only trigger), `tests/test_restore_verify_integration.py` (`test_backup_restore_verify_round_trip_passes` incl. scoreboard parity + negative controls), `tests/test_migration_drift_integration.py` (`test_head_has_no_autogenerate_drift`, `test_full_downgrade_leaves_clean_database`) | PASSES vs live PG (38-test run). Restore round-trip additionally needs `pg_dump`/`pg_restore`; absent both it SKIPS. Covers logical restore, **not** continuous PITR. |
| **S9** — control plane never executes generated code / never mounts the Docker socket | **QUALIFIED (host, static) + QUALIFIED (integration-gated, runtime)** | Static: `tests/test_mcp_server.py` (`test_source_imports_no_effectful_or_platform_module`, `test_fresh_import_pulls_no_forbidden_module`, `test_no_docker_tool_exposed`), `tests/test_architecture_boundaries.py`. Runtime: `tests/test_docker_backend_integration.py` | Static boundary asserted in the host suite; runtime confinement asserted in the Docker env. |

**S-gate meta-guard:** `tests/test_security_validation_meta.py` (host, 6 tests,
executed here) fails if any cited module disappears or a gate drops out of the
checklist — so the mapping above cannot silently rot.

**S1–S9 verdict:** all nine are QUALIFIED by an executed test on this host —
S4/S5/S6/S9(static) on the host, S1/S2/S3/S7/S8/S9(runtime) in the PG/Docker
integration env. **No S-gate is UNVERIFIED on this host.** The
production-deployment S1–S9 sweep (TLS reverse proxy, real worker fleet, external
scope) and the independent external security review are separate v1.0 blockers
(§7) and are NOT qualified.

---

## 3. Per-stage capabilities (v0.1-alpha … v0.5-beta)

Reconciliation note ([`RELEASE_CRITERIA.md §0`](RELEASE_CRITERIA.md)): M6–M18
**implemented** most of the v0.1→v0.4 scope. *Implemented ≠ release-qualified.*
This section marks which capability lines are backed by a **shipped-code + executed
test** pair (QUALIFIED) versus which carry a gap. Formal per-capability box-ticking
stays with this pass; capability lines whose only proof is "code exists" without an
executed assertion are marked **IMPLEMENTED (not independently qualified)**.

| Stage | QUALIFIED (executed evidence) | Gaps / NOT-QUALIFIED |
|---|---|---|
| **v0.1-alpha** (reliable generator) | Deterministic rebuild-equality + no-wall-clock provenance: `tests/test_conformance_suite.py` (52 OK, host). Filesystem hardening: S6 tests (host). Flag/secret non-leak: S4/S5 (host). | Formal "CI runs unit + `compileall` + Docker validation on every change" is IMPLEMENTED (`.github/workflows/pr.yml`) but Docker-validation-in-CI is not asserted by a test here. Family-SDK / quality-gate / release-artifact capability lines are IMPLEMENTED, not independently re-qualified in this pass. |
| **v0.2-alpha** (isolated execution) | PG job system (leases/heartbeats/retries/idempotency/dead-letter): `tests/test_worker_job_service_integration.py`, `test_worker_repository_integration.py`, `test_worker_loop_integration.py` (PG-gated). Instance lifecycle + reconciliation of orphans: `test_instance_lifecycle_integration.py` (10 drift cases incl. orphaned). Resource/network isolation: S2 Docker tests. Bundle code runs only on isolated workers: S9 (host static + Docker runtime). | **Rootless Docker/Podman + rootless BuildKit** is capability-gated on this rootful arm64 host → NOT-QUALIFIED here ([`security/runtime-isolation.md`](security/runtime-isolation.md)). |
| **v0.3-alpha** (persistent control plane) | PG domain model + Alembic (head `0014`): migration-drift + full-downgrade tests. Immutable content-addressed publish + at-most-one-solve + score-event reconstruction: `alpha_sim.py` / `beta_sim.py` + `test_e2e_flow_integration.py` + S8 restore parity. AuthN/AuthZ across roles: S1/S7. Audit trail: S8 ledger append-only. | All PG-gated (integration env, not host). Production-deployment authz sweep NOT-QUALIFIED. |
| **v0.4-beta** (complete workflow) | Organizer web (M11), contestant portal (M12), live-ops orchestration (M8), reports via API (M9/M16) — exercised by `test_web_*`, `test_api_*`, `test_instance_lifecycle_integration.py`. One organizer→contestant workflow: `alpha_sim.py` Half A over real PG. | **Supported deployment (reverse proxy + TLS, S3 artifact storage)** NOT-QUALIFIED — not stood up. **Operating targets (25×20, ≥99% launch, <3 s/<500 ms)** NOT-QUALIFIED — see §5. The single joined organizer→contestant→worker-launch flow is a **composite**, not one flow (§4). |
| **v0.5-beta** (quality + evaluation) | Scenario engine live + provably blocks the real attack surface (offline) for 4 families: `tests/test_family_scenarios.py` (host). Single-host scripted eval delta machinery exists and is exercisable (`agent_eval`, `SingleHostEvalJobRunner`). | **Distributed / at-scale / real-LLM adversarial eval NOT-QUALIFIED** — `build_challenge` unbuilt; LLM profile credential-blocked; no continuous automated resistance-number artifact ([`validation/ai-resistance.md`](validation/ai-resistance.md), §6). |

---

## 4. Alpha / beta gates

### Internal-alpha — MET-by-simulation, with one composite seam UNVERIFIED

From [`validation/internal-alpha-report.md`](validation/internal-alpha-report.md).
Every **technical** exit criterion is backed by an executed test on this host at
simulation scale: S2/S9 (`test_docker_backend_integration.py`, 9 PASS), S1
(`test_api_authz_scoping_integration.py`), instance lifecycle
(`test_instance_lifecycle_integration.py`), S5 (`test_logging_redaction.py`), and
Half A of the spine (`scripts/alpha_sim.py` — generate→publish→submit→solve→score
→scoreboard over live PG, all steps PASS; `test_alpha_sim_integration.py`, 6 tests).

**The single composite seam — stated plainly, not overstated.** The exit
criterion asks for one challenge *generated → published → launched on a worker →
solved → scored → on a scoreboard, end to end.* This is **NOT one unbroken
automated flow.** It is a **composite of two separately-proven halves**:

- **Half A** scores the intended solver's flag against the published,
  content-addressed version over real PG — and **launches nothing**.
- **Half B** launches a **real** isolated container and proves containment
  (`test_docker_backend_integration.py`) — using a **benign `alpine` image, not
  the generated bundle**.

The glue that would join them — `build_challenge` (full-bundle delivery +
worker-side image build) — is **UNBUILT**. The joined
worker-launch-of-the-published-bundle flow is therefore **UNVERIFIED**. It must
not be represented as a single working flow.

One entry item — **named internal operators + rollback plan** — is UNVERIFIED as
an executed artifact: it is an organizational/process sign-off, not code.

**Internal-alpha verdict: QUALIFIED-by-simulation (single host), with the
composite worker-launch seam and the operator/rollback process item UNVERIFIED.**

### Closed-beta — PARTIAL

From [`validation/closed-beta-report.md`](validation/closed-beta-report.md). The
two **correctness invariants** the exit checklist names are QUALIFIED by executed
tests over real PG through the production HTTP edge:

- **At-most-one solve under concurrent real submissions** (exit X3): the guarantee is
  **enforced by construction** (a DB `UNIQUE(competition, team, version)` constraint + the
  transactional submission service) and is QUALIFIED primarily by the service-level race
  `test_submission_processing_integration.test_eight_simultaneous_correct_submissions_one_solve`
  (8 simultaneous correct submissions → exactly one solve). It is additionally **demonstrated
  end-to-end through the HTTP edge** by `scripts/beta_sim.py` /
  `test_beta_sim_integration.test_at_most_one_solve_under_concurrency` — N simultaneous correct
  submissions released off a barrier → exactly **1** first-solve, ledger solves=1 /
  solve-events=1 (the "all N accepted" liveness is a secondary observation, not the guarantee).
- **Scoreboard reconstructed from persisted score events == live state** (exit X4):
  `test_beta_sim_integration.test_scoreboard_reconstructed_matches_live_state` — an
  independent from-scratch refold of `score_events` is **byte-equal** to the persisted
  live projection.
- Zero public flag leak + zero deterministic-rebuild failures (exit X5): S4 (host) +
  `test_conformance_suite.py` (host).

What is **NOT-QUALIFIED** for closed-beta exit: a real competition at target scale
(X1), ≥99% launch success + sustained latency at scale (X2 — submission p95 OVER
target at 25×20 in-process), a real TLS deployment + S3 storage (E3), continuous
RPO (E5/X7), a real external beta with real people, and the external security
review (X6). These are exactly the v1.0 blockers.

**Closed-beta verdict: PARTIAL.** Security, isolation, determinism, uniqueness,
and reconstruction guarantees are QUALIFIED by executed evidence at smoke/sim
scale; the production-scale, real-deployment, and real-external-people criteria
are UNVERIFIED and block closed-beta **exit** and v1.0.

---

## 5. NFR / operating targets

| Target | Verdict | Evidence |
|---|---|---|
| **RTO ≤ 30 min** (REQ-NFR-007) | **QUALIFIED (integration-gated, mechanism; small dataset)** | `scripts/recovery_drill.sh` + `tests/test_recovery_drill_integration.py` measured **RTO ≈ 1.7 s** wall-clock (restore→verified-usable) vs the ≤1800 s SLO against live PG, with live negative controls (`--rto-slo-seconds 0` and `--empty-target` both breach & exit nonzero). Small representative dataset; **production-scale-volume RTO UNVERIFIED** ([`operations/backup-recovery-upgrade.md §5`](operations/backup-recovery-upgrade.md)). |
| **Continuous RPO ≤ 5 min** (REQ-NFR-006) | **NOT-QUALIFIED / UNVERIFIED** | Only a logical `pg_dump` **baseline** RPO (≈0 s at snapshot) exists — reported as baseline-only, **not a gate**. Continuous RPO needs **WAL archiving / PITR**, not configured on this host. |
| **Submission processing < 500 ms** (REQ-NFR-005) | **QUALIFIED at smoke scale only; NOT-QUALIFIED at production scale** | Smoke (3×2): submission p95 ≈435 ms (under target). At the **25×20** concurrency, in-process single-PG: submission p95 ≈**2050 ms — OVER TARGET** ([`validation/capacity.md`](validation/capacity.md)). Sustained production sign-off UNVERIFIED. |
| **Scoreboard update < 3 s** (REQ-NFR-004) | **QUALIFIED at smoke; degrading at scale** | Smoke p95 ≈115 ms; at 25×20 in-process p95 ≈1180 ms (still under 3 s but degrading). Sustained production sign-off UNVERIFIED. |
| **Instance launch success ≥ 99%** (REQ-NFR-003) | **NOT-QUALIFIED / UNVERIFIED** | No real launch of the published bundle on a worker fleet exists (`build_challenge` unbuilt); the harness probes the instances API surface and reports launch success UNVERIFIED — it never fabricates a ≥99% number. |
| **25 teams × 20 challenges envelope** (REQ-NFR-001/002) | **NOT-QUALIFIED / UNVERIFIED** | The harness can seed/drive that concurrency for submission + scoreboard paths, but "20 live challenges" in production means 20 launched, reachable instances, which the in-process harness does not stand up. |
| **Determinism (zero rebuild failures)** (REQ-NFR-009) | **QUALIFIED (host)** | `tests/test_conformance_suite.py` — byte-stable golden manifests + run-to-run determinism + no-wall-clock-in-provenance (52 OK). |
| **Zero public flag leak** (REQ-NFR-008) | **QUALIFIED (host)** | S4 (`test_public_flag_leak.py`, `test_score.py`). |

---

## 6. What an adopter can rely on TODAY vs what to treat as experimental

Mirrors the honesty of [`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md): V1 is a single
supported deployment path; anything not listed is unsupported by definition.

**An adopter can rely on TODAY (executed evidence exists):**

- A **deterministic generator/validator core** with byte-stable rebuilds and no
  wall-clock in provenance (`test_conformance_suite.py`, host).
- The **S1–S9 security guarantees** in the integration env — authz scoping, worker
  container isolation, cross-team denial, no flag/secret leak, safe destructive
  paths, authenticated control plane, recoverable-and-append-only persistence, and
  the control-plane-never-executes-code / never-mounts-Docker-socket boundary (§2).
- **Correctness under concurrency**: at-most-one-solve per (team, challenge,
  competition) holds under a real concurrent race, and the scoreboard is
  **reconstructable byte-equal** from the append-only score-event log (`beta_sim.py`,
  S8 restore parity).
- **Disaster-recovery mechanism** well within the RTO SLO on a representative
  dataset, with live negative controls.
- The **organizer→contestant application spine** (generate→publish→submit→solve→
  score→scoreboard) over real PostgreSQL through the production HTTP edge
  (`alpha_sim.py`).

**Treat as EXPERIMENTAL / UNVERIFIED (do not rely on for production):**

- **Production-scale performance** — degrades OVER the submission SLO at 25×20
  in-process; no tuned multi-host sustained run exists.
- **A real TLS / reverse-proxy / S3-storage deployment** — not stood up here.
- **Distributed worker bundle launch** (`build_challenge`) — UNBUILT; ≥99% launch
  success has no evidence.
- **Rootless / userns worker isolation** — capability-gated on this rootful arm64
  host.
- **Continuous RPO / PITR** — not configured; only baseline `pg_dump` RPO exists.
- **AI-resistance beyond the proven core.** Per [`validation/ai-resistance.md`](validation/ai-resistance.md),
  the claim has **three distinct signals that must be claimed separately** — do not
  collapse them into one "resistance score":
  1. the static `score` band is an **advisory bundle-quality heuristic**, gameable
     for all but two integrity-gated failure cases (embedded flag / leaked flag) —
     **NOT a measured or guaranteed resistance level**;
  2. the **live scenario engine is real and deterministic for 4 families** and
     provably fires and blocks each family's own attack surface **offline**
     (`test_family_scenarios.py`) — but this is a unit-level proof, **not a live
     autonomous agent defeated by a running instance**;
  3. the Evaluation Lab **can** compute a single-host scripted (non-LLM)
     solved-with-vs-without-defense delta — but the real-LLM adversary and the
     distributed/at-scale eval are **UNVERIFIED** (credential-blocked; pipeline
     unbuilt; no continuous automated resistance-number artifact).

---

## 7. v1.0 blockers + recommended path to full qualification

The honest list of what no evidence on this host can close, each with the
concrete artifact that would close it:

1. **Production-scale capacity.** Run `scripts/loadtest.py` (and a real launch
   path) at 25 teams × 20 challenges **on the supported deployment** — separate
   tuned PostgreSQL, connection-pool sizing, log shipping off the hot path, ≥1
   isolated worker host — and demonstrate submission p95 <500 ms / scoreboard
   <3 s / ≥99% launch **sustained**. (Today: submission p95 ≈2050 ms in-process,
   OVER target.)
2. **TLS multi-host deployment run.** Stand up the reverse proxy + TLS ingress,
   PostgreSQL, isolated worker host(s), and S3-compatible artifact storage per
   `docs/HOSTING.md`, then re-run the S1–S9 sweep against that deployed stack.
3. **Real external closed beta.** Invite real external organizers + contestants,
   run a competition, and gate the findings into the v1.0 external-review scope.
4. **`build_challenge` distributed-launch pipeline.** Build the full-bundle
   delivery + worker-side image build so the **published bundle** launches on a
   real remote worker, joining internal-alpha Half A + Half B into one verified
   flow and unlocking the ≥99% launch-success measurement and distributed eval.
5. **WAL/PITR for continuous RPO.** Configure WAL archiving / PITR in the beta
   deployment and re-run `scripts/recovery_drill.sh` to demonstrate continuous
   RPO ≤5 min (today: baseline-only) and production-volume RTO.
6. **External security review.** Commission an independent external assessment of
   S1–S9 against the deployed stack; resolve any critical/high before v1.0.

When all six are closed against re-runnable evidence and adjudicated the way this
document adjudicates the current gates, v1.0 can be signed. **Until then, the
overall verdict stands: v1.0 is NOT fully release-qualified.**

---

## Adjudication note

This pass ticks no checkbox in `RELEASE_CRITERIA.md` that lacks a cited,
re-runnable executed artifact. Every QUALIFIED verdict above names its test or
simulation; every gap is named UNVERIFIED with its reason. The document is
documentation and reconciliation only — no code, test, schema, migration,
fixture, or scoring math was changed in M22.
