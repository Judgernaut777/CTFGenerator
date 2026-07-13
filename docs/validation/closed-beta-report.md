# Closed-beta gate — simulation report (M21 stream B)

A **simulated dry-run** of the closed-beta entry + exit checklists
(`docs/RELEASE_CRITERIA.md`, "Closed-beta gate", entry lines ~216-224, exit lines
~226-235) on this single host. Purpose: map **every** entry and exit criterion to
executed evidence or a documented **UNVERIFIED**. This report is the M21
deliverable; ticking the boxes in `RELEASE_CRITERIA.md` remains M22's job (this
report changes no checkbox).

Charter honesty rule (§5): a criterion is **MET / SIMULATED** only if backed by an
artifact anyone can re-run. Anything needing a real distributed-worker launch of
the *published bundle* (the `build_challenge` pipeline is unbuilt —
`docs/evaluation/eval-worker-limitations.md`, `docs/validation/e2e.md`), a real
TLS reverse proxy, **production scale** (25 teams / 20 challenges / ≥99% launch),
or real **external** organizers/contestants (a social process, not simulable
here) is **UNVERIFIED** with the reason.

Status legend:
- **MET-by-evidence** — an existing executed test asserts it.
- **SIMULATED** — this stream's new sim (`scripts/beta_sim.py` +
  `tests/test_beta_sim_integration.py`) executes and asserts it over live PG.
- **UNVERIFIED** — not demonstrable on this host; reason given.

Run commands (this report's own artifacts):

```
cd /home/mini/CTFGenerator && PYTHONPATH=src:tests \
  CTFGEN_TEST_DATABASE_URL='postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres' \
  .venv/bin/python3 scripts/beta_sim.py --teams 3 --challenges 2 --concurrency 6
cd /home/mini/CTFGenerator && PYTHONPATH=src:tests \
  CTFGEN_TEST_DATABASE_URL='postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres' \
  .venv/bin/python3 -m unittest test_beta_sim_integration
```

Both SKIP cleanly (never silently pass) without `CTFGEN_TEST_DATABASE_URL` or the
`[api]`/`[db]` extras.

---

## What this stream mechanizes (state it plainly)

The closed-beta gate is fundamentally a **real event with external people at
production scale on a deployed stack** — most of it is a social/operational
sign-off, not a code artifact, and is honestly UNVERIFIED here. What IS
mechanizable are the two **correctness invariants** the exit checklist names, and
those this stream proves over a **real PostgreSQL** through the **production HTTP
edge** (`create_app` + Starlette `TestClient`) and the **production scoring fold**:

- **At-most-one solve under CONCURRENT real submissions** (exit X3). `--concurrency`
  submitters POST the SAME correct flag for ONE (competition, team, challenge)
  **simultaneously** (released off a `threading.Barrier`, each with its OWN
  `TestClient` so httpx is never shared). Asserted: all N accepted, **exactly one**
  `first_solve`, and the ledger holds **exactly one** solve row + **exactly one**
  `solve` score event — no double-count.
- **Scoreboard reconstructed from persisted score events == live state** (exit X4).
  After a mixed multi-team solve set is folded into the live projection cache by
  the real `ScoreProjector` (via the 0008 transactional outbox), the sim
  **independently refolds** the append-only `score_events` through the same pure
  `compute_scoreboard` path and asserts the reconstruction is **byte-equal** to the
  persisted live projection (the S8 "scoreboard reconstructable from persisted
  score events" property, exercised end to end).

This is a **smoke-scale** run (3 teams × 2 challenges × 6 concurrent submitters),
NOT the production-scale beta. See "Explicitly UNVERIFIED" below.

---

## Entry criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| E1 | Internal-alpha exit criteria all met | **MET-by-evidence** (via M21 stream A) | `docs/validation/internal-alpha-report.md` maps every internal-alpha exit criterion to executed evidence (`scripts/alpha_sim.py`, `test_alpha_sim_integration.py`, `test_docker_backend_integration.py`). The one composite gap (worker-launch-of-published-bundle) is triaged/deferred there, not a blocker for an internal-only alpha. |
| E2 | v0.4-beta capabilities complete: admin UI + contestant portal + live ops + reports | **MET-by-evidence** (built) / **UNVERIFIED** (formal v0.4 sign-off → M22) | Organizer web (M11), contestant portal (M12), live-ops instance orchestration (M8), reports surfaced via API (M9/M16) are implemented and tested (`tests/test_web_*`, `test_api_*`, `test_instance_lifecycle_integration.py`). Formal per-capability v0.4 sign-off is M22 (RELEASE_CRITERIA §0: implemented ≠ release-qualified). |
| E3 | Supported deployment stood up: reverse proxy + TLS, PostgreSQL, isolated worker(s), artifact storage | **UNVERIFIED** | PostgreSQL + isolated worker ARE exercised (live PG container; `test_docker_backend_integration.py` real container). **Real TLS reverse-proxy ingress and S3-compatible artifact storage are NOT stood up on this host**; the sim drives the ASGI app in-process (Starlette `TestClient`, no real socket). Deployment stack docs: `docs/operations/`. Deployment-scale sign-off = M22. |
| E4 | **All S1–S9 green** in the beta deployment | **MET-by-evidence** (per-gate) / **UNVERIFIED** (as a full deployed stack) | Per-gate executed evidence mapped in `docs/validation/security-checklist.md` + guarded by `tests/test_security_validation_meta.py`: S1/S7 `test_api_authz_scoping_integration.py`; S2/S9 `test_docker_backend_integration.py`; S3 `test_team_isolation_integration.py`; S4 `test_public_flag_leak.py`; S5 `test_logging_redaction.py`; S6 `test_build_hardening.py`+`test_mcp_server.py`; S8 `test_recovery_drill_integration.py`+`scripts/recovery_drill.sh` (RTO) + this stream's scoreboard-reconstruction proof. "All green **in the beta deployment**" as one deployed stack is a M22 deployment sign-off. |
| E5 | Backup/restore tested; RPO/RTO plan in place (**S8**) | **MET-by-evidence** (RTO) / **UNVERIFIED** (continuous RPO) | `scripts/recovery_drill.sh` + `tests/test_recovery_drill_integration.py` MEASURE RTO wall-clock vs the ≤30 min SLO against live PG (executed; negative controls). **RPO ≤5 min continuous is UNVERIFIED — needs WAL archiving / PITR, not configured on this host**; the drill reports RPO baseline-only, not as a gate (`scripts/recovery_drill.sh` "RPO HONESTY", `docs/validation/README.md`). |
| E6 | Private solvers confirmed non-served; contestants scoped to their own team's instances (**S3**) | **MET-by-evidence** | Private solver never in `public/`: `tests/test_public_flag_leak.py` + `test_baseline_fixtures` (no-private-content-in-public invariant, in `test_conformance_suite.py`). Cross-team scoping: `tests/test_team_isolation_integration.py` (S3) + `test_api_authz_scoping_integration.py` (a contestant confined to their own team; cross-team read denied). PG-/Docker-gated. |
| E7 | Incident-response and rollback runbook ready | **operational note** | Runbook = `docs/operations/` incident + backup/restore/downgrade tooling (`scripts/recovery_drill.sh`, `scripts/restore.sh`, `test_migration_drift_integration.py` full-downgrade). Adopting it as *this deployment's* runbook is an operator sign-off, not a code artifact (same disposition as internal-alpha E6). |

---

## Exit criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| X1 | A real competition run at target scale: 25 concurrent teams, 20 active challenges | **UNVERIFIED** | Production scale with **real external teams** is not simulable on one host. The in-process capacity harness (`scripts/loadtest.py`, `docs/validation/capacity.md`) CAN seed/drive 25×20, but that is synthetic in-process load, not a real competition, and at that concurrency submission p95 was measured **OVER TARGET** (≈2050 ms) — see X2. Real-scale run = M22. |
| X2 | ≥99% instance launch success; scoreboard update <3s; submission processing <500ms server-side sustained | **UNVERIFIED (at scale)** / smoke lower-bound only | Launch success ≥99% is **UNVERIFIED** — needs the M8 reconciler driving a real worker host that starts the published bundle's containers (`build_challenge` unbuilt; `loadtest.py` `_probe_launch` reports it UNVERIFIED, never a fabricated number). Latency: at **smoke** scale (3×2) submission p95 ≈435 ms / scoreboard p95 ≈115 ms (`capacity.md`) — a LOWER-BOUND data point, under target; but at 25×20 in-process submission p95 ≈**2050 ms OVER TARGET**. Sustained-at-scale is UNVERIFIED. |
| X3 | At-most-one solve per (team, challenge, competition) held under real submissions | **SIMULATED — MET** | `scripts/beta_sim.py` / `test_beta_sim_integration.test_at_most_one_solve_under_concurrency`: **6 simultaneous** correct submissions of the same flag → all 6 accepted, **first_solve=1**, ledger **solves=1, solve-events=1, submissions=6**. Backed by the service-level race `test_submission_processing_integration.test_eight_simultaneous_correct_submissions_one_solve` (advisory lock + `uq_solves_*` backstop + SAVEPOINT). Executed vs live PG. |
| X4 | Scoreboard reconstructed from persisted score events and matched live state | **SIMULATED — MET** | `scripts/beta_sim.py` / `test_beta_sim_integration.test_scoreboard_reconstructed_matches_live_state`: after the real `ScoreProjector` folds the outbox into the live cache, an **independent from-scratch refold** of the append-only `score_events` (same pure `compute_scoreboard`) is **byte-equal** to the persisted live projection (3 ranked rows, `as_of_seq=3`). This is the S8 reconstructability property exercised end to end. Executed vs live PG. |
| X5 | Zero public flag leakage and zero deterministic-rebuild failures observed | **MET-by-evidence** | Zero flag leak (S4): `tests/test_public_flag_leak.py` + the no-private-content-in-public invariant in `test_conformance_suite.py`; the trust boundary injects the flag at runtime via `${CTFGEN_FLAG:-}`, never into `public/`. Zero deterministic-rebuild failures: `tests/test_conformance_suite.py` (byte-stable golden manifests + a direct run-to-run determinism + no-wall-clock-in-provenance assertion). Both **host**, PASS. |
| X6 | No unresolved critical/high security finding across **S1–S9** | **MET-by-evidence** (per gate) / **UNVERIFIED** (external review) | Every gate S1–S9 has executed evidence with no open critical/high in the exercised surface (see E4 map + `security-checklist.md`). The **external** security review (v1.0 capability) is out of scope here and UNVERIFIED — findings from this beta feed into it (X8). |
| X7 | Recovery drill (RPO 5min / RTO 30min) rehearsed at least once | **MET-by-evidence (RTO)** / **UNVERIFIED (continuous RPO)** — already executed via M20 | Already rehearsed: `scripts/recovery_drill.sh` + `tests/test_recovery_drill_integration.py` measure **RTO** wall-clock vs the ≤30 min SLO against live PG (executed at least once; asserts restore is not a no-op). **RPO ≤5 min is baseline-only / UNVERIFIED — needs WAL/PITR** (`docs/validation/README.md`, `scripts/recovery_drill.sh` "RPO HONESTY"). Production-volume RTO also UNVERIFIED. |
| X8 | Beta findings logged and gated into the v1.0 external-review scope | **SIMULATED** | See "Findings" below — the sim ran clean (no failing invariant, no double-count, byte-equal reconstruction). The standing scope gaps (real-scale run, ≥99% launch, TLS ingress, continuous RPO) are logged here and carried into the M22 / v1.0 external-review scope. |

---

## Sim run result (evidence for X3, X4, X8)

`scripts/beta_sim.py --teams 3 --challenges 2 --concurrency 6` executed against
`172.20.0.2:5432`, OVERALL **PASS**:

```
[1] AT-MOST-ONE-SOLVE UNDER CONCURRENCY (exit: at-most-one solve/team/challenge)
    6 simultaneous correct submissions of the same flag
    accepted(correct)=6/6  first_solve=true count=1 (want 1)
    ledger: solves=1 (want 1)  solve-events=1 (want 1)  submissions=6 (want 6)
    -> PASS

[2] SCOREBOARD RECONSTRUCTED FROM PERSISTED SCORE EVENTS == LIVE STATE
    live projection rows=3  reconstructed rows=3  as_of_seq=3
    byte-equal(live cache == from-scratch event refold)=True
    -> PASS

OVERALL: PASS
```

`test_beta_sim_integration` (3 tests) asserts these invariants over the same run
and SKIPS cleanly without PG. The concurrency check drives the **real HTTP edge**
(`POST /api/v1/competitions/{id}/submissions`) from 6 concurrent OS threads,
released together off a barrier for a genuine race; the reconstruction check reads
the **live projection cache** back through `SqlAlchemyScoreboardProjectionRepository`
and compares it to an independent refold of `score_events` through the same pure
`compute_scoreboard` the projector uses (default `dynamic_decay` engine, so parity
is meaningful, not tautological across engines).

---

## Findings

| ID | Finding | Severity | Disposition | Owner |
|---|---|---|---|---|
| B-1 | The production-scale beta (X1/X2) — 25 real external teams × 20 live challenges, ≥99% launch, sustained <500 ms/<3 s — is not runnable on this host. At 25×20 in-process the submission p95 is measured **OVER TARGET** (≈2050 ms). | Medium (scale gap; also a real performance signal) | **Deferred** — real-scale run + perf tuning tracked to M22 / v1.0; the OVER-TARGET measurement is logged into the external-review scope, not softened. | Platform / M22 |
| B-2 | Continuous RPO ≤5 min (E5/X7) is UNVERIFIED — no WAL archiving / PITR on this host; only logical `pg_dump` baseline RPO is demonstrable. | Medium | **Deferred** — needs PITR configured in the beta deployment; RTO is proven, RPO is honestly baseline-only. | Ops / M22 |
| B-3 | Supported deployment (E3): real TLS reverse-proxy ingress and S3-compatible artifact storage are not stood up; the sim uses in-process ASGI + local PG. | Medium (deployment gap, not a defect) | **Deferred** — deployment-stack sign-off owned by M22; PG + isolated worker halves are exercised. | Ops / M22 |

No correctness blocker was discovered by this simulation: at-most-one-solve held
under a real concurrent race and the scoreboard reconstructed byte-equal from the
persisted event log.

---

## Explicitly UNVERIFIED on this host (charter §5)

- **Production scale (X1).** 25 concurrent teams × 20 active challenges as a real
  competition. Synthetic in-process load can reach that concurrency but is not a
  real run, and shows submission p95 OVER TARGET there (`docs/validation/capacity.md`).
- **≥99% instance launch success (X2).** Needs the M8 reconciler driving a real
  isolated worker host that launches the *published bundle's* containers;
  `build_challenge` is unbuilt (`docs/evaluation/eval-worker-limitations.md`).
- **Sustained <500 ms submission / <3 s scoreboard AT SCALE (X2).** Smoke-scale
  numbers are an under-target LOWER BOUND only; at-scale is UNVERIFIED (and
  degrades OVER target in-process at 25×20).
- **Real TLS reverse-proxy deployment + S3 artifact storage (E3).** The sim drives
  the ASGI app in-process via Starlette `TestClient` (an httpx client, no real
  socket). Same boundary as `docs/validation/e2e.md`.
- **Real EXTERNAL organizers and contestants (the whole point of a beta).** A
  social/operational process — invitations, real humans playing — not simulable on
  one host. UNVERIFIED by nature; owned by the M22 qualification + the actual beta.
- **Continuous RPO ≤5 min (E5/X7).** Needs WAL/PITR; baseline-only here.
- **Formal v0.4 capability sign-off (E2) and "all S1–S9 green in the beta
  deployment" as one deployed stack (E4).** M22 deployment sign-offs, not code
  artifacts. Per-gate and per-capability evidence exists and is executed.
