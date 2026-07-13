# Internal-alpha gate — simulation report (M21 stream A)

A **simulated dry-run** of the internal-alpha entry + exit checklists
(`docs/RELEASE_CRITERIA.md`, "Internal-alpha gate", lines ~192-208) on this
single host. Purpose: map **every** entry and exit criterion to executed evidence
or a documented **UNVERIFIED**. This report is the M21 deliverable; ticking the
boxes in `RELEASE_CRITERIA.md` remains M22's job (this report changes no
checkbox).

Charter honesty rule: a criterion is **MET / SIMULATED** only if backed by an
artifact anyone can re-run. Anything needing a real distributed-worker launch of
the *published bundle* (the `build_challenge` pipeline is unbuilt —
`docs/evaluation/eval-worker-limitations.md`), a real TLS reverse proxy,
production scale, or real external people is **UNVERIFIED** with the reason.

Status legend:
- **MET-by-evidence** — an existing executed test asserts it.
- **SIMULATED** — this milestone's new sim (`scripts/alpha_sim.py` +
  `tests/test_alpha_sim_integration.py`) executes and asserts it over live PG.
- **UNVERIFIED** — not demonstrable on this host; reason given.

Run commands (this report's own artifacts):

```
cd /home/mini/CTFGenerator && PYTHONPATH=src:tests \
  CTFGEN_TEST_DATABASE_URL='postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres' \
  .venv/bin/python3 scripts/alpha_sim.py
cd /home/mini/CTFGenerator && PYTHONPATH=src:tests \
  CTFGEN_TEST_DATABASE_URL='postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres' \
  .venv/bin/python3 -m unittest test_alpha_sim_integration
```

Both SKIP cleanly (never silently pass) without `CTFGEN_TEST_DATABASE_URL` or the
`[api]`/`[db]` extras.

---

## The ONE composite seam (state it plainly)

The exit criterion asks for one challenge *"generated, published, **launched on a
worker**, solved via intended solver, scored, and shown on a scoreboard — end to
end"*. This is **NOT one unbroken automated flow on this host**. It is a
**composite** whose two halves are each proven by a real executed test, but which
are not stitched together, because the pipeline that would join them
(`build_challenge`: full-bundle delivery + image build on a networked worker) is
**unbuilt**:

- **Half A — generate → publish → submit → solve → score → scoreboard.**
  `scripts/alpha_sim.py` runs this whole spine through the real application
  services + HTTP API over a fresh per-run migrated PostgreSQL, with real
  auth (`DbAuthenticator`). It scores the **intended solver's flag** against the
  **published, content-addressed** version. Executed; PASS (see below).
- **Half B — a worker launches an isolated container instance and it is
  contained.** `tests/test_docker_backend_integration.py` launches a **real**
  container under the strict `ContainerPolicy` and proves the hardening took
  effect (non-root, all caps dropped, seccomp, no-new-privileges, read-only,
  noexec tmpfs, per-instance network, no host namespaces) and that `destroy`
  leaves nothing behind. Executed; 9 tests PASS on this host.

What is missing between them is only the delivery+build glue: the sim does **not**
build/run the challenge *services* on the worker, and the Docker test launches a
benign `alpine` image, not the generated bundle. Both constituents are real; the
single joined flow is UNVERIFIED and deferred to `build_challenge`
(`docs/evaluation/eval-worker-limitations.md`, `docs/validation/e2e.md`).

---

## Entry criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| E1 | v0.1-alpha capabilities complete; CI green | **MET-by-evidence** (CI) / **UNVERIFIED** (formal v0.1 sign-off → M22) | CI green: host `unittest` suite + `compileall` + Docker validation in `.github/workflows/pr.yml`. Formal per-capability v0.1 sign-off is the M22 qualification pass (reconciliation note in `RELEASE_CRITERIA.md` §0: implemented ≠ release-qualified). |
| E2 | Security gates **S4, S5, S6** green | **MET-by-evidence** | S4 `tests/test_public_flag_leak.py` (+`test_score.py` integrity demotion); S5 `tests/test_logging_redaction.py`; S6 `tests/test_build_hardening.py` + `tests/test_mcp_server.py` path guards. All **host** tests, PASS. See `security-checklist.md`. |
| E3 | Worker protocol + job system available in a test deployment (v0.2) | **MET-by-evidence** | PG job queue + worker identity/leases: `tests/test_worker_job_service_integration.py`, `tests/test_worker_repository_integration.py`, `tests/test_worker_loop_integration.py` (M7). PG-gated. |
| E4 | Bundle code executes only on isolated workers, never on the control-plane host | **MET-by-evidence** | S9 boundary: `tests/test_mcp_server.py` import firewall (`test_fresh_import_pulls_no_forbidden_module`, `test_no_docker_tool_exposed` → no `subprocess`/`docker`/`runtime_validator`/`scenario_runtime`/`agent_eval`, never mounts the Docker socket) + `tests/test_architecture_boundaries.py`. **host**, PASS. |
| E5 | Test PostgreSQL instance with migrations applied | **SIMULATED** | `scripts/alpha_sim.py` provisions a fresh database and runs `alembic upgrade head` (0001→0014) per run against the live PG container `ctfgen_pg_epic1 @172.20.0.2:5432` — visible in the run log. |
| E6 | Named internal operators and a rollback plan | **SIMULATED** (operator) / **operational note** (rollback) | The sim authenticates a **named** operator (`organizer@example.com`) via real `AuthService`/`DbAuthenticator` and a named contestant. Rollback plan = the documented backup/restore + downgrade tooling (`docs/operations/backup-recovery-upgrade.md`, `scripts/recovery_drill.sh`, `test_migration_drift_integration.py` full-downgrade); adopting it as *this deployment's* runbook is an operational sign-off owned by the operator, not a code artifact. |

---

## Exit criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| X1 | One challenge generated → published (immutable/content-addressed) → launched on a worker → solved via intended solver → scored → on a scoreboard, end to end | **SIMULATED (composite)** — see "ONE composite seam" | Half A: `scripts/alpha_sim.py` / `test_alpha_sim_integration.py` — generate→publish→submit→solve→score→scoreboard over live PG (steps `generate`, `publish`, `submit-and-solve`, `score-and-scoreboard` all PASS). Half B (worker launch + isolation): `tests/test_docker_backend_integration.py` (9 PASS). The joined `build_challenge` flow is **UNVERIFIED** (unbuilt). |
| X2 | **S2** (container escape) and **S9** (control-plane boundary / no Docker socket) verified | **MET-by-evidence** | S2: `tests/test_docker_backend_integration.py` (`test_strict_policy_hardening_takes_effect`, `test_writable_tmpfs_is_noexec`) + `tests/test_team_isolation_integration.py` (host-unreachable, egress denied). Executed on this host (9 PASS). S9: `tests/test_mcp_server.py` + `tests/test_architecture_boundaries.py` (**host**). |
| X3 | No critical/high **authz** finding (**S1**) in the exercised surface | **MET-by-evidence** | `tests/test_api_authz_scoping_integration.py` (`test_organizer_of_a_is_denied_every_scoped_write_in_b`, positive control `test_organizer_of_a_still_authorized_in_a`, `test_red_a_confined_to_red_in_a_and_absent_in_b`). PG-gated. |
| X4 | Instance lifecycle proven: launch, health check, expiration, cleanup, reconciliation of an orphaned instance | **MET-by-evidence** | `tests/test_instance_lifecycle_integration.py`: reserve→launch (`test_request_reserves_places_and_enqueues_launch`), expiry (`test_renew_keeps_hold_then_expire_releases`), reconciler drift incl. **orphaned** (`test_case1_missing_container`, `test_case5_leaked_resource`, `test_case10_orphaned_endpoint`) + `test_docker_backend_integration.py` health check + `destroy` leaves nothing. PG- / Docker-gated. |
| X5 | Flags/tokens/provider-keys absent from all logs and reports (**S5**) | **MET-by-evidence** + **SIMULATED** | `tests/test_logging_redaction.py` (**host**, redaction of every secret class incl. the real worker logger). Plus a first-party scan: `test_alpha_sim_integration.test_no_secret_leaks_into_the_sim_log` asserts the intended flag literal and any `Bearer ` token are **absent from this sim's own captured log**, and `flag_absent_from_contestant_surfaces` asserts the flag is never echoed on the submission-outcome bodies. |
| X6 | Findings triaged; blockers fixed or explicitly deferred with owner | **SIMULATED** | See "Findings" below — the sim ran clean (no failing step, no leaked secret); the one architectural gap (X1 composite) is triaged and deferred to `build_challenge` with the boundary documented. |

---

## Sim run result (evidence for X1 half A, X5, X6)

`scripts/alpha_sim.py` executed against `172.20.0.2:5432`, all steps PASS:

```
[PASS] operator-login        named internal operator authenticated over HTTP
[PASS] generate              draft version created; server-computed spec_sha256=<hex>
[PASS] publish               state=published immutable=True content-addressed (spec_sha256 stable across create->publish)
[PASS] attach-publication    published version attached to the competition
[PASS] submit-and-solve      intended solver's flag accepted; first_solve=True; flag not echoed
[PASS] exactly-one-solve     duplicate correct re-submit accepted but yields NO second solve
[PASS] score-and-scoreboard  projector folded the outbox; Red ranked with solve_count=1 score=500
invariants: single_solve, scoreboard_reflects_solve, append_only_consistent,
            published_content_addressed_immutable, flag_absent_from_contestant_surfaces  (all PASS)
```

`test_alpha_sim_integration` (6 tests) asserts these invariants over the same run;
`test_docker_backend_integration` (9 tests) backs the S2/S9/worker-launch claim.
Both suites PASS on this host.

Invariants asserted (mirroring `test_e2e_flow_integration`, tightened for this
gate): **exactly one solve** (a genuine duplicate correct re-submit is accepted
but yields `first_solve=false`, no second solve, distinct submission id); the
**scoreboard reflects the solve** only after the projector folds the transactional
outbox, and re-folding is **append-only-consistent** (byte-identical standings,
`solve_count` unchanged); the published version is **content-addressed**
(`spec_sha256` is a server-computed 64-hex digest, **stable across
create→publish**) and **immutable** (`immutable=true` once published).

---

## Findings

| ID | Finding | Severity | Disposition | Owner |
|---|---|---|---|---|
| A-1 | The single joined "published bundle launched as a contestant instance on a worker" flow (X1) is not wired: `build_challenge` (full-bundle delivery + worker-side image build) is unbuilt. Both constituent halves are proven by real executed tests; only the glue is absent. | Medium (architectural gap, not a defect) | **Deferred** — tracked to the `build_challenge` pipeline; boundary documented here + in `docs/evaluation/eval-worker-limitations.md` + `docs/validation/e2e.md`. Not a release *blocker* for an internal-only alpha whose two halves are each independently demonstrated. | Platform / M22 |
| A-2 | Team-membership placement has no HTTP route; the sim seeds the contestant's password + player membership via services (same documented gap as the e2e tests). | Low | **Deferred** — unfilled product surface, not worked around by inventing a route; everything downstream of placement runs over HTTP. | Platform |

No blocker was discovered by this simulation. No secret leaked into the sim's own
output (X5).

---

## Explicitly UNVERIFIED on this host (charter)

- **The joined worker-launch-of-the-published-bundle flow (X1).** Composite only;
  `build_challenge` unbuilt. Halves proven separately.
- **Real TLS reverse proxy / network socket.** The sim drives the ASGI app
  in-process via Starlette `TestClient` (an `httpx` client, no real socket). TLS
  termination, header normalization, and request-size limits owned by a real
  proxy are out of scope — same boundary as `docs/validation/e2e.md`.
- **Rootless/userns outer isolation layer.** This host is rootful arm64; the
  per-container hardening is enforced and asserted, but the rootless outer layer
  is capability-gated (`docs/security/runtime-isolation.md`).
- **Formal v0.1 capability sign-off (E1) and operational rollback-runbook
  adoption (E6).** These are M22 / operator sign-offs, not code artifacts.
