# Incident Response — Live Event Runbooks

Status: **planning deliverable** for the target four-plane platform (Author Studio, Competition
Control Plane, Execution Plane, Evaluation Lab). Some runbooks reference components that are
**planned** (worker protocol, PostgreSQL job queue, instance orchestration, lifecycle/cleanup —
release stages v0.2/v0.3). Where a procedure can be executed against the **current** codebase
(`0.1.0`), the current tooling is named explicitly and grounded in the codebase map. Steps labelled
**(planned)** describe target behavior and are not yet implemented. **As of M16 the observability +
audit surface referenced throughout is IMPLEMENTED** — see §1.1 (`/system/ready` depth,
`/system/metrics`, the durable audit-read API `GET /audit`, structured redacted logs); many
"(planned)" *detection* steps below now have a concrete signal there.

Scope: responding to failures and security events during a *live competition*. Assumes the V1
deployment model — single control-plane deployment, PostgreSQL persistence, one or more isolated
worker hosts, containerized challenge workloads, reverse proxy with TLS, local-FS or S3-compatible
artifact storage.

---

## 1. Severity classification

| Sev | Definition | Examples | Target response start |
|---|---|---|---|
| **SEV-1** | Confidentiality/integrity breach or full-event outage | Suspected container escape, public flag leak, control-plane compromise, scoreboard corrupted for all teams, PostgreSQL unavailable | Immediate; page on-call |
| **SEV-2** | Major degradation, event continues | A challenge broken mid-event, artifact store unavailable, submission flood degrading latency, one worker host offline | < 5 min |
| **SEV-3** | Localized/single-team impact with workaround | One challenge launch failure, single stuck instance, scoreboard lag within SLO | < 15 min |
| **SEV-4** | Cosmetic / no contestant impact | Non-blocking log noise, delayed report generation | Best effort |

Escalation triggers (any one → treat as **SEV-1**): flag material outside `private/`, evidence a
workload reached a worker host beyond its container, provider API keys / session tokens / flags seen
in logs. These map directly to the KEY INVARIANTS "ZERO public flag leakage" and "control plane
never mounts Docker socket".

**Standing invariants that bound every response:**
- Control plane never executes generated challenge code and never has Docker socket access.
- Generated vulnerable workloads run only on isolated Execution-Plane workers.
- Flags, session tokens, provider keys are never logged (M16: enforced by the structured-logging
  redaction filter, not only by discipline — REQ-INV-011).
- Scoreboards are reconstructable from persisted score events (`events.py` JSONL / `postgres_events.py`).
- One team cannot reach another team's instance.

Every SEV-1/SEV-2 gets a timeline log (detection → containment → remediation → post-incident) that
feeds the audit trail.

### 1.1 Observability quick-reference (now IMPLEMENTED — M16)

The signals and controls below are real as of M16 and ground the "(planned)" detection/audit steps in
§2. All are secret-free (they never expose a flag/token/DSN):

| Surface | What it gives you | Notes |
|---|---|---|
| `GET /system/ready` | Structured multi-check readiness: `{status, degraded, checks:{database, migrations, dead_letter, projection_lag}}` | **503** when DB is down or migrations are behind; **200 `degraded:true`** for dead-letter depth / projection lag (serving-but-attention). `GET /system/live` = cheap liveness (no DB). |
| `GET /system/metrics` | Prometheus text: `ctfgen_projection_pending/_failed`, `ctfgen_jobs_dead_letter`, `ctfgen_eval_runs_non_terminal`, `ctfgen_build_info` | Admin/support-scoped (`METRICS_READ`). Scrape for alerting thresholds. |
| `GET /audit?actor=&action=&outcome=&since=&until=` | The durable, **append-only, tamper-evident** audit trail of every privileged state change **and denied privileged attempt** | Admin/support-scoped (`AUDIT_READ`). This is the timeline sink referenced in every runbook's post-incident step. |
| `GET /jobs/dead-letter`, `GET /jobs/{id}` | Failed/exhausted jobs (type/state/attempts/`error_class`; never payload/result) | Act via `POST /jobs/{id}/retry` (dead-letter requeue) / `POST /jobs/{id}/cancel`. |
| `GET /competitions/{id}/scoreboard/lag` | ProjectionLag (pending/failed/oldest-pending age) | Advisory; also surfaced in `/system/ready` + `/system/metrics`. |
| Instance ops | `GET /instances`, `.../instances/{id}`; act via `POST .../stop|reset`, `DELETE .../{id}` | The manual containment verbs for a leaking/stuck instance. |
| Structured JSON logs | One JSON line/record with `request_id` correlation; a **redaction filter** strips flags/tokens/passwords/provider-keys/DSNs before emit (REQ-INV-011) | Grep by `request_id` to reconstruct a request across services. |

---

## 2. Runbooks

Each runbook: **Detection signals** → **Immediate containment** → **Remediation** → **Post-incident**.

### 2.1 Worker offline

Applies to Execution-Plane worker hosts. **Job queue, leases, and heartbeats are planned** (v0.2,
PostgreSQL-backed rows with `FOR UPDATE SKIP LOCKED` + leases + heartbeats + retries + dead-letter).
Current state has no worker protocol; the generation/validation code (`runtime_validator`) runs
locally.

| Phase | Actions |
|---|---|
| Detection | (planned) Worker heartbeat lease expires; jobs stuck in `leased` past lease TTL. Symptom: instance launches / runtime validations stop completing. Instance-launch success drops below the 99% target. |
| Containment | (planned) Mark worker `drained` so the scheduler stops assigning it. Requeue expired-lease jobs via lease reclaim (idempotency keys prevent double-launch). Do not delete in-flight instances yet — they may still be reachable. |
| Remediation | Bring a replacement worker into the pool; confirm rootless Docker/Podman + rootless BuildKit healthy. Reconcile: for each competition instance the DB believes is live, verify a container exists; relaunch missing ones from the immutable published artifact. Deterministic-rebuild invariant guarantees identical artifacts from `(generator version, spec, family version, seed)`. |
| Post-incident | Record cause (host crash, network partition, resource exhaustion). Confirm no jobs stranded in `leased`. Verify dead-letter queue empty. File capacity note against the 25-team / 20-challenge operating target. |

### 2.2 Challenge launch failure

A specific challenge fails to start an instance for a team.

| Phase | Actions |
|---|---|
| Detection | (planned) Launch job → `failed` after retries; health check never passes. Current analog: `ctfgen validate-runtime <path>` exits **1** with `Runtime validation failed:` and prints `report.logs` (build/up/healthcheck/solver stages). |
| Containment | Hold publication/launch of that challenge for affected teams; surface a "temporarily unavailable" state rather than a broken instance. Do not retry indefinitely — cap at the configured retry count, then dead-letter. |
| Remediation | Inspect logs for the failing stage: image build vs `docker compose up` vs `/healthz` poll (`tests/healthcheck.py`, polled by `runtime_validator._wait_for_health`) vs solver. Reproduce off-event with `ctfgen validate-runtime` (add `--sandbox` to run bundle `healthcheck.py`/`solver.py` inside an ephemeral read-only container rather than on the host). For non-HTTP families check `private/runtime.json` invocation overrides. Fix or pull the challenge; relaunch. |
| Post-incident | If the artifact itself is defective, the published version is immutable — cut a new version through Author Studio review/approval; never mutate a published version. Record which teams saw the failure for possible score adjustment. |

### 2.3 Broken challenge mid-event

A published challenge is solvable-incorrectly, unsolvable, or leaks its flag trivially after teams
have already engaged.

| Phase | Actions |
|---|---|
| Detection | Anomalous solve pattern (all teams solve instantly, or none can); contestant reports; `ctfgen score <path>` integrity gates flag `band = weak` (embedded flag in solver, or flag leaked into a `public/` file for non-`blue` mode). |
| Containment | (planned) Set the challenge to `hidden`/`frozen` in the control plane so no new solves register; existing instances may keep running if not leaking. If it leaks a flag, treat as **§2.8 flag leak (SEV-1)**. |
| Remediation | Reproduce with `validate-runtime` and `replay` (cross-instance solver replay proves whether the intended vuln class holds). If the challenge must be pulled, decide scoring policy: void solves for that `challenge_id` or freeze its value. Score events are append-only, so corrections are new events, not edits. |
| Post-incident | Root-cause the generation/spec defect; regenerate deterministically; re-run static + runtime + sibling/replay gates before republishing as a new immutable version. Admin score changes require an explicit recorded reason (KEY INVARIANT). |

### 2.4 Database unavailable (PostgreSQL)

Control-plane persistence. **PostgreSQL is the V1 target**; current state persists competition
events as JSONL (`events.py::JsonlEventStore`) with an optional `postgres_events.py` store.

| Phase | Actions |
|---|---|
| Detection | Control-plane API errors on read/write; submissions not persisting; scoreboard stops updating. RPO target is 5 min, RTO 30 min. |
| Containment | Put the control plane in read-only / maintenance mode. **Do not** accept submissions that cannot be durably written — a lost submission risks violating "at most one solve per (team,challenge,competition)" reconciliation. Queue nothing in volatile memory as authoritative. |
| Remediation | Fail over to standby or restore from the most recent backup (RPO 5 min). After recovery, **rebuild scoreboard from persisted score events** (`compute_scoreboard` over the event log) — the scoreboard is a pure fold and is fully reconstructable; never hand-edit standings. Verify sequence monotonicity (`Event.seq` strictly increasing from 1). |
| Post-incident | Confirm no duplicate solves were created during the outage (dedupe on submission idempotency). Validate against RTO ≤ 30 min. Schedule a recovery drill (v1.0 gate). |

### 2.5 Artifact store unavailable

Local-FS (dev) or S3-compatible (prod) storage for published, immutable, content-addressed artifacts.

| Phase | Actions |
|---|---|
| Detection | Image builds / instance launches fail to fetch published artifacts; artifact reads 5xx or time out. |
| Containment | (planned) Pause new launches that require artifact fetch; already-running instances are unaffected (artifacts are pulled at build/launch, not steady-state). Do not fall back to regenerating on the control plane — the control plane never builds or executes challenge code. |
| Remediation | Restore store connectivity or fail over to a replica. Because published artifacts are **immutable + content-addressed**, integrity is verifiable by content hash — re-fetch and verify hash before trusting any restored object. If an artifact is lost entirely, deterministic rebuild reproduces byte-identical output from `(generator version, spec, family version, seed)`. |
| Post-incident | Verify content-address integrity across the published set. Confirm private files never entered public artifacts. Review backup/replication coverage of the bucket/volume. |

### 2.6 Scoreboard inconsistency

Public scoreboard or admin standings disagree with the event log, or teams see stale/wrong ranks.

| Phase | Actions |
|---|---|
| Detection | Rank/score mismatch vs `events.py` log; public `/public/scoreboard` differs from admin `/`; update latency exceeds the < 3 s target. Current `serve` exposes admin `/`, public `/public/scoreboard`, `/public/feed`. |
| Containment | If the *displayed* values are wrong but the event log is intact, this is a projection bug, not data loss — freeze the public view if it misleads teams. Do not accept manual standings edits. |
| Remediation | Recompute deterministically: `compute_scoreboard(events, challenges, config, engine, as_of)` is a pure fold with deterministic ordering, retroactive decay, and single first-blood per challenge. Use `--as-of` for a frozen snapshot to compare against the live view. Reconcile engine choice (default `time_decay`) and config (freeze_time, scoring windows). CLI cross-check: `ctfgen scoreboard --events ... --challenges ... --config ...`. |
| Post-incident | If the log itself was inconsistent (e.g. duplicate solve events), identify the ingestion path that allowed it and add the guard. Confirm "at most one solve per (team,challenge,competition)". |

### 2.7 Submission flood

Abnormal submission volume — brute-force flag guessing, a script loop, or DoS.

| Phase | Actions |
|---|---|
| Detection | Submission rate spike; server-side processing exceeds the 500 ms target; one team_id or IP dominates. |
| Containment | Rate-limit at the reverse proxy / API (per-team, per-IP). Flags are validated server-side; a correct submission creates at most one solve, so flooding cannot inflate score — but it can degrade latency. Throttle or temporarily block the offending team pending review. |
| Remediation | Confirm submission validation is constant-work and that repeated wrong guesses are cheap. Ensure the event store write path is not the bottleneck (append is `threading.Lock`-serialized in `events.py`; the planned PG job/queue path uses `SKIP LOCKED`). Scale API workers if legitimate load. |
| Post-incident | Decide whether flooding was abuse (penalty/disqualification per event rules, recorded with reason) or a client bug. Tune default rate limits for the operating target (25 teams). |

### 2.8 Suspected flag leak — **SEV-1**

A flag is exposed outside its intended reveal path: seen in a `public/` artifact, in logs, in the
scoreboard/feed, in an instance response it should not appear in, or shared out-of-band.

| Phase | Actions |
|---|---|
| Detection | `ctfgen score` integrity gate fires (`band = weak` when flag leaked into a `public/` file for non-`blue` mode, or flag embedded in solver); flag string found in logs (must **never** be logged — KEY INVARIANT); identical instant solves across unrelated teams; contestant report. |
| Containment | Treat the flag as **burned immediately**. (planned) Rotate the flag: flags are injected at runtime via `${CTFGEN_FLAG:-}` env, never baked into `public/` — so rotation = set a new `CTFGEN_FLAG` and relaunch affected instances. **Quarantine the leaking instance state**: stop the instance, snapshot its container/logs for forensics before teardown, and preserve the `private/variant.json` ground truth for that instance. Invalidate solves recorded after the leak window for that `challenge_id`. |
| Remediation | Determine leak source: (a) generation defect leaking into a public artifact → pull and regenerate as a new immutable version; (b) service disclosing the flag on a route it shouldn't → fix template/service; (c) logging path emitting the flag → remove and scrub logs. **Rotate any secrets that shared the exposure surface** (session tokens, public scoreboard token via `serve --public-token` / dashboard token rotation, provider API keys if in the same log stream). Re-issue flags per affected instance. |
| Post-incident | Audit log every scored change with an explicit reason. Add a detection signature (grep published artifacts and log stream for flag-format strings pre-publication). Confirm "private solvers never served to contestants" held. Full timeline to the audit trail. |

### 2.9 Suspected container escape — **SEV-1**

Evidence that a challenge workload broke out of its container or reached the worker host, another
team's instance, or the control plane.

| Phase | Actions |
|---|---|
| Detection | Unexpected process/network activity on a worker host; a workload reaching outside its `internal: true` compose network or published port; resource limits bypassed; a container touching the Docker socket (which the control plane never mounts — so any such signal on the control plane is a **critical** breach). Cross-team instance reachability. |
| Containment | **Isolate the worker host immediately**: cut its network (remove from scheduler, block egress), do **not** power off if forensics are needed — freeze it. **Quarantine instance state**: snapshot the suspect container(s), the host's process/network state, and logs before any teardown. Stop scheduling new jobs to that host (mark `drained`). Assume every instance and secret on that host is compromised. |
| Remediation | Rebuild the worker from a known-good image; do not reuse the suspect host until wiped. Verify runtime hardening is intact on all workers: `no-new-privileges`, `cap_drop: [ALL]`, `mem_limit`, `pids_limit`, `internal: true` networks with no published port (declared in generated `docker-compose.yml`), rootless Docker/Podman + rootless BuildKit. **Rotate every secret reachable from the host**: flags for its instances (`CTFGEN_FLAG` reinjection + relaunch elsewhere), worker↔control-plane credentials/tokens, artifact-store access keys, provider API keys. Confirm the control plane itself was never in the blast radius (it holds no Docker socket and executes no challenge code — verify this boundary held). |
| Post-incident | Preserve forensic snapshots for the security review (external review is a v1.0 gate). Root-cause the escape vector (kernel, misconfig, missing hardening flag) and add a regression check to the worker provisioning. Full audit timeline. Re-examine whether any cross-team access ("one team cannot access another team's instance") was possible. |

### 2.10 Failed cleanup / instance expiration

An instance fails to tear down at expiration, or cleanup leaves orphaned containers, networks,
volumes, or artifacts. **Instance lifecycle + expiration + cleanup are planned** (v0.2).

| Phase | Actions |
|---|---|
| Detection | (planned) Containers running past their expiration lease; worker resource usage climbing; orphaned networks/volumes accumulating. Reconciliation finds instances the DB marks `expired` but that still exist on a worker. |
| Containment | (planned) Stop scheduling to the affected worker if resource-starved. Do not let stale instances remain reachable by contestants after a competition window closes — expired instances are a data-exposure surface (they still hold live flags). |
| Remediation | (planned) Run reconciliation: for every instance the control plane considers terminated, force-remove the container + its network + volumes on the worker. Because launch is idempotent and artifacts are immutable, safe re-teardown is repeatable. Reclaim disk. Verify no flag-bearing container persists past its window. |
| Post-incident | Confirm cleanup is idempotent and that a failed teardown dead-letters rather than silently leaking. Ensure expiration is enforced by the worker, not only the control-plane clock. Check for capacity impact against the operating targets. |

---

### 2.11 Bad deploy / rollback

| | |
|---|---|
| Severity | SEV-2 (degradation after a release) or SEV-1 (a release breaks auth / leaks a secret / corrupts data) |
| Detection | Post-deploy: `GET /system/ready` flips to 503 or `degraded`; error rate / `ctfgen_jobs_dead_letter` climbs in `/system/metrics`; a spike of `outcome=denied`/`error` in `GET /audit`; structured logs show a new exception class by `request_id`. |
| Containment | Stop the rollout / take the new version out of the load-balancer rotation. Because challenge artifacts are **immutable + content-addressed** and instance launch is **idempotent**, a control-plane rollback does not disturb running instances. Do NOT roll the DB back blindly — see remediation. |
| Remediation | **App rollback:** redeploy the previous image/tag; `GET /system/version` confirms the running version and `/system/ready`'s `migrations` check confirms the schema matches the code (`CODE_MIGRATION_HEAD`). **Schema:** migrations are **reversible** (Alembic `downgrade`), but only downgrade if the new migration is the cause AND no data depends on it — prefer a forward fix. Append-only tables (audit_events, the ledger, score_events) are never downgraded destructively. Re-run the readiness checks until green. |
| Post-incident | Record the rollback in the audit trail (who/what/why via the `reason` field). Add the failing signal to the pre-deploy smoke set. Confirm no secret was emitted during the incident window (grep the redacted log stream). |

---

## 3. Cross-cutting actions

**Secret rotation checklist** (invoke for §2.8 flag leak and §2.9 container escape):

| Secret | Where | Rotation |
|---|---|---|
| Challenge flag | Runtime env `${CTFGEN_FLAG:-}`, never in `public/` | New value → relaunch affected instances |
| Public scoreboard token | `serve --public-token` (else random, printed once); dashboard supports token rotation | Re-issue; distribute to observers |
| Admin session | `serve --admin-user/--admin-password`, `--secure-cookie` behind TLS proxy | Rotate credentials; invalidate sessions |
| Worker credentials | (planned) worker↔control-plane auth | Rotate; re-enroll worker |
| Artifact-store keys | (planned) S3-compatible access keys | Rotate at provider; update workers |
| Provider API keys | `anthropic`/`openai` (spec/agent-eval); never logged | Rotate at provider if exposure suspected |

**Do-not-do (hard boundaries during any incident):**
- Never run generated challenge code on the control plane to "debug" it — use an isolated worker or
  `validate-runtime --sandbox`.
- Never mount the Docker socket into the control plane.
- Never hand-edit scoreboard standings — recompute from score events.
- Never mutate a published (immutable) artifact version — cut a new version.
- Never log a flag, session token, or provider key while gathering evidence.

**Evidence & audit:** every SEV-1/SEV-2 produces a timeline (detection, containment, remediation,
post-incident) and every privileged state change (score void, challenge pull, credential rotation)
is recorded with an explicit reason in the audit trail.
