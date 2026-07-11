# Title: ADR-001 — Never execute generated challenge code on the control plane

> One line: The competition control plane must never build, launch, validate, or
> solve generated challenge code and must never mount the Docker socket; all such
> execution moves to isolated workers reached only through explicit job and
> job-result contracts.

## Status

**Accepted**

## Date

`2026-07-11`

## Context

This decision touches the **worker trust model** and **runtime isolation** axes
(ADR-000 required-axes table) and enforces the plan's highest-priority boundary:
*generated vulnerable workloads must never execute on the control plane*, and the
invariant *control plane never mounts the Docker socket*.

**Current state (grounded in the codebase map).** Generation and execution run in
the **same process**, with no isolation boundary:

| Concern | Current mechanism | Effect |
|---|---|---|
| Build + launch + health-check + solve + teardown | `runtime_validator.py` → `CommandRunner._run` = real `subprocess.run` → `docker compose build/up/down` | In-process Docker orchestration |
| Bundle script execution | `runtime_validator` runs the bundle's `tests/healthcheck.py` and `private/solver.py` **on the host with the caller's privileges by default**; `--sandbox` (opt-in) runs them in an ephemeral read-only `python:3.11-slim` container | Untrusted, vulnerable-by-construction code executes on the host unless the operator opts in |
| Cross-instance replay | `replay_validator.cross_replay` reuses `runtime_validator` internals (`_run`, `_wait_for_health`) | Same in-process Docker path |
| Sibling validation | `sibling_validator` imports `generator`, `replay_validator`, `runtime_validator` | Same |
| Scenario / agent eval | `scenario_runtime.py`, `agent_eval.py` each reach into `runtime_validator`'s private helpers + `urllib` + `subprocess` | Leaky, un-abstracted execution layer smeared across five modules |
| CLI surface | `cli.py` subcommands `validate-runtime`, `replay`, `validate-siblings --runtime`, `run-scenario --runtime`, `eval-agent` are all **Effectful (Docker)** and invoke the above inline | The 1389-line god-module mixes arg parsing with Docker orchestration |

`cli.py` already carries a stderr WARNING that `healthcheck.py` / `solver.py` run
"on the host with your privileges" unless `--sandbox` is passed. The MCP server
(`mcp_server.py`) already honors this boundary in the small: it exposes only pure,
deterministic tools and **never imports** `runtime_validator`, `scenario_runtime`,
`agent_eval`, `dashboard_server`, or `subprocess`. This ADR generalizes that MCP
posture to the whole control plane.

**Forces.**
- The generated service source (`services/*/app.py`, `worker.py`) is
  *vulnerable by construction*; the reference `private/solver.py` is *adaptive*
  and runs arbitrary discovery/exploit logic. Running either where competition
  state, auth material, or secrets live is unacceptable.
- Target invariants that must hold: *flags/session-tokens/provider-keys never
  logged*; *one team cannot access another team's instance*; *private solvers
  never served to contestants*; *every privileged state change auditable*.
- The four-plane target (Author Studio, Competition Control Plane, Execution
  Plane, Evaluation Lab) already assigns build/launch/validate/solve to the
  **Execution Plane on isolated workers** and forbids the Control Plane from
  holding Docker socket access.

## Decision

We will make the control plane / execution plane split a hard architectural
boundary, enforced structurally rather than by convention.

1. **The control plane never executes generated challenge code.** No control-plane
   process builds images, launches instances, runs health checks, runs runtime or
   sibling or replay validation, runs scenario runtime, or runs agent eval. The
   control plane also never runs bundle-shipped scripts (`healthcheck.py`,
   `solver.py`) in-process, sandboxed or not.

2. **The control plane never mounts the Docker socket** and has no container
   runtime, BuildKit, or `docker`/`podman` binary available to it. (Target
   runtime, per plan: rootless Docker/Podman + rootless BuildKit, on workers
   only.)

3. **All execution moves to isolated workers.** The behaviors currently inside
   `runtime_validator`, `replay_validator`, `sibling_validator`,
   `scenario_runtime`, and `agent_eval` become worker responsibilities (Execution
   Plane / Evaluation Lab), running on separate isolated hosts.

4. **Control plane ↔ worker communication is only via explicit job and
   job-result contracts** (planned). The control plane enqueues a typed *job*
   describing what to do (e.g. build, launch, runtime-validate, replay,
   agent-eval) with the inputs it needs; a worker leases the job, executes it in
   isolation, and returns a typed *job-result* (status, logs, health outcome,
   solve outcome, produced artifact references). **Workers never modify
   competition-domain state directly** — results flow back only through the
   job-result contract, which the control plane validates and applies. (Job queue
   mechanism is a separate decision; per plan the intended substrate is
   PostgreSQL-backed job rows with `FOR UPDATE SKIP LOCKED`, leases, heartbeats,
   retries, idempotency keys, and dead-letter — see the Queue-strategy ADR when
   written.)

5. **Interface adapters call application services, not the execution layer.** CLI,
   REST API (planned), web (planned), and MCP invoke application services that
   enqueue jobs; no route handler or arg parser orchestrates Docker. This matches
   the target package shape: `domain` imports no docker/http/framework code;
   `application` depends only on domain interfaces; `workers` implement execution
   behind the job contract.

Conformance test: a change violates this ADR if any control-plane module imports
`runtime_validator`, `replay_validator`, `sibling_validator`, `scenario_runtime`,
`agent_eval`, or `subprocess`/`docker` for the purpose of executing challenge
code, or if any control-plane deployment is granted the Docker socket.

## Consequences

### Positive
- The highest-priority security boundary becomes structural: compromised or
  malicious generated code cannot reach competition state, secrets, or the Docker
  socket from a worker.
- Blast radius of the vulnerable-by-construction services and adaptive solvers is
  confined to disposable, isolated worker hosts.
- Execution logic that is today smeared across five modules and reached through
  `runtime_validator`'s private helpers gets consolidated behind one job contract,
  removing the leaky un-abstracted execution layer.
- CLI and API can share the same application services; the god-module `cli.py`
  loses its inline Docker orchestration.
- Generalizes the posture `mcp_server.py` already proves safe (pure tools only,
  no `subprocess`/`runtime_validator` import) to the whole control plane.

### Negative
- Requires building the job + job-result contract, a worker runtime, job
  dispatch, leasing/heartbeat/retry, and result application — none of which exist
  today (execution is currently a direct in-process `subprocess.run`).
- Adds operational surface: at least one isolated worker host must be deployed
  and reconciled alongside the control plane (V1 deployment model: one control
  plane + one or more isolated worker hosts).
- Local/dev ergonomics regress: `ctfgen validate-runtime` and friends can no
  longer "just run Docker here"; they must round-trip through a worker (or a
  dev-mode local worker) instead of executing inline.
- Latency and failure modes of an asynchronous job round-trip replace a single
  synchronous call.

### Neutral
- The job queue mechanism, worker protocol details, resource/network enforcement,
  and instance lifecycle/reconciliation are **out of scope here** and belong to
  the v0.2-alpha isolated-execution stage and their own ADRs.
- Artifact hand-off between planes (immutable, content-addressed published
  artifacts; local-FS dev / S3-compatible prod) is governed by the
  artifact-storage axis, not this ADR, but job-results must reference artifacts
  through that interface rather than passing host paths.
- The existing `--sandbox` ephemeral-container path in `runtime_validator` is
  superseded by worker isolation; it is not the target isolation mechanism.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| **Status quo — in-process Docker via `runtime_validator`** | Directly violates the highest-priority boundary: generated vulnerable code and adaptive solvers run in the same process/host as (future) competition state, secrets, and the Docker socket. |
| **In-process execution hardened with seccomp / read-only container (extend today's `--sandbox`)** | **Rejected.** Still co-locates untrusted execution and a container runtime with the control plane, still implies Docker socket / build capability on the control host, and leaves the leaky `runtime_validator`-internals coupling intact. Hardening a shared process is weaker than removing the capability entirely. |
| **VM-per-request isolation on the control host** | **Deferred.** Heavier operationally (per-request VM lifecycle, images, orchestration) than the isolated-worker + job-contract model, and does not by itself remove execution from the control plane. May revisit as a *worker-side* isolation upgrade, not as a control-plane mechanism. |
| **Separate workers but let them write competition state directly (shared DB writes)** | Rejected: breaks the rule that workers never modify competition-domain state directly and reintroduces a trust path from untrusted-execution hosts into the domain; results must flow through the validated job-result contract. |
