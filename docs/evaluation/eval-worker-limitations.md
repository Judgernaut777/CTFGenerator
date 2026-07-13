# Agent-evaluation worker: what M15b ships and what it defers

M15b wires the `run_agent_evaluation` job end to end: a worker claims it, runs the
agent evaluation, and reports a **secret-free advisory result** that a
control-plane projector folds onto the `EvalRun`. This note records exactly which
path is implemented and which dependency is deferred, so the boundary is honest.

## The control-plane / worker boundary (ADR-001)

- The **control plane never runs the eval** and never imports `agent_eval` on any
  execution path. `EvalRunService.request_eval` only creates the `EvalRun` record
  and enqueues a references-only job; `EvalResultProjector` only folds an
  already-computed, secret-free result. The `mcp_server` import firewall
  (`test_mcp_server.MCPImportFirewallTests`) and `test_architecture_boundaries`
  stay green.
- The **effectful eval runs on the worker**: `workers.worker._do_agent_eval`
  drives an injected `EvalJobRunner`. `agent_eval` (Docker/subprocess/HTTP) is
  imported **lazily**, inside the runner's `run()`, so no import graph reachable
  from the control plane pulls it in.

## Implemented now: the single-host path

`workers.eval_runner.SingleHostEvalJobRunner` is the documented single-host
runner — the analogue of `LocalControlPlaneClient`. It requires the worker to
share a host **and a database** with the control plane. It:

1. loads the published `ChallengeVersion` from the DB,
2. reconstructs the `ChallengeSpec` and **renders the FULL bundle** in-process
   (rendering is pure deterministic text — ADR-001 permits it on any process,
   exactly as `BuildMaterializationService` renders the public bundle), then
3. runs `agent_eval` against the rendered bundle, which **builds and runs the
   challenge image via Docker on this host** (`already_running=False`) and tears
   it down.

Scripted profiles (`one_shot_prompt`, `writeup_replay`, `tool_using_agent`) need
**no LLM key** and are Docker-verified by the lead on this host.

## Deferred: the distributed path (depends on `build_challenge`)

A fully **distributed** worker — a separate host with no control-plane DB
credential — cannot use the single-host runner. It would need:

- the **FULL bundle delivered** to it (not the M14c public-only artifact — the
  worker must build and run the challenge *services*), and
- the **challenge image built** on the worker via the `build_challenge` worker
  pipeline, which is **not yet built**.

Until that pipeline exists, a networked worker leaves `eval_runner` unset; the
dispatch then reports a sanitized **advisory failure** ("eval runner not
configured … distributed eval requires the build_challenge pipeline") so the
`EvalRun` resolves instead of wedging pending. This mirrors M8 slice 2, which
shipped the single-host `LocalControlPlaneClient` and deferred the networked
transport.

## Credential-blocked: the `llm_agent` profile

`llm_agent` drives a real tool-using LLM and needs the `[anthropic]`/`[openai]`
extra plus a provider key — **credential-blocked in CI**. It is contract-tested
with a fake client (see `tests/test_agent_eval.py`); a live run is documented as
key-gated and is not part of the automated gate.

## Secret-free result (both layers)

- The **job payload** carries references only: `eval_run_id`, `definition_slug`,
  `version_no`, `profile`, `adversarial`.
- The **reported result** carries only the allowlisted advisory subset
  (`solved`/`steps`/`success_dropped`/`step_delta`) plus **redacted** notes, keyed
  by `eval_run_id`. The worker is the first secret-free guard (it redacts
  `ctf{…}`/`FLAG{…}`/`sk-…`/bearer tokens out of every forwarded note and never
  emits a `base_url`, candidate answer, or credential); `record_result`
  re-sanitizes defensively. Proven by
  `tests/test_worker_agent_eval_dispatch.py` (a planted flag is absent from the
  reported result) and `tests/test_eval_result_projector_integration.py` (absent
  from the persisted `EvalRun`).

## Advisory

Recording an eval result never gates publication or a competition (unchanged from
15a); `record_result` never blocks anything.
