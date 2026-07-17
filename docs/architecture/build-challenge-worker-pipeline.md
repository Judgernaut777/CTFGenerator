# The `build_challenge` worker pipeline

**Status:** first slice implemented. **Scope:** closes the missing consumer half
of the `build_challenge` job type named as the composite-seam blocker in
[`RELEASE_QUALIFICATION.md`](../RELEASE_QUALIFICATION.md) §1 item 4 and
[`evaluation/eval-worker-limitations.md`](../evaluation/eval-worker-limitations.md).
This note pins the design decisions; it does not re-derive ADR-001 (control
plane never executes challenge code) or ADR-004 (rootless-only runtimes), both
of which this pipeline is bound by.

## What existed before this slice

* `BuildService.trigger_build` (control plane) already enqueues a durable
  `build_challenge` job idempotently, keyed by the version's `spec_sha256`. It
  never builds anything itself (ADR-001).
* `Worker._dispatch` had no branch for `build_challenge`: `DISPATCHABLE_JOBS`
  omitted it and dispatch raised `ValueError` for it.
* `DockerRuntimeBackend.build_image` already existed and is real-Docker-proven
  (`tests/test_build_isolation_integration.py`): `docker build --network=none
  --force-rm --pull=false`, a post-build size ceiling that removes and refuses
  an oversized image, and a content-addressed digest return. It was unreachable
  from the worker run loop.
* `BuildMaterializationService` already proved the RENDER-vs-EXECUTE split is
  safe on the control plane: rendering a bundle is pure deterministic text
  generation (`generator.create_challenge` only writes files), so it is
  ADR-001-legal on the control plane. It renders and strips to `public/` only
  (contestant-safe artifact for the download endpoint) — the **full** bundle
  (private/, services/, docker-compose) was never packaged or served anywhere.
* `VALID_CREDENTIAL_SCOPES` already reserved `artifacts:pull` for "per-job
  scoped artifact handles" without a consumer.
* `worker_image_cache` (migration + ORM model) already existed as a
  scheduler-affinity read (`SqlAlchemyScheduler.candidate_workers` LEFT JOINs
  it, ranking-only, never a gate) with **no writer anywhere**.

## Job payload contract (unchanged, verified against `BuildService`)

```json
{"definition_slug": "<slug>", "version_no": 1, "spec_sha256": "<hex>"}
```

This is exactly what `BuildService.trigger_build` already enqueues; this slice
does not change the producer. `spec_sha256` is recorded **at enqueue time**,
read fresh from the `ChallengeVersion` row — this is the independent anchor the
worker's second verification step (below) compares against.

## How the worker obtains the buildable bytes

The worker has no DB credential and no filesystem reach into control-plane
storage (per `WorkerControlPlaneClient`'s own contract docstring: "the worker's
sole link to the control plane"). So `WorkerControlPlaneClient` gained one new
method:

```python
def fetch_build_bundle(
    self, definition_slug: str, version_no: int, now: datetime
) -> BuildBundle
```

(No explicit `token` parameter — matching the existing asymmetry in the
Protocol: queue verbs `claim`/`start`/`heartbeat`/`complete`/`fail` take an
explicit token threaded through `_process`; every other verb —
`get_instance`, `report_health`, `transition_instance`, and now this — is
handled by an implementation that holds its own token internally.)

* **`LocalControlPlaneClient`** (single-host/test path) delegates to a new
  gated application service, `WorkerBuildService.fetch_build_bundle`, which
  authenticates the token, requires the `artifacts:pull` scope (the reserved
  vocabulary entry, now wired to its first consumer), and calls a new
  `FullBundleService.render` — the FULL-bundle analogue of
  `BuildMaterializationService`: same pure-rendering legality (ADR-001), but
  packages **every** rendered file (not just `public/`) into the same
  byte-deterministic USTAR tar shape. `FullBundleService` is control-plane-only
  and **never** exposed through the contestant artifact-download surface — it
  embeds the flag/solution.
* **`HttpControlPlaneClient`** (networked path) calls a new worker-gateway
  route, `GET /worker/builds/{definition_slug}/{version_no}/bundle`, gated by
  the same `require_worker` + `artifacts:pull` scope check, returning the tar
  bytes as the response body with the content hash and the version's current
  `spec_sha256` in response headers (`X-Bundle-Sha256`, `X-Spec-Sha256`) —
  never inside a JSON envelope that would force a base64 round-trip of
  attacker-influenced bytes through Pydantic.

Both implementations share one `WorkerBuildService`/`FullBundleService` pair on
the control-plane side; the transport is the only thing that differs, mirroring
every other verb in this Protocol.

## Content-address verification (two independent checks, stated precisely)

The worker performs **two** checks, in order, before extracting a single byte
onto disk, let alone invoking `docker build`:

1. **Transport integrity**: recompute `sha256(received_bytes)` and compare to
   `bundle.bundle_sha256` (the hash the control plane computed from the exact
   bytes it is sending, carried alongside them). A mismatch means the bytes
   were corrupted or altered somewhere between the control plane's render step
   and the worker — refuse, no extraction, no build.
2. **Enqueue-vs-fetch drift**: compare `bundle.spec_sha256` (read fresh from
   the `ChallengeVersion` row **at fetch time**) to the job payload's
   `spec_sha256` (read from the same row **at enqueue time**, potentially
   minutes or hours earlier). A mismatch means the version was mutated (e.g.
   re-drafted) between enqueue and fetch — the job must not build content that
   no longer matches what was requested. Refuse, no build.

**What this does and does not prove**, stated as plainly as
`RELEASE_QUALIFICATION.md` insists elsewhere: this is **not** an
end-to-end-signed, MITM-proof integrity guarantee — a fully compromised control
plane could lie about both values, exactly as it could serve a worker any other
poisoned instruction. It **does** catch in-transit corruption/bugs and
enqueue-time/fetch-time version drift, which is the concrete, honest scope of
"content-address verification" available without introducing a signing scheme
(out of scope for this slice; the worker already trusts the control plane as
its one link, per the Protocol's own docstring).

Both checks are proven by unit tests with a fake client (`tests/
test_worker_build_dispatch.py`): a hash mismatch and a spec-drift mismatch each
refuse cleanly with **zero** calls into the build backend.

## Isolated image build

* The bundle is extracted into a **fresh temporary directory**
  (`tempfile.TemporaryDirectory`), never the worker's cwd or a shared path.
  Extraction is manual and defensive (`_safe_extract_bundle`): every tar member
  must be a plain regular file whose resolved path stays strictly inside the
  temp root — no absolute paths, no `..`, no symlinks/devices. This holds even
  though the bytes originate from the control plane's own renderer: **generated
  code is hostile input by construction** (ADR-001's own framing), so the
  extraction step does not trust the source, only the shape it validates.
* The generated code is **never executed on the worker outside of `docker
  build`** — no bundle script (`healthcheck.py`, `solver.py`, application code)
  is imported, `exec`'d, or shelled out to directly. It is packaged into the
  build context and handed to `docker build` as an opaque input; the image
  build itself runs inside the isolated Docker builder, not the worker
  process.
* **Build context selection**: a root-level `Dockerfile` is preferred; failing
  that, the lexicographically-first `services/<name>/Dockerfile` is used. This
  is a **known, documented simplification**: real generated families (e.g.
  `templates/network.py`) can render **multiple** `services/*/Dockerfile`
  trees orchestrated by a `docker-compose.yml` the renderer also writes. This
  slice builds exactly **one** image, matching the current single-image launch
  model end to end (`ContainerRequest.image_ref`, `RuntimeBackend.launch` take
  one image reference per instance) — there is no compose-aware
  launch path to hand a multi-image build to yet. A compose-aware
  build **and** launch model is a coherent follow-up, not invented here.
* **No network during the build** (`network=False`, `DockerRuntimeBackend`'s
  existing secure default). This is a **known, honest limitation**, not
  silently worked around: the generator's real Python-family Dockerfiles `RUN
  pip install` at build time, which needs egress. A no-network build correctly
  *refuses* those today rather than quietly granting hostile generated
  `RUN` steps network reach during the build (the security-relevant direction
  to fail in). The production fix is a pre-warmed local package
  mirror/build-cache reachable without general egress — tracked as a followup,
  not implemented here. The Docker-gated integration test in this slice
  therefore builds a tiny `alpine`-based bundle (no network needed at build
  time), exactly mirroring `test_build_isolation_integration.py`'s own
  established convention, so it proves the wiring without hitting this known
  gap.
* **Size ceiling**: reused verbatim from `DockerRuntimeBackend.build_image` (no
  new ceiling logic) — an oversized image is removed and refused via
  `UnsupportedRuntimeError`, which `Worker._process`'s existing exception
  branch already classifies as `infrastructure`/non-retryable (same path
  `_do_launch` already exercises).
* **No secrets in the build environment**: `build_image` accepts no
  `--build-arg`; nothing about the flag, seed, or credentials is ever passed to
  `docker build`, logged, or placed in a result. The temp directory is removed
  (`TemporaryDirectory`'s own cleanup) whether the build succeeds or raises.

## `BuildBackend` seam

A new `domain.execution.runtime.BuildBackend` Protocol (`build_image(...)
-> str`, `is_available() -> bool`) mirrors `RuntimeBackend`'s existing shape:
pure interface, no docker/subprocess import in `domain/`. `DockerRuntimeBackend`
already satisfies it **structurally** — its existing `build_image`/
`is_available` methods match the Protocol's shape exactly, so no new adapter
class is required; `main()` passes the same `DockerRuntimeBackend` instance for
both `backend` (launch/stop/...) and the new `build_backend` parameter. Unit
tests inject a `FakeBuildBackend` recording calls instead of shelling to
`docker`.

## How the built `image_ref` gets reported back

The job's `complete(result=...)` payload carries the outcome:

```json
{
  "definition_slug": "...", "version_no": 1, "bundle_sha256": "...",
  "image_ref": "ctfgen-build/<slug>:v<n>-<bundle_sha256[:16]>",
  "digest": "sha256:..."
}
```

This is the **completion-result contract** option named in the task brief,
deliberately chosen over extending `WorkerInstanceService`'s
fact/transition-reporting surface: `build_challenge` is **not** instance-scoped
(same reasoning `run_agent_evaluation` already established — it branches in
`_dispatch` *before* the `instance_id` extraction, alongside the eval job).
There is no instance to attach a runtime-resource/health report to; a
`ChallengeBuild`- or `Instance`-scoped fact would be a fiction.

**What this slice does not do** (an honest, scoped deferral, exactly like
`eval-worker-limitations.md`'s existing deferred-distributed-path section):
it does not yet write a `worker_image_cache` row, and it does not yet wire "a
launched instance's `image_ref` should be the freshly built one" into
`InstanceLifecycleService`/`SchedulingService`. Both are real, already-scaffolded
seams (`worker_image_cache`'s writer is simply unimplemented; the scheduler
already reads it for affinity ranking) but are a **separate** slice: consuming
a build result into instance placement is a scheduling/instance-creation
concern, not a worker-execution concern, and folding it in here would make this
slice larger than "the single most important missing seam" asks for. The job
`result` JSON is durable or worker completion; a follow-up projector (the
`EvalResultProjector` pattern) is the natural next step.

## Security posture summary (checklist against the hard rules)

* Content-hash verify before any build attempt — implemented, two independent
  checks, proven to refuse before touching the build backend.
* Hostile-code assumptions — generated code is never executed outside `docker
  build`; extraction is defensive against a malicious/corrupted tar regardless
  of its stated source.
* No docker socket exposure beyond the worker's existing model — reuses
  `DockerRuntimeBackend`, which already owns the only docker CLI invocation
  surface on the worker; no new socket/credential path.
* Never-log rule — the job payload/result carry references and hashes only;
  the fetched bundle bytes (which may embed the flag/solution) are never
  logged, and the worker's error paths log only `job_id`/`definition_slug`/
  `version_no`, matching the existing `_do_launch`/`_do_agent_eval` style.
* Worker identity/scopes gate the new verb exactly like existing ones —
  `fetch_build_bundle` is authenticated + `artifacts:pull`-scoped through the
  same `WorkerEnrollmentService.authenticate` + `require_scope` used by every
  other worker verb; no new bypass path.
