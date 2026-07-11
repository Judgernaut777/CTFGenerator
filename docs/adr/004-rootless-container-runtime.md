# Title: ADR-004 — Run challenge workloads and image builds under a rootless container runtime on isolated workers

> One line: challenge image builds and instance launches run under **rootless
> Docker/Podman + rootless BuildKit** on isolated worker hosts, behind a
> runtime-backend interface — never privileged, no host namespaces, no Docker
> socket, resource-limited.

## Status

**Accepted**

## Date

`2026-07-11`

## Context

This decision touches the **Runtime isolation** and **Worker trust model** axes
(ADR-000 required-axis table) and upholds the plan's highest-priority boundary:
*generated vulnerable workloads must never execute on the control plane.*

Current state (grounded in the codebase map):

- **Root-ful Docker, in-process, same host.** `runtime_validator.py` shells out
  via `_run` (real `subprocess.run`) to `docker compose build` / `up` / `down`,
  polls `tests/healthcheck.py`, and runs `private/solver.py`. This is invoked
  inline by `validate-runtime`, `replay`, `validate-siblings --runtime`,
  `run-scenario --runtime`, and `eval-agent` — all **CLI-only** effectful paths.
- **Bundle code runs on the host with caller privileges by default.**
  `validate-runtime` prints a stderr WARNING that `tests/healthcheck.py` and
  `private/solver.py` execute on the host with your privileges; `--sandbox` is
  **opt-in** and only reruns those two scripts inside an ephemeral read-only
  `python:3.11-slim` container. The Docker build/up itself still uses the host
  daemon.
- **Some hardening already lives in the generated bundle.** `docker-compose.yml`
  renders services with `no-new-privileges`, `cap_drop: [ALL]`, `mem_limit`,
  `pids_limit`, and attaches internal-only services to an `internal: true`
  network with no published port. The flag is injected at runtime via
  `${CTFGEN_FLAG:-}` and is never present in `public/`.
- **Non-HTTP families declare their own invocation.** `private/runtime.json`
  (read by `runtime_validator._load_runtime_manifest`) overrides how
  health/solve scripts are invoked for raw-TCP binary and Modbus/SCADA families
  that are not web-on-8080.
- **No worker/execution boundary exists.** `runtime_validator._run` is reached
  directly by `replay_validator`, `sibling_validator`, `scenario_runtime`, and
  `agent_eval` via private helpers — a leaky, un-abstracted execution layer with
  no isolation seam.

The `serve` control-plane surface (`dashboard_server.py`) and the MCP server
(`mcp_server.py`) already **never** shell out to Docker; MCP explicitly imports
no `subprocess` and no runtime modules. That non-execution property of the
control plane must be preserved and formalized, not regressed.

Invariants this decision must uphold: *control plane never mounts the Docker
socket*; *generated paths cannot escape the build dir*; *one team cannot access
another team's instance*; *flags/session-tokens/provider-keys never logged*;
*identical (generator version, spec, family version, seed) ⇒ identical
artifacts* (the runtime backend must not perturb deterministic build output).

## Decision

We will run **all** challenge image builds and instance launches under a
**rootless** container runtime on **isolated worker hosts**, mediated by a
single runtime-backend interface. Specifically (all **target**, none built yet):

1. **Rootless runtime.** Builds use **rootless BuildKit**; instances run under
   **rootless Docker or rootless Podman**. The daemon/engine runs as an
   unprivileged user in a user namespace. No container is ever `privileged`, no
   host namespace is shared (`--pid=host`, `--net=host`, `--ipc=host` are
   forbidden), and no `cap_add` beyond the empty set the bundle already declares.
2. **Runtime-backend interface.** A single port (e.g. `RuntimeBackend`) abstracts
   `build`, `up`, `health_check`, `run_solver`, `down`, and log collection. The
   current `runtime_validator` code becomes **one implementation** behind it; the
   private-helper reach-ins from `replay_validator` / `sibling_validator` /
   `scenario_runtime` / `agent_eval` are replaced by calls through this port.
   Backend selection (rootless Docker vs. rootless Podman) is configuration.
3. **Isolated workers only.** The backend executes solely on Execution-Plane
   worker hosts. The Competition Control Plane never links, imports, or invokes
   the backend, and **never mounts the Docker socket**. Jobs reach workers via
   the PostgreSQL-backed job queue (see plan tech baseline), and results return
   through explicit job-result contracts — workers never mutate competition
   domain state directly.
4. **No socket exposure inside workloads.** The Docker/Podman socket is never
   bind-mounted into any challenge container. Challenge services get no access to
   the runtime API.
5. **Resource + network enforcement is mandatory, not bundle-optional.** The
   backend enforces CPU, memory, PID, and wall-clock limits and network
   isolation at launch time, independent of what a rendered `docker-compose.yml`
   requests. The existing compose hardening (`no-new-privileges`,
   `cap_drop: [ALL]`, `internal: true`) remains the floor, not the ceiling.
6. **Untrusted bundle scripts run confined.** `healthcheck.py` and `solver.py`
   run inside the isolated runtime, not on the worker host with ambient
   privileges. The current opt-in `--sandbox` behavior becomes the **default and
   only** mode on workers; running bundle scripts directly on the host is removed
   from the worker path.

## Consequences

### Positive
- The highest-priority boundary is enforced structurally: vulnerable code and
  the container runtime live on isolated workers; the control plane keeps its
  existing no-Docker property and never touches the socket.
- Rootless execution removes the root-daemon escalation surface: a container
  escape lands as an unprivileged host user in a user namespace, not root.
- One `RuntimeBackend` port ends the leaky reach-ins into
  `runtime_validator`'s private helpers and makes Docker-vs-Podman a config
  choice, not a code fork.
- Mandatory launch-time resource/network limits make instance behavior
  predictable under the initial operating targets (25 teams, 20 challenges).

### Negative
- **Rootless limitations.** Rootless runtimes constrain what workloads can do:
  no binding to privileged ports (<1024) without extra config, default userland
  networking (e.g. slirp4netns/pasta) with lower throughput than root bridging,
  restricted cgroup delegation (needs cgroup v2 + systemd delegation for
  reliable `mem_limit`/`pids_limit`/CPU caps), no host devices, and limited
  overlay/storage-driver options. Families assuming raw sockets, kernel modules,
  privileged capabilities, or low ports will not run unchanged.
- **Per-family compatibility must be re-verified.** The 8 families were built
  against root-ful Docker. Each needs validation under rootless:

  | Family / trait | Rootless risk |
  |---|---|
  | `web_business_logic_tenant_export` (API + Redis + worker) | Low — HTTP on high ports; verify Redis + worker networking under userland net. |
  | `crypto_token_forgery` (single web service) | Low — HTTP on high port. |
  | `cloud_metadata_ssrf` (`/internal/objects`) | Medium — internal-network SSRF target must resolve under rootless networking. |
  | `network_lateral_pivot` (edge→internal pivot) | Medium — multi-network pivot topology depends on userland net behavior. |
  | `scada_ics_modbus_takeover` (Modbus/PLC, `runtime.json`) | High — non-HTTP raw-TCP; verify port/protocol under rootless net + `runtime.json` invocation. |
  | `binary_heap_exploit` (raw-TCP, `runtime.json`) | High — raw-TCP service; low-port/protocol assumptions must be checked. |
  | `forensics_incident_triage` | Low — likely offline/artifact-driven. |
  | `mobile_insecure_storage` | Low–Medium — verify service exposure and any emulation needs. |

- **Migration burden.** `validate-runtime`'s host-execution default and the four
  private-helper consumers must be routed through the new port before the
  rootless worker path can be trusted. The scenario-runtime HTTP glue
  (`scenario_runtime.py`) and `agent_eval` must target confined instances.

### Neutral
- The runtime-backend port is the seam a future stronger-isolation ADR plugs
  into (see Alternatives) — no compose/bundle rewrite is required to swap the
  backend implementation.
- Determinism is a build-input property (generator version, spec, family
  version, seed); the runtime backend must not feed wall-clock or host-specific
  state into builds, so BuildKit invocations stay reproducible.
- CLI ergonomics change on workers: the host-privilege WARNING path is retired
  in favor of always-confined execution; local developer CLI use outside the
  worker plane is out of scope for this ADR.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| **Keep root-ful Docker on the same host (status quo)** | Violates the highest-priority boundary — generated vulnerable workloads and bundle scripts run on the control-plane host with root-daemon access. Rejected. |
| **Privileged Docker containers** (`--privileged`, host namespaces, `cap_add`) | Directly contradicts the no-privilege / no-host-namespace requirement and undoes the bundle's existing `cap_drop: [ALL]` hardening. Rejected. |
| **Bind-mount the Docker socket into a helper/worker container** | The socket is root-equivalent; mounting it anywhere the control plane can reach breaks the "control plane never mounts the Docker socket" invariant. Rejected. |
| **gVisor (runsc) sandboxed runtime** | Stronger syscall-level isolation, but heavier and not required for V1's rootless-on-isolated-workers threat model. **Noted as future hardening** — pluggable behind the `RuntimeBackend` port. |
| **Kata Containers (VM-isolated)** | VM-per-container isolation exceeds V1 needs and adds nested-virtualization/operational cost; the single-node infra premise is already untested. **Noted as future hardening** behind the same port. |
| **Kubernetes + pod security policies** | Explicit V1 non-goal (no Kubernetes operator); over-scoped for the single control-plane + isolated-worker deployment model. Rejected for V1. |
