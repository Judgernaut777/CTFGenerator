# Runtime Isolation Policy for Challenge Workloads

**Status:** Security workstream deliverable (plan milestone 8). Defines the required isolation
policy for executing generated, vulnerable-by-construction challenge workloads.

Generated challenges are **hostile code by design** — each bundle ships an intentionally
vulnerable service plus a `private/solver.py` that exploits it. Executing that code is the single
highest-risk operation in the platform. This document specifies the isolation contract the
Execution Plane must enforce, contrasts it with today's in-process Docker invocation, and records
`validate-runtime --sandbox` as the current partial mitigation.

Terminology follows STABLE PLAN FACTS: **Control Plane** (auth/competitions/scoring; never executes
challenge code, never mounts the Docker socket) vs **Execution Plane** (isolated workers that build
images, launch instances, run health checks and the intended solver).

---

## 1. Current state (grounded in codebase map)

### 1.1 What runs, and where

| Aspect | Current behavior |
|---|---|
| Executor | `runtime_validator.py` shells out via `CommandRunner._run` → real `subprocess.run`, calling `docker compose build` / `up` / `down`. |
| Host mixing | Generation and execution run **in the same process**. `validate-runtime`, `replay`, `validate-siblings --runtime`, `eval-agent`, and `run-scenario --runtime` all reach into `runtime_validator` internals from the CLI process. |
| Default trust | `tests/healthcheck.py` and `private/solver.py` execute **on the host with the caller's privileges** by default. The CLI prints a stderr WARNING to this effect unless `--sandbox` is passed. |
| Partial mitigation | `validate-runtime --sandbox` runs healthcheck/solver **inside an ephemeral read-only `python:3.11-slim` container** instead of on the host. Opt-in only. |
| MCP boundary | `mcp_server.py` exposes only pure/deterministic tools; it never imports `subprocess`, `runtime_validator`, `scenario_runtime`, or `agent_eval`. Connecting a model host never yields container builds or host execution. |

### 1.2 Hardening already emitted into generated bundles

The rendered `docker-compose.yml` (see Generated File Layout) already carries per-service
hardening that the Execution Plane must preserve and extend:

| Directive (current) | Effect |
|---|---|
| `security_opt: no-new-privileges` | Blocks privilege escalation via setuid/setgid. |
| `cap_drop: [ALL]` | Drops all Linux capabilities. |
| `mem_limit` | Caps memory per service. |
| `pids_limit` | Caps process count per service. |
| flag via `${CTFGEN_FLAG:-}` | Flag injected at runtime through env, never baked into the image or `public/`. |
| `internal: true` network | Internal-only services attach with **no published port**; validator checks family `compose_service_markers` (e.g. `edge:`+`internal:`). |

### 1.3 Gaps (why milestone 8 exists)

- Solver/healthcheck run on the host by default (`--sandbox` is opt-in, not enforced).
- The compose file is author-controlled text; nothing today re-imposes the isolation policy at
  launch time or rejects a non-compliant bundle.
- No rootless requirement, no seccomp/AppArmor profile, no read-only rootfs, no CPU/disk/wall-clock
  enforcement, no per-team network isolation, no build-time credential scrubbing.
- Execution is smeared across five modules with no explicit worker/isolation boundary.

---

## 2. Target runtime isolation policy (planned)

**Planned.** Every challenge instance launched by an Execution Plane worker MUST satisfy all
controls below. Non-compliant bundles are rejected before launch, not hardened silently.

### 2.1 Container execution controls

| Control | Requirement | Current status |
|---|---|---|
| Rootless runtime | Rootless Docker or Podman on the worker; the daemon/engine does not run as root. | Planned |
| No privileged containers | `--privileged` forbidden; reject any bundle requesting it. | Planned |
| No host namespaces | No `network=host`, `pid=host`, `ipc=host`; each instance gets private net/PID/IPC. | Partial (compose uses `internal:` nets; host-ns not yet forbidden) |
| No Docker socket | `/var/run/docker.sock` never mounted into any workload. Control Plane never mounts it (KEY INVARIANT). | Planned / invariant |
| Dropped capabilities | `cap_drop: [ALL]`, add back none (or a minimal reviewed allowlist per family). | Current in compose |
| no-new-privileges | `security_opt: no-new-privileges` on every service. | Current in compose |
| Non-root user | Containers run as a non-root UID/GID; enforce `user:` and drop root in Dockerfiles. | Planned |
| Read-only rootfs | `read_only: true` where the workload is compatible. | Planned |
| tmpfs for writable | Writable paths mounted as size-capped `tmpfs`; no host bind-mounts of writable dirs. | Planned |
| seccomp | Restrictive seccomp profile (default-deny with a reviewed syscall allowlist). | Planned |
| AppArmor / SELinux | Mandatory-access-control profile applied per instance. | Planned |

### 2.2 Resource and lifetime limits

| Limit | Requirement | Current status |
|---|---|---|
| Memory | `mem_limit` enforced per service. | Current in compose |
| PIDs | `pids_limit` enforced per service. | Current in compose |
| CPU | CPU quota/shares cap per instance. | Planned |
| Disk | Ephemeral/overlay storage quota; capped tmpfs sizes. | Planned |
| Wall-clock timeout | Hard instance TTL and per-operation timeout; instance killed on expiry. | Partial — CLI `--timeout` (default 90) bounds a validation run, not a launched instance's lifetime |
| Expiration / cleanup | Every instance has an expiry; workers reconcile and tear down (`docker compose down`) leaked instances. | Planned (teardown exists; reconciliation planned) |

### 2.3 Network controls

| Control | Requirement | Current status |
|---|---|---|
| Per-instance network | Each instance on its own bridge network; internal services unpublished. | Partial (`internal: true` used today) |
| Controlled ingress | Only the intended player-facing port is exposed, via the reverse proxy; no direct worker port exposure. | Planned |
| Restricted egress | Default-deny egress from workload containers (no arbitrary outbound internet). | Planned |
| No metadata access | Block routes to cloud instance-metadata endpoints (e.g. link-local metadata IP). | Planned |

---

## 3. Build isolation (planned)

Image builds are as dangerous as instance runs and MUST be isolated from production credentials
and from the Control Plane.

| Control | Requirement |
|---|---|
| Rootless BuildKit | Builds run under rootless BuildKit / rootless Podman build. |
| Disposable build workers | Build environments are ephemeral and discarded after each build; no shared mutable state between builds. |
| No production creds | Build workers hold NO registry admin, DB, artifact-admin, or cloud credentials. Provider keys, flags, and session tokens are never present in the build environment (and never logged — KEY INVARIANT). |
| Content-addressed output | Published artifacts are immutable and content-addressed; identical (generator version, spec, family version, seed) ⇒ identical artifacts (KEY INVARIANT). |
| No arbitrary Dockerfiles | Contestant-supplied Dockerfiles are an explicit V1 non-goal; only generator-produced bundles are built. |

---

## 4. Per-team network design (planned)

Each team's live instance MUST be isolated such that one team cannot reach another team's instance
(KEY INVARIANT), and no instance can reach platform infrastructure.

| Rule | Requirement |
|---|---|
| Unique internal net | Each `(team, challenge, instance)` gets a dedicated internal network. |
| No cross-team route | No L2/L3 path between one team's instance network and another's. |
| No route to DB | Workload networks cannot reach the Control Plane's PostgreSQL. |
| No route to artifact admin | Workloads cannot reach artifact-store admin/write endpoints. |
| No cloud metadata | Cloud instance-metadata endpoints blocked from all workload networks. |
| Ingress only via proxy | Player traffic reaches the instance only through the TLS reverse proxy → intended port. |

---

## 5. Enforcement boundary summary

| Plane | May build images | May run challenge code | Mounts Docker socket |
|---|---|---|---|
| Control Plane | No | **Never** | **Never** (invariant) |
| Execution Plane (isolated workers) | Yes (rootless BuildKit) | Yes (isolated per §2) | No (rootless engine) |
| MCP server | No | No (pure tools only) | No |

**Migration note.** Today `validate-runtime --sandbox` is the only enforced isolation primitive,
and it is opt-in and covers only the healthcheck/solver step (ephemeral read-only container),
not the full workload. The target state moves all execution behind the Execution Plane worker
contract, makes isolation mandatory and non-bypassable, and rejects bundles that cannot satisfy
this policy rather than falling back to host execution.
