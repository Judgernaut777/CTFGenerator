# CTFGenerator Threat Model

> Plan section 7 · backlog #2 (HIGH). Structured threat model for the CTFGenerator
> productization effort. STRIDE-style per-component analysis grounded in the current
> codebase; all forward-looking controls are explicitly labelled **[target]**.

**Status:** current codebase is a single-process, stdlib-core Python generator/validator
(v0.1.0). The four-plane split, control-plane API, browser app, PostgreSQL persistence,
isolated workers, and artifact store are **[target]** — they do not exist yet. This
document models the target system so V1 release blockers can be tracked from day one,
and states current exposure honestly where a component already ships.

Legend:
- **[current]** — behavior present in the codebase map today.
- **[target]** — planned control; not yet built. Milestone tags (v0.1..v1.0) map to the
  plan's release stages.
- STRIDE = Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
  Elevation of privilege.

---

## 1. Assets

| # | Asset | Where it lives | Why it matters |
|---|---|---|---|
| A1 | Challenge flags | Injected at runtime via `${CTFGEN_FLAG:-}` env; ground truth in `private/variant.json` | Public leakage = competition integrity loss. Invariant: ZERO public flag leakage. |
| A2 | Private solvers / solutions | `private/solver.py`, `private/solution.md`, `private/checkpoints.yaml` | Never served to contestants; disclosure trivializes challenges. |
| A3 | Instance ground truth | `private/variant.json` (`flag`, `vuln_class`, routes, credentials/tokens, class_params) | Reveals the intended solve; per-team isolation depends on it. |
| A4 | Control-plane secrets **[target]** | DB DSN, session signing keys, provider API keys, worker-shared secrets | Compromise = full-platform compromise. |
| A5 | Competition state **[target]** | PostgreSQL: teams, submissions, solve events, score events, audit log | Source of truth for scoreboards; must be reconstructable and tamper-evident. |
| A6 | Auth material | Admin creds (`--admin-user/--admin-password`), session cookies, public scoreboard token | Spoofing / privilege escalation surface. |
| A7 | Provider API keys | `anthropic`/`openai` keys used by `spec_generator`, `agent_eval` | Cost + data-exfil risk; must never be logged (KEY INVARIANT). |
| A8 | Published artifacts **[target]** | Immutable, content-addressed challenge bundles in local-FS or S3 | Deterministic-rebuild + immutability invariants depend on integrity. |
| A9 | Worker credentials **[target]** | Worker registration/job-lease tokens | Rogue worker could poison results or exfiltrate flags. |
| A10 | Generated vulnerable workloads | `services/*/app.py`, `worker.py`, Dockerfiles, compose topology | Vulnerable **by construction** — treated as hostile once running. |
| A11 | Host / worker infrastructure | Docker/Podman daemon, build cache, host FS, cloud metadata endpoint | The blast-radius target of a container escape. |
| A12 | Reports & logs | `report_writer` JSON envelopes, structured logs **[target]** | Must not embed flags/keys/session tokens; feed audit + scoreboard reconstruction. |

---

## 2. Trust boundaries

The target architecture is four planes. The **highest-priority boundary**: generated
vulnerable workloads must NEVER execute on the control plane, which NEVER mounts the
Docker socket.

```
        [ Author Studio ]        [ Competition Control Plane ]
        spec/gen/validate/        auth · competitions · teams · publication
        review/approve            submissions · scoring · scoreboards · audit
              |                    (PostgreSQL; NO Docker socket; no challenge code)
              |                              |         ^
              v                              v         | job-result contract [target]
        [ Artifact Store ]  <----------  publish   ----+
        immutable, content-addressed                   |
                                                       v
                                        [ Execution Plane — ISOLATED WORKERS ]
                                        rootless Docker/Podman + BuildKit
                                        build · launch · health · solve · cleanup
                                                       |
                                        [ Evaluation Lab ] agent baselines, difficulty
```

Named boundaries called out in the brief:

| Boundary | Direction of distrust | Current state |
|---|---|---|
| B1 Contestant ↔ challenge instance | Contestant is an attacker with network access to their own instance only. | **[current]** compose services hardened (`no-new-privileges`, `cap_drop:[ALL]`, `mem_limit`, `pids_limit`); internal services on `internal:true` net with no published port. Per-team network isolation is **[target]**. |
| B2 Worker ↔ control plane | Worker is semi-trusted; runs hostile code, so results crossing back are distrusted. | **[target]** — no worker protocol exists; execution runs inline in `runtime_validator` today. |
| B3 Challenge container ↔ host | Container is fully hostile (vulnerable by construction). | **[current]** compose hardening only; rootless runtime + per-instance netns + metadata blocking are **[target]**. |
| B4 Control plane ↔ Execution plane | Control plane must never gain code-exec or socket access. | **[target]** — the two planes are one process today. |

---

## 3. Component analysis

Each row: STRIDE-relevant threat → current exposure → mitigation / owning milestone.

### 3.1 Control-plane API **[target]**

| Threat (STRIDE) | Current exposure | Mitigation · milestone |
|---|---|---|
| E/T: business logic in route handlers bypasses invariants | No API exists; `cli.py` is a 1389-line god-module inlining logic. | Thin routes over shared application services; no logic in handlers (TARGET PACKAGE SHAPE). v0.3. |
| E: control plane gains code-exec via challenge code | `runtime_validator` shells `docker compose` + runs bundle `solver.py` in-process. | Control plane NEVER imports execution modules or mounts Docker socket; all exec via worker job contract. v0.2/v0.3. |
| D: unbounded submission/scoring load | n/a | Submission processing <500ms server-side; PG job rows w/ SKIP LOCKED. v0.3. |
| R: privileged changes not attributable | Reports exist but no per-actor audit. | Every privileged state change auditable; admin score changes require explicit reason (KEY INVARIANT). v0.3. |

### 3.2 Browser app (admin dashboard + public scoreboard)

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| I/T: XSS in dashboard | **[current]** `dashboard_ui.py` uses `html` escaping only; hand-rolled 705-line `ThreadingHTTPServer`. Inline HTML, no external CDN. | Framework-templated escaping + CSP **[target]**. v0.4. |
| S: served over plain HTTP | **[current]** built-in server is plain HTTP; `--secure-cookie` only meaningful behind TLS proxy. | Reverse proxy with TLS (V1 deployment model). v0.4. |
| D: threading server resource exhaustion | **[current]** per-request threads, no limits. | Production ASGI server (FastAPI-class). v0.4. |

### 3.3 Authentication

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| S: credential spoofing | **[current]** single `--admin-user/--admin-password` pair passed on CLI; `secrets`-based session + token rotation in `dashboard_server`. | 8-role RBAC (owner..observer) over PG-backed identities. v0.3/v0.4. |
| I: creds on process args / in logs | **[current]** admin password is a CLI arg (visible in process table). | Secret-store / env-injected creds; flags/tokens/keys NEVER logged (KEY INVARIANT). v0.3. |
| S: public scoreboard token guessable | **[current]** `--public-token` random if omitted, printed once. | Scoped read-only observer token; rotation. v0.4. |

### 3.4 Sessions

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| S: session fixation / hijack | **[current]** in-process session login + rotation in `dashboard_server`; `Secure` attr only with `--secure-cookie`. | HttpOnly+Secure+SameSite cookies behind TLS; server-side session store in PG. v0.3/v0.4. |
| D: unbounded sessions in memory | **[current]** sessions in process memory. | Persistent, expiring sessions. v0.4. |

### 3.5 CSRF

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| T: cross-site state-changing requests to admin dashboard | **[current]** hand-rolled server, `parse_qsl` form handling — no CSRF token protection documented in the map. | CSRF tokens / SameSite cookies on all mutating routes. **[target]** v0.4. **Treat as a blocker before any non-localhost admin exposure.** |

### 3.6 PostgreSQL **[target]**

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| T: score/solve tampering | **[current]** JSONL event log (`events.py`) guarded by a bare `threading.Lock`; optional `postgres_events.py`. | Append-only score events; scoreboards reconstructable from persisted events (KEY INVARIANT). v0.3. |
| E: SQL injection | psycopg store exists (lazy). | SQLAlchemy 2.x parameterized queries + Alembic migrations. v0.3. |
| S: reachable from challenge containers | No network boundary today. | PG on control-plane network only; unreachable from worker/challenge nets (**marquee**, §4). v0.2/v0.3. |
| I: duplicate solves | Enforced only in-fold in `scoreboard.py`. | DB constraint: ≤1 solve per (team,challenge,competition) (KEY INVARIANT). v0.3. |

### 3.7 Artifact storage **[target]**

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| T: mutable / swapped published artifact | **[current]** bundles are plain files on disk; no content addressing, no immutability. | Immutable, content-addressed published artifacts; atomic build output. v0.1/v0.3. |
| I: private files leak into published artifact | **[current]** trust split exists (public/ vs private/); validator checks required files, but no publish-time enforcement. | Publish gate: private files NEVER in public artifacts; generated paths cannot escape build dir (KEY INVARIANTS). v0.1. |
| S/T: unauthenticated S3 access | n/a | Scoped credentials; server-side integrity check on fetch. v0.3. |

### 3.8 Worker registration **[target]**

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| S: rogue worker joins the pool | No worker protocol; execution is in-process. | Authenticated worker registration with issued credentials (A9). v0.2. |
| T: worker impersonation to claim jobs | n/a | Signed leases; worker identity bound to job claims. v0.2. |

### 3.9 Worker jobs (build/launch/solve) **[target]**

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| E: bundle code runs on host with operator privileges | **[current]** `validate-runtime`/`replay`/`agent_eval` run `tests/healthcheck.py` + `private/solver.py` **on the host by default**; `--sandbox` (ephemeral read-only container) is opt-in and CLI warns. | Move ALL execution to isolated workers; rootless Docker/Podman + rootless BuildKit. v0.2. |
| T: job double-processing / lost jobs | JSONL/lock model, no lease. | PG job rows: FOR UPDATE SKIP LOCKED, leases, heartbeats, retries, idempotency keys, dead-letter. v0.2. |
| D: runaway build/instance | **[current]** compose `mem_limit`/`pids_limit`; `--timeout` on runtime cmds. | Enforced resource limits + expiration/cleanup + reconciliation. v0.2. |

### 3.10 Worker result submission **[target]**

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| T: worker (running hostile code) forges competition state | **[current]** validators write reports/mutate state inline — no result contract. | Results flow ONLY through explicit job-result contracts; workers never modify competition-domain state directly (TARGET PACKAGE SHAPE). v0.2/v0.3. |
| S: unattributed results | Reports carry `git_commit`, no signer. | Result signed by worker identity; validated control-plane side. v0.2. |

### 3.11 Container build **[target]**

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| E: build-time code exec / cache poisoning | **[current]** `docker compose build` via host daemon in `runtime_validator`. | Rootless BuildKit on isolated worker; no shared privileged daemon. v0.2. |
| T: non-deterministic artifacts | Determinism invariant asserted; `meta_mapping()` has no wall-clock. | (gen version, spec, family version, seed) ⇒ identical artifacts; ZERO deterministic-rebuild failures (INVARIANT/target). v0.1. |

### 3.12 Container runtime

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| E: container escape to host | **[current]** compose hardening (`no-new-privileges`, `cap_drop:[ALL]`); host daemon still root. | Rootless runtime + seccomp/AppArmor + read-only rootfs. v0.2. |
| I: reach host FS / Docker socket | No socket mounted in generated compose (map shows none). | No socket in any challenge container; per-instance user namespaces (**marquee**, §4). v0.2. |
| D: resource exhaustion of worker | **[current]** `mem_limit`/`pids_limit` per service. | Full cgroup limits + expiration. v0.2. |

### 3.13 Challenge networks

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| I: one team reaches another team's instance | **[current]** `internal:true` networks isolate service tiers *within* one bundle; no cross-instance isolation model. | Per-(team,instance) network namespace; one team CANNOT access another's instance (KEY INVARIANT) (**marquee**, §4). v0.2. |
| I: challenge reaches control-plane / PG / metadata | No egress control today. | Default-deny egress; block cloud metadata (169.254.169.254) (**marquee**, §4). v0.2. |

### 3.14 Private solvers

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| I: solver served to contestants | **[current]** trust split keeps `private/solver.py` out of `public/`; solver is adaptive/class-agnostic. | Publish gate + serving layer: private solvers NEVER served to contestants (KEY INVARIANT). v0.1/v0.4. |
| E: solver runs on host during validation | **[current]** runs on host by default (see 3.9). | Solver executes only inside isolated worker sandbox. v0.2. |
| I: hostile container reads solver ground truth | Same host FS today. | Solver/variant never mounted into the attackable container (**marquee**, §4). v0.2. |

### 3.15 CVE retrieval

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| I/T: SSRF or poisoned data via live NVD | **[current]** `NvdCveSource` (live NVD 2.0) reachable from CLI `--source nvd`; `CachingCveSource` writes TTL cache files. MCP is **snapshot-only** (no `nvd` selectable regardless of caller input). | Keep MCP snapshot-only; treat NVD as untrusted input, validate parsed records; pin/allowlist host. v0.1. |
| D: cache file tampering | Cache JSON has no version/integrity field (§12 gap). | Schema-versioned, validated cache. v0.1. |

### 3.16 LLM providers

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| I: provider API key leakage | **[current]** `anthropic`/`openai` used by `spec_generator`, `agent_eval` (lazy, injectable). | Keys NEVER logged (KEY INVARIANT); env/secret-store injection. v0.1/v0.3. |
| T: LLM injects code/flags into spec | **[current mitigation]** LLM emits ONLY `_LLM_SCHEMA` (title/objectives/checkpoints); `additionalProperties:false`; category/`ai_resistance`/flags are deterministic server-side. | Preserve this schema boundary; validate all LLM output. v0.1. |
| D: unbounded provider cost/exfil | n/a | Rate/size limits on backend calls. v0.5. |

### 3.17 MCP integration

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| E: model host gains host-write / recursive-delete | **[current mitigation]** `_resolve_in_workspace` confines `output_dir` to a workspace root (`CTFGEN_MCP_WORKSPACE`/CWD); `..`/absolute-escape → `WorkspaceError`. Rationale: `force=True` does `shutil.rmtree` first. | Maintain sandbox; keep root non-overlapping with control-plane data. v0.1. |
| E: model host triggers Docker/host exec | **[current mitigation]** MCP exposes ONLY pure tools; never imports `scenario_runtime`, `agent_eval`, `dashboard_server`, or `subprocess`; CVE access snapshot-only. | Keep the CLI-only execution boundary intact. v0.1. |

### 3.18 Logging **[target]**

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| I: secrets in logs | **[current]** ad-hoc stderr prints; no structured logging. | Structured JSON logging; flags/session-tokens/provider-keys NEVER logged (KEY INVARIANT); redaction filters. v0.3. |
| R: insufficient audit trail | Reports only. | Per-actor audit for every privileged state change. v0.3. |

### 3.19 Reports

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| I: flag/ground-truth in a report artifact | **[current]** `report_writer` serializes command results (validation/runtime/replay/scoreboard/scenario). Runtime/replay logs could echo solver output. | Redact flags/variant ground truth from persisted reports. v0.2/v0.3. |
| T: report tampering | **[current]** filename carries a SHA-1 `disc` over result; envelope has `git_commit` but no signature. | Content-addressed / signed reports if used for audit. v0.3. |

### 3.20 Backup files **[target]**

| Threat | Current exposure | Mitigation · milestone |
|---|---|---|
| I: backups contain flags/keys in cleartext | No backup subsystem today. | Encrypted backups; RPO 5min / RTO 30min; recovery drill at v1.0. v0.4/v1.0. |
| T: backup restore integrity | n/a | Verified restore; scoreboards reconstructable post-restore. v1.0. |

---

## 4. Marquee threat — challenge-container containment

**A compromised challenge container is assumed. It must NOT reach any of the following.**
This is the load-bearing security property of the platform.

| Must NOT reach | Why | Control · state |
|---|---|---|
| Control-plane secrets (A4) | Full-platform compromise | Control plane on a separate host/network; no secrets on workers beyond the job. **[target]** v0.2/v0.3. |
| PostgreSQL (A5) | Tamper competition state | PG reachable only from control-plane net; challenge nets have no route to it. **[target]** v0.2/v0.3. |
| Worker credentials (A9) | Impersonate worker, poison results | Worker creds never mounted into challenge containers. **[target]** v0.2. |
| Other teams' instances (A3) | Cross-team cheating / flag theft | Per-(team,instance) network namespace; one team cannot access another's instance (KEY INVARIANT). **[current]** only intra-bundle `internal:true` isolation; cross-instance **[target]** v0.2. |
| Container sockets (Docker/Podman) | Trivial host escape → root | No socket mounted in any challenge container (none present in generated compose today). Enforce at launch + rootless daemon. **[current]** none mounted; **[target]** enforcement v0.2. |
| Private solvers / variant ground truth (A2/A3) | Trivializes the challenge | `private/*` never mounted into the attackable container; solver runs only in isolated sandbox. **[current]** trust split; **[target]** worker isolation v0.2. |
| Host filesystem (A11) | Escape / data theft | Rootless runtime + read-only rootfs + user namespaces + `cap_drop:[ALL]` + `no-new-privileges`. **[current]** caps/privs dropped; **[target]** rootless + userns v0.2. |
| Cloud metadata (169.254.169.254) | Steal cloud IAM creds | Default-deny egress; explicit block of link-local metadata. **[current]** none; **[target]** v0.2 (see `cloud_metadata_ssrf` family — this is exactly the class we generate). |

**Gap today:** execution runs in-process on the operator's host (`runtime_validator._run`,
host-by-default solver/healthcheck), with no per-team network isolation and a root Docker
daemon. The marquee property is **NOT yet enforced**; it is the central deliverable of the
Execution Plane (v0.2).

---

## 5. V1 release blockers

Ordered; each must be closed before v1.0 (external security review + recovery drill).

1. **Generated code never executes on the control plane.** Control plane must not import
   execution modules or mount the Docker socket (KEY INVARIANT). *Owner: v0.2/v0.3.*
2. **Isolated Execution Plane.** All builds/launches/solvers on isolated workers via
   rootless Docker/Podman + rootless BuildKit; no host-by-default bundle execution. *v0.2.*
3. **Challenge-container containment (marquee, §4) enforced** — secrets, PG, worker creds,
   other-team instances, sockets, solvers, host FS, cloud metadata all unreachable. *v0.2.*
4. **Per-team instance isolation.** One team cannot reach another team's instance. *v0.2.*
5. **Authenticated worker protocol + signed job-result contract.** Workers never mutate
   competition-domain state directly. *v0.2/v0.3.*
6. **PostgreSQL domain model with integrity constraints** — ≤1 solve per
   (team,challenge,competition); append-only score events; scoreboards reconstructable. *v0.3.*
7. **AuthN/AuthZ over 8 roles** with sessions + CSRF protection on all mutating routes;
   no creds on process args. *v0.3/v0.4.*
8. **Secret hygiene** — flags, session tokens, and provider keys NEVER logged; structured
   logging with redaction; full audit for privileged changes. *v0.3.*
9. **Zero public flag leakage** — publish gate keeps private files + solvers out of public
   artifacts; flags only reachable by exploiting the service. *v0.1/v0.4.*
10. **Immutable, content-addressed published artifacts** + zero deterministic-rebuild
    failures. *v0.1/v0.3.*
11. **TLS reverse proxy**; dashboard not served plain-HTTP in production; secure cookies. *v0.4.*
12. **Backup/restore with encryption** meeting RPO 5min / RTO 30min, validated by a
    recovery drill. *v0.4/v1.0.*

**Preserve (already-shipped controls that must not regress):** MCP pure-tools-only boundary
+ workspace sandbox; LLM `_LLM_SCHEMA` boundary (no code/flags from the model); MCP
snapshot-only CVE access; compose hardening (`cap_drop:[ALL]`, `no-new-privileges`,
`mem_limit`, `pids_limit`); public/private trust split.
