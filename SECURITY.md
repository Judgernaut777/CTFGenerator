# Security Policy

CTFGenerator generates, validates, and operates **deliberately vulnerable** cybersecurity
challenges. A generated challenge bundle is hostile-by-construction code: its service source
contains real exploitable bugs, and its `private/solver.py` is executable attack code. This policy
describes the security model, what data is sensitive, and how to report a vulnerability.

> Status note: the product is pre-release (version **0.1.0**). Sections below mark **current**
> behavior (grounded in the shipping codebase) versus **target** behavior (the V1 four-plane
> architecture that is planned, not yet built). Do not assume a target control is in place today.

---

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| `0.1.0` (current `main`) | Yes | Active development; fixes land on `main`. |
| Any earlier / tagged pre-release | No | Alpha software; upgrade to latest `main`. |

There is no LTS branch. Security fixes are applied to the latest `main` only until a stable
`v1.0` release exists.

---

## Security Model

### Core principle: challenges are hostile

Every generated challenge is treated as untrusted, attacker-controlled code. The vulnerable service
sources (`services/*/app.py`, `worker.py`, etc.) and the reference solver (`private/solver.py`) are
adversarial inputs, not trusted platform code.

### Control-plane / execution separation (target)

The V1 architecture splits into four planes with a hard boundary:

| Plane | Executes challenge code? | Docker socket? |
|---|---|---|
| Author Studio | No | No |
| Competition Control Plane | **Never** | **Never mounts it** |
| Execution Plane (isolated workers) | Yes, on isolated hosts | Rootless runtime only |
| Evaluation Lab | Via Execution Plane | No direct socket |

**Highest-priority boundary (target):** generated vulnerable workloads must **never** execute on the
control plane, and the control plane must **never** mount the Docker socket. Results flow from
workers back to the control plane only through explicit job-result contracts.

**Current reality:** generation and execution are not yet isolated. In the shipping code,
`runtime_validator` shells out to `docker compose` and, **by default, runs the bundle's
`tests/healthcheck.py` and `private/solver.py` on the host with the invoker's privileges**. The
`validate-runtime` CLI command prints a stderr warning to this effect. The `--sandbox` flag runs
those scripts inside an ephemeral read-only `python:3.11-slim` container instead. Until the
Execution Plane exists, treat any host running `validate-runtime`, `replay`, `validate-siblings
--runtime`, `eval-agent`, or `run-scenario --runtime` as capable of executing untrusted bundle code.

### Least privilege in generated bundles (current)

Generated `docker-compose.yml` applies runtime hardening to every service:

- `no-new-privileges`
- `cap_drop: [ALL]`
- `mem_limit` and `pids_limit`
- internal-only services attach to an `internal: true` network with no published port

The flag is never baked into an image; it flows in at runtime via `${CTFGEN_FLAG:-}` and is only
reachable by actually exploiting the service.

### MCP server boundary (current)

`mcp_server.py` exposes **only pure, side-effect-bounded tools** (spec/create/validate/score/
catalog/CVE-snapshot). It never imports `subprocess`, `runtime_validator`, `scenario_runtime`,
`agent_eval`, or `dashboard_server`, so connecting a model host never grants container builds or
host execution. Write tools resolve `output_dir` through `_resolve_in_workspace`; paths escaping the
workspace root (absolute-outside or `..` traversal) raise `WorkspaceError`. The root defaults to the
process CWD and is overridable via `CTFGEN_MCP_WORKSPACE`. CVE access over MCP is snapshot-only (no
network `nvd` source is reachable regardless of caller input).

### Trust boundary inside a bundle (current)

| Side | Files | Served to contestants? |
|---|---|---|
| Public | `public/`, service source, `docker-compose.yml`, `challenge.yaml` | Yes |
| Private / operator | `private/` (`flag`, `solver.py`, `variant.json`, `solution.md`, `scenario_timeline.json`, `checkpoints.yaml`) | **Never** |

The flag is never present in `public/`. Private solvers are never served to contestants.

---

## Sensitive Data and the Never-Log Rule

The following are secrets. They must **never** appear in logs, reports, artifacts, error messages,
or telemetry:

| Secret | Where it lives |
|---|---|
| Challenge flags | Injected at runtime via `${CTFGEN_FLAG:-}`; ground truth in `private/variant.json` (`flag`). |
| Session / admin tokens | `serve` dashboard sessions (`secrets`-generated), public scoreboard token, admin credentials (`--admin-user` / `--admin-password`). |
| Provider API keys | Anthropic / OpenAI keys used by the `spec --backend anthropic\|openai` path and `agent_eval`. |
| Private solvers | `private/solver.py` — reference attack code that trivially solves any sibling instance. |

**Never-log rule (invariant):** flags, session tokens, and provider API keys are never written to
logs or persisted reports; private solvers are never served to contestants. Report artifacts written
by `report_writer` intentionally carry validation/score/runtime metadata, **not** flags or
credentials — do not add secret material to a report `result` block.

Operational guidance:

- Pass provider keys via environment, never on the command line or in committed config.
- Run `serve` behind a TLS-terminating reverse proxy and use `--secure-cookie` (the built-in
  `http.server` is plain HTTP; the flag is only meaningful behind TLS).
- Treat `private/` and any `variant.json` as secret; never publish them alongside public artifacts.

---

## Reporting a Vulnerability

Please report security issues via responsible disclosure. **Do not** open a public GitHub issue for
a security vulnerability.

- See **[`docs/security/responsible-disclosure.md`](docs/security/responsible-disclosure.md)** for
  the disclosure process, scope, and contact/PGP details.
- Include: affected version/commit, component (CLI / MCP / dashboard / generated bundle / worker),
  reproduction steps, and impact.
- Do not include live flags, credentials, or provider API keys in your report.

We ask for coordinated disclosure and a reasonable remediation window before public write-up.

### In scope

- Control-plane execution of challenge code or Docker-socket exposure (target boundary violations).
- Workspace/path-escape in generation or MCP write tools.
- Flag / token / API-key leakage into public artifacts, logs, or reports.
- One team accessing another team's instance; duplicate-solve or scoreboard-integrity bypass.
- Dashboard auth bypass, session/token weaknesses.

### Out of scope

- The intended vulnerabilities inside a **generated challenge** (that is the product).
- Running effectful `validate-runtime` / `replay` / `eval-agent` without `--sandbox` on a host you
  control (documented behavior; run these on isolated hosts).
- V1 non-goals (public multi-tenant SaaS, arbitrary contestant Dockerfiles, arbitrary
  control-plane plugins, etc.).

---

## V1 Release Security Blockers

`v1.0` must not ship until every item below is satisfied. These derive from the platform's key
invariants and initial operating targets.

| # | Blocker | Invariant / target |
|---|---|---|
| 1 | Control plane never executes generated challenge code | Hard plane boundary |
| 2 | Control plane never mounts the Docker socket | Hard plane boundary |
| 3 | Challenge execution runs only on isolated workers with rootless Docker/Podman + rootless BuildKit | Execution Plane isolation |
| 4 | Zero public flag leakage — flags never in public artifacts, logs, or served content | ZERO public flag leakage |
| 5 | Private files (solver, variant, solution, timeline) never included in published/public artifacts | Private-file confidentiality |
| 6 | Flags, session tokens, and provider API keys are never logged | Never-log rule |
| 7 | Deterministic rebuild: identical `(generator version, spec, family version, seed)` ⇒ identical artifacts; zero deterministic-rebuild failures | ZERO deterministic-rebuild failures |
| 8 | Generated paths cannot escape the build directory; atomic build output | Path-containment invariant |
| 9 | Published versions are immutable and content-addressed | Immutable artifacts |
| 10 | A correct submission creates at most one solve per `(team, challenge, competition)` | Submission integrity |
| 11 | One team cannot access another team's instance | Tenant isolation |
| 12 | Every privileged state change is auditable; admin score changes require an explicit reason | Audit invariant |
| 13 | Network isolation and resource enforcement on every launched instance; instance expiration + cleanup | Execution Plane controls |
| 14 | External security review + recovery/upgrade/capacity drills completed | `v1.0` release gate |

---

*This file is a security policy, not a warranty. CTFGenerator produces intentionally vulnerable
software; deploy and operate it only in isolated environments you control.*
