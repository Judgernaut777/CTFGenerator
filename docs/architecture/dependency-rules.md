# Package Dependency Rules

Status: **TARGET / planned** architecture. The rules below describe the destination
layered layout for `src/ctf_generator/`, not the code as it exists today. Where a
constraint is contrasted against the current flat package, that is stated explicitly.

This document is the **spec that the CI import-boundary test implements** (see
[The architectural import test](#the-architectural-import-test)). Any layered module added
under `src/ctf_generator/` must satisfy these rules or CI fails.

---

## 1. Current state (flat) vs. target (layered)

**Current (2026-07-11):** a single flat package `src/ctf_generator/` (~35 modules) with no
enforced layering. `cli.py` (1389 lines) imports nearly every subsystem; `families.py` is a
central import hub with a by-convention circular-import contract ("templates must NOT import
`families`") enforced only by comments; `runtime_validator._run` shells out to `docker compose`
and executes bundle-shipped `solver.py`/`healthcheck.py` in-process. Optional deps
(`anthropic`/`openai`, `psycopg`, `mcp`) are imported lazily inside their own modules, each
behind a per-module Protocol (`SpecBackend`, `EventStore`, `Connection`) — there is no single
infrastructure seam.

**Target:** five layers with a strict one-directional dependency rule.

```
interfaces ──▶ application ──▶ domain ◀── infrastructure
                   ▲                          │
                   └──────────────────────────┘
                     (via domain-defined ports)
workers ──▶ application (+ domain); results flow back only via job-result contracts
```

The core rule (from the stable plan): **domain imports NO http/docker/postgres/mcp/LLM/framework
code; application depends only on domain interfaces/protocols; infrastructure implements those
protocols; interfaces (api/cli/web/mcp) call application services; CLI and API share the same
application services; no business logic in route handlers or arg parsers; workers never modify
competition-domain state directly.**

---

## 2. Target directory tree

```
src/ctf_generator/
├── __init__.py                 # package + __version__ (no layer)
├── __main__.py                 # python -m ctf_generator → interfaces.cli
│
├── domain/                     # pure model + business rules; stdlib only
│   ├── models.py               # ChallengeSpec, ScenarioSpec, scoring/competition configs
│   ├── spec_rules.py           # validate_spec rules, spec_to_dict / spec_from_dict
│   ├── families/               # Family registry + FamilyRenderer Protocol + templates
│   │   ├── registry.py         # register/get/family_names/_REGISTRY
│   │   └── templates/          # pure renderers (crypto, network, tenant_export, ...)
│   ├── scenario.py             # scripted trigger/response engine (pure, no Docker/HTTP)
│   ├── scoring/                # score.py, scoring_engine.py, scoreboard.py (pure folds)
│   ├── cve.py                  # CveRecord, CveBlueprint, blueprint_from_cve (pure)
│   ├── events.py               # Event dataclass + EventStore Protocol (port only)
│   └── ports.py                # domain-owned Protocols (repositories, sources, backends)
│
├── application/                # use-cases / orchestration; depends only on domain
│   ├── generate.py             # create_challenge, create_challenge_from_cve
│   ├── spec.py                 # build/validate/write spec use-cases
│   ├── validate.py             # static validation use-case
│   ├── execution.py            # runtime/replay/sibling orchestration (via execution port)
│   ├── scoring.py              # score, scoreboard, competition service use-cases
│   ├── competition.py          # competitions/teams/submissions/audit use-cases
│   └── reporting.py            # report envelope + index use-cases
│
├── infrastructure/             # adapters implementing domain ports; owns optional deps
│   ├── docker_runtime.py       # docker compose build/up/down; subprocess CommandRunner
│   ├── persistence/
│   │   ├── jsonl_events.py      # JsonlEventStore (implements EventStore)
│   │   └── postgres_events.py   # psycopg-backed store (lazy import)
│   ├── llm/
│   │   ├── anthropic_backend.py # implements SpecBackend
│   │   └── openai_backend.py
│   ├── cve/
│   │   ├── snapshot_source.py    # SnapshotCveSource (bundled fixture)
│   │   ├── nvd_source.py         # NvdCveSource (network)
│   │   └── caching_source.py     # CachingCveSource (TTL file cache)
│   ├── artifacts/               # local-FS + S3 artifact storage (implements storage port)
│   ├── yaml_writer.py           # dump_yaml emitter
│   └── report_writer.py         # report envelope writer (git via subprocess)
│
├── interfaces/                 # thin adapters over application services
│   ├── cli.py                   # argparse front door (no business logic)
│   ├── api/                     # ASGI (FastAPI or comparable) route handlers
│   ├── web/                     # web UI
│   └── mcp_server.py            # MCP tools (pure/deterministic surface only)
│
└── workers/                    # isolated job executors; results via job-result contracts
    ├── protocol.py              # job + job-result contract types
    ├── runner.py                # claim/lease/heartbeat/retry loop (PG SKIP LOCKED)
    └── jobs/                    # build, launch, healthcheck, runtime-validate, agent-eval
```

Family templates live **inside** `domain/families/templates/` and keep the existing purity
contract: a template imports only domain model + the YAML emitter, never the registry.

---

## 3. Allowed-imports matrix

Rows = importer layer; columns = imported layer. `yes` = permitted; `no` = forbidden edge
(CI fails). "stdlib" and third-party import policy is covered per-layer in §5.

| Importer \ Imports | domain | application | infrastructure | interfaces | workers |
|---|---|---|---|---|---|
| **domain**         | yes (intra-layer) | no | no | no | no |
| **application**    | yes | yes (intra-layer) | no | no | no |
| **infrastructure** | yes | no | yes (intra-layer) | no | no |
| **interfaces**     | yes¹ | yes | yes² | yes (intra-layer) | no |
| **workers**        | yes | yes | yes² | no | yes (intra-layer) |

¹ **interfaces → domain** is limited to domain *types* used in signatures/serialization
(e.g. `ChallengeSpec`, DTO shapes). Interfaces must not re-implement domain rules; validation
and orchestration go through `application`.

² **interfaces/workers → infrastructure** is permitted **only at the composition root** (a single
wiring/DI module per interface or worker entrypoint) that constructs concrete adapters and injects
them into application services. Business modules within interfaces/workers depend on domain ports,
not concrete infrastructure. TARGET: the import test may narrow the allowed infrastructure edge to
designated `*/wiring.py` modules.

Key consequences:

- **domain depends on nothing but itself.** No layer name and no framework/IO library may appear
  in a domain import.
- **application depends only on domain** (its models and its ports/Protocols). It never imports
  `infrastructure`, `interfaces`, or `workers`, and never imports Docker/HTTP/DB/LLM libraries.
- **infrastructure depends on domain** (to implement its ports) and nothing higher.
- **CLI and API are peers**: both are `interfaces` and both call the same `application` services.
  No business logic in route handlers or arg parsers.
- **workers never modify competition-domain state directly.** A worker runs a job and returns a
  job-result contract (see `workers/protocol.py`); the control plane applies the result via an
  `application` use-case. This encodes the highest-priority boundary: generated vulnerable
  workloads execute only on isolated workers, never on the control plane.

---

## 4. Forbidden imports per layer (library / edge bans)

Beyond the layer-to-layer matrix, each layer bans specific external and IO modules. The domain
ban list is the load-bearing one and is checked by substring/prefix match on import roots.

| Layer | Forbidden import roots | Rationale |
|---|---|---|
| **domain** | `http`, `http.server`, `urllib`, `socket`, `docker`, `subprocess`, `psycopg`, `mcp`, `anthropic`, `openai`, `fastapi`, `starlette`, `uvicorn`, `sqlalchemy`, `alembic`, `boto3`, `pydantic`¹ | Domain is pure, deterministic, IO-free. It is the only layer whose ban list CI treats as a hard, non-negotiable gate. |
| **application** | `http.server`, `urllib`, `socket`, `docker`, `subprocess`, `psycopg`, `mcp`, `anthropic`, `openai`, `fastapi`, `starlette`, `uvicorn`, `sqlalchemy`, `boto3` | Application orchestrates via domain ports only; concrete IO/framework belongs to infrastructure/interfaces. |
| **infrastructure** | `fastapi`, `starlette`, `uvicorn` (ASGI framework), and importing `interfaces`/`workers`/`application` | Adapters must not reach up into the delivery/framework layer. Optional deps (`psycopg`, `anthropic`, `openai`, `boto3`, `docker`/`subprocess`) are **permitted here and here only**, imported lazily. |
| **interfaces** | direct `docker`/`subprocess` challenge execution; direct `psycopg`/store internals; challenge-code execution of any kind | Delivery layer wires and calls application; it must not execute generated workloads or bypass the persistence port. The control plane (API/web) in particular must never mount the Docker socket. |
| **workers** | importing `interfaces`; writing competition-domain state via `infrastructure` persistence directly | Workers are isolated executors; their only channel back to domain state is the job-result contract consumed by an application use-case. |

¹ `pydantic` (or any framework validation lib) is banned in `domain`; domain validation stays as
plain dataclasses + `validate_spec`-style pure functions. Pydantic/Pydantic-style models are
allowed at the `interfaces` (API request/response) and `infrastructure` boundaries.

**The concrete domain rule stated in the plan:** a `domain` module may not import
`http` / `docker` / `psycopg` / `mcp` / `anthropic` / `openai` / `fastapi` / `sqlalchemy`
(nor their submodules). This is the minimum the CI test must enforce.

Current-state note: some existing modules that will land in `domain` today reference IO-ish
symbols incidentally (e.g. the codebase map notes an incidental `subprocess`/docker string match
in `scenario.py`/`score.py`/`validator.py`, and `events.py` uses `threading.Lock`). `threading`
is stdlib concurrency and is **not** on the domain ban list; the incidental Docker/subprocess
matches must be removed or relocated to infrastructure before those modules move under `domain/`.

---

## 5. Per-layer import policy summary

| Layer | May import (layers) | May import (external) | Purity |
|---|---|---|---|
| domain | domain | Python stdlib only (no IO/network/db/framework) | pure, deterministic |
| application | domain, application | stdlib; domain ports only | orchestration, no concrete IO |
| infrastructure | domain, infrastructure | stdlib + optional deps (docker/subprocess, psycopg, anthropic, openai, boto3, yaml/http clients) — imported lazily | adapters |
| interfaces | domain (types), application, infrastructure (wiring root only) | ASGI framework, argparse, MCP, html | thin delivery adapters |
| workers | domain, application, infrastructure (wiring root only) | docker/subprocess runtime, job-queue client | isolated executors |

---

## 6. The architectural import test

TARGET deliverable. A single test (planned location `tests/architecture/test_import_boundaries.py`,
runnable under the existing `unittest` gate, stdlib-only) statically enforces every rule above by
**walking modules and parsing imports** — it never imports the target modules (so it stays fast and
free of side effects / optional-dep requirements).

### Algorithm

1. **Enumerate modules.** Walk `src/ctf_generator/` recursively for `*.py` files. Derive each
   file's **layer** from its path (first path segment under the package root: `domain`,
   `application`, `infrastructure`, `interfaces`, `workers`; files directly under the package root
   like `__init__.py`/`__main__.py` are layer-exempt or whitelisted).
2. **Parse imports.** For each file, `ast.parse(source)` and walk `ast.Import` / `ast.ImportFrom`
   nodes to collect the set of imported module roots. Resolve intra-package relative imports
   (`from ..domain.models import X`, `from .registry import Y`) to their absolute
   `ctf_generator.<layer>....` form so the target layer of each edge is known.
3. **Classify each edge.**
   - **Internal edge** (import of another `ctf_generator.<layer>...` module): look up importer
     layer and imported layer, assert the pair is `yes` in the **allowed-imports matrix** (§3).
   - **External edge** (any other top-level root, e.g. `docker`, `psycopg`, `fastapi`): assert the
     root is not in the importer layer's **forbidden import roots** (§4). Match by first dotted
     component (`http.server` → root `http`) so submodules are covered.
4. **Assert no forbidden edges.** Collect every violation as
   `(<file>, <imported>, <reason>)` and fail with the full list if non-empty. The test reports all
   violations at once (not just the first) so a refactor sees the complete blast radius.

### What it guarantees

- No layer imports "upward" or across a forbidden boundary (matrix, §3).
- No `domain` module imports `http`/`docker`/`psycopg`/`mcp`/`anthropic`/`openai`/`fastapi`/
  `sqlalchemy` (or the wider ban list, §4) — the primary invariant.
- The `templates must NOT import families` contract becomes structural: templates live under
  `domain/families/templates/` and importing the registry is an intra-domain edge the test can
  restrict to a one-directional rule.
- Optional deps (`psycopg`, `anthropic`, `openai`, `mcp`, `boto3`, `docker`) appear **only** in
  `infrastructure` (and the runtime pieces of `workers`), keeping the optional-dependency policy a
  single coherent seam rather than per-module.

### Limits (by design)

- **Static only.** It parses `import`/`from` statements; it does not detect dynamic imports
  (`importlib.import_module(name)`), so lazy adapter loading by string is invisible to it. Layer
  wiring should therefore prefer explicit imports at composition roots.
- **Path-derived layers.** A module's layer is its directory, so the tree in §2 is authoritative;
  moving a file changes the rules that apply to it.
- It checks *import structure*, not call semantics — "no business logic in route handlers" (§3) is
  a review guideline the test cannot verify, only the import edges are enforced.

### CI integration

Runs inside the existing project gates (`unittest` + `compileall`, per the CTFGenerator project
gates) as an ordinary test module, so a forbidden import fails the same pipeline as any unit-test
regression. No new tooling or third-party linter is required.
