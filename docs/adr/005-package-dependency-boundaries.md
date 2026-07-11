# Title: ADR-005 — Adopt layered package boundaries with enforced import rules

> One line: Restructure `src/ctf_generator/` into `domain`, `application`,
> `infrastructure`, `interfaces`, and `workers` layers, with the allowed
> import direction enforced by architectural import tests in CI.

## Status

**Accepted**

## Date

`2026-07-11`

## Context

The package is a **flat directory** of ~35 modules under `src/ctf_generator/`
with no internal layering. The coupling is concentrated and load-bearing:

- **`cli.py` is a 1389-line god-module.** It parses arguments for ~20
  subcommands *and* inlines the use-case orchestration for each one, importing
  nearly every subsystem (`generator`, the validators, `score`, `families`,
  `report_writer`/`report_index`, `spec_generator`). There is no separation
  between the argument-parsing surface and the orchestration it drives; `cli`,
  `mcp_server`, and `dashboard_server` each re-implement their own slice of the
  same use-cases instead of sharing one.
- **Generation and execution mix in-process.** `runtime_validator._run` shells
  out via `subprocess` to `docker compose build/up` and executes bundle-shipped
  `solver.py` / `healthcheck.py` **on the host by default** (`sandbox=True` is
  opt-in). Four modules — `agent_eval`, `replay_validator`, `sibling_validator`,
  `scenario_runtime` — each independently reach into `runtime_validator`'s
  private helpers (`_run`, `_record`, `_wait_for_health`), so the execution edge
  is a leaky, un-abstracted layer rather than a boundary.
- **Optional/infra deps are reached lazily but not gated behind ports.**
  `anthropic`/`openai` (`spec_generator`, `agent_eval`), `psycopg`
  (`postgres_events`), `mcp` (`mcp_server`), and the hand-rolled `http.server`
  (`dashboard_server`) are each imported inside their own module, each defining
  its own Protocol (`SpecBackend`, `EventStore`, …). The optional-dependency
  policy is per-module, with no coherent infrastructure seam.
- **`families.py` is a central import hub** with a by-convention "templates must
  NOT import `families`" circular-import contract, enforced only by comments.

This ADR touches the **Plugin model** axis (family registry boundary) and
establishes the structural precondition for the **Database strategy**,
**Queue strategy**, **Worker trust model**, and **Artifact storage** axes,
each of which needs a `domain`↔`infrastructure` port to depend on. It must
uphold the plan's highest-priority boundary — **generated vulnerable workloads
must never execute on the control plane** — which today has no structural
representation at all.

## Decision

We will restructure the package into five layers and enforce the allowed import
direction with architectural import tests that run in CI. This ADR fixes the
**boundary contract**; module-by-module migration is incremental (target shape,
not yet built).

**Layers and responsibilities:**

| Layer | Holds | May import |
|---|---|---|
| `domain` | Pure spec/competition types and rules (today: `models`, `families` registry contract, scenario/scoring rule logic) and the Protocols other layers implement. | Standard library + other `domain` modules only. |
| `application` | Use-case services that orchestrate a single operation (generate, validate, score, run competition). | `domain` (types + Protocols) only. |
| `infrastructure` | Concrete adapters implementing domain/application Protocols: Docker/subprocess execution, Postgres/JSONL stores, artifact storage, LLM backends, CVE sources, HTTP framework. | `domain`, `application` Protocols; external libraries. |
| `interfaces` | Thin adapters that translate an external surface into application calls: `api` (REST), `cli`, `web`, `mcp`. | `application` services; `domain` types for typing. |
| `workers` | Isolated job runners that execute build/launch/solve/eval jobs. | `domain` types + explicit job-contract types; execution `infrastructure`. |

**Enforced import rules (the contract CI checks):**

1. `domain` imports **no** `http`, `docker`, `subprocess`, `postgres`/`psycopg`,
   `mcp`, LLM (`anthropic`/`openai`), or web-framework code — standard library
   and `domain` only.
2. `application` depends **only** on `domain` types and Protocols — never on a
   concrete adapter, framework, or `interfaces`.
3. `infrastructure` **implements** domain/application Protocols; nothing in
   `domain`/`application` imports `infrastructure` concretely.
4. `interfaces` call `application` services and hold **no business logic** —
   route handlers and argparse handlers only translate input/output.
5. **CLI and API share the same `application` services** — no use-case logic
   lives in `cli.py` or in a REST route handler.
6. `workers` **never mutate competition-domain state directly**; results flow
   back through explicit job-result contracts consumed by `application`.

**Enforcement:** an architectural import test (e.g. AST/`importlib`-based module
scan) asserts rules 1–6 by inspecting each module's imports and failing CI on any
violation. This makes the "templates must not import `families`" style contract
structural rather than advisory.

## Consequences

### Positive
- The control-plane/execution split becomes a **structural invariant**: the
  Docker/subprocess edge lives only in `infrastructure`/`workers`, so "generated
  code must never run on the control plane" is checkable in CI, not a review
  convention.
- One set of `application` services backs `cli`, `api`, `web`, and `mcp`,
  dissolving the 1389-line `cli.py` god-module and the duplicated orchestration
  across the three current entry points.
- Optional deps (LLM, psycopg, mcp, HTTP framework) collapse behind a single
  `infrastructure` seam of domain-owned Protocols, replacing the per-module lazy
  imports and ad-hoc Protocols.
- Later ADRs (Postgres persistence, Postgres job queue, artifact storage) attach
  concrete adapters to already-defined ports instead of re-plumbing callers.

### Negative
- Substantial one-time migration: nearly every module moves, and the god-module
  and the leaky `runtime_validator` private-helper reuse must be untangled.
- A new CI gate (the architectural import test) can block merges on layout, and
  must itself be maintained as modules move.
- More indirection for small operations — a use-case now crosses an
  `interface → application → infrastructure` hop rather than being inlined.

### Neutral
- The five-layer names and the six rules are now the frozen vocabulary all
  subsequent refactor ADRs must use.
- Migration is incremental; until a module moves it may still violate the target
  layout, so the import test is introduced enforcing the boundaries that already
  hold and tightened as modules land.
- The family registry (`families.py`) becomes a `domain`-level plugin boundary;
  the exact SDK/registration interface is deferred to the Plugin-model ADR.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| **Keep the flat package** (status quo) | Rejected. The flat layout is what produced the 1389-line `cli.py`, the in-process generation/execution mix, and five modules reaching into `runtime_validator`'s privates. It gives the highest-priority security boundary no structural home and lets every new subsystem deepen the coupling. |
| Layer by convention/docstrings only, no CI check | Rejected. The existing "templates must not import `families`" convention is already enforced only by comments; without a test it drifts. The boundary that keeps vulnerable code off the control plane is too important to leave advisory. |
| Split into separate installable packages/repos per layer | Rejected for V1. Heavier release and versioning overhead than the single-deployment V1 model needs; import-test-enforced layers inside one package deliver the same boundary guarantees now. |
| Feature/vertical-slice modules (one folder per subcommand) instead of horizontal layers | Rejected. It would co-locate route handling, orchestration, and Docker/subprocess execution inside each slice, which is exactly the control-plane/execution mixing this ADR must forbid. |
