# CTFGenerator — Current System (As-Built)

> **HISTORICAL (M0 / v0.1.0 baseline).** Describes the pre-platform flat package as built at
> Milestone 0. Milestones M7–M18 are now shipped; for the current layered system see
> [`architecture/overview.md`](architecture/overview.md). This document is retained as a
> historical record and no longer describes the code as it exists today.

Milestone 0 baseline. This document is a precise description of CTFGenerator **as it exists today
(2026-07-11, v0.1.0)**. It is the authoritative current-state reference that later milestones diff
against. Everything under "Current" is grounded in the codebase map. Anything forward-looking is
explicitly marked **(planned/target)**.

---

## 1. What it is today

A pure-Python (3.11, stdlib-only core) deterministic **CTF challenge generator + validator**, plus
attached scoring, competition-dashboard, live-adversarial-scenario, agent-evaluation, and CVE-sourcing
subsystems. Distribution is a single flat package `src/ctf_generator/` (~35 modules) installed as the
`ctfgen` console entry point, with an optional MCP server. 709 unit tests green.

Core invariant: identical `(generator version, spec, family, seed)` → identical rendered artifacts
(no wall-clock in the provenance stamp; see `meta_mapping()`). The generator renders a self-contained
challenge *bundle*; a family renderer returns `dict[relative_path -> text]` and `generator.create_challenge`
writes it, appends `challenge.yaml`, and (only when `scenario.enabled`) `private/scenario_timeline.json`.

License is proprietary/for-profit. Repo `Judgernaut777/CTFGenerator`, remote `origin`
(SSH alias `github-ctfgenerator`).

---

## 2. Modules grouped by responsibility (~35 in `src/ctf_generator/`)

### Core generation pipeline (pure, deterministic)
| Module | Responsibility |
|---|---|
| `__init__.py` | Package + `__version__`. |
| `__main__.py` | `python -m ctf_generator` → `cli.main`. |
| `models.py` | Spec-domain dataclasses (`ChallengeSpec`, `ScenarioSpec`, `TriggerSpec`, `ResponseSpec`, scoring/competition configs). Imports only `__version__`. |
| `yaml_writer.py` | Hand-rolled **write-only** YAML emitter (`dump_yaml`). No reader. |
| `spec_generator.py` | Deterministic `default_spec`, `SpecBackend` Protocol, validation (`validate_spec`), JSON round-trip (`spec_to_dict`/`spec_from_dict`), optional Anthropic/OpenAI backends. |
| `generator.py` | Orchestrates one generation: `create_challenge`, `create_challenge_from_cve`. |
| `families.py` | Family registry (`register`/`get`/`family_names`/`family_of`), `Family`/`FamilyRenderer`/`ScoringHints`. Imports all templates; central hub. |
| `validator.py` | Static bundle validation (`validate_challenge`, `ValidationReport`); regex-parses `challenge.yaml`. |

### Templates (`templates/`, pure renderers — import only `models`+`yaml_writer`, never `families`)
`crypto.py`, `network.py`, `tenant_export.py`, `binary.py`, `cloud.py`, `forensics.py`, `mobile.py`,
`scada_ics.py`, `__init__.py`.

### Execution / validation (impure edge — Docker + `subprocess`)
| Module | Responsibility |
|---|---|
| `runtime_validator.py` | Builds & runs the bundle via `docker compose`; polls healthcheck; runs solver; tears down. Optional `sandbox=True` runs bundle scripts in an ephemeral read-only `python:3.11-slim` container. Reads `private/runtime.json`. |
| `replay_validator.py` | `cross_replay`: runs one instance's solver against a sibling instance (non-transfer proof). |
| `sibling_validator.py` | Generates N siblings, validates + cross-replays. |
| `agent_eval.py` | AI-agent eval harness (lazy anthropic/openai) driving a tool-using agent against a live instance. |

### Scenario engine (live-adversarial)
| Module | Responsibility |
|---|---|
| `scenario.py` | Pure scripted trigger/response engine + condition DSL (`evaluate_condition`). No Docker. |
| `scenario_runtime.py` | Docker/HTTP glue binding the scenario engine to a running instance. |

### Scoring & competition
| Module | Responsibility |
|---|---|
| `score.py` | Offline AI-resistance quality scoring (`score_challenge`) from `variant.json` + bundle heuristics + `ScoringHints`. |
| `scoring_engine.py` | Pluggable live scoring engines (`static`/`dynamic_decay`/`time_decay` default/`ai_resistance`). |
| `scoreboard.py` | Pure scoreboard folds (`compute_scoreboard`, `compute_challenge_values`). |
| `competition_service.py` | Stateful service over event log + scoring. |
| `events.py` | Append-only competition event log; `threading.Lock`-guarded; JSONL persistence; `EventStore` Protocol. |
| `postgres_events.py` | Optional psycopg-backed durable event store (lazy import). |

### CVE grounding
| Module | Responsibility |
|---|---|
| `cve_source.py` | `CveSource` Protocol; `SnapshotCveSource` (bundled fixture), `NvdCveSource` (live NVD 2.0), `CachingCveSource` (TTL file cache). |
| `cve_blueprint.py` | `CveRecord` → themed `ChallengeSpec` (`spec_from_cve`); category→family map; `content_hash`. |

### Reporting
| Module | Responsibility |
|---|---|
| `report_writer.py` | Per-run report envelope (`build_report`/`write_report`), `SCHEMA_VERSION="1.0"`, result serializers. |
| `report_index.py` | Read-only JSON/HTML index over report dir (`load_index`, `render_table`, `render_html`). |

### Interfaces / servers
| Module | Responsibility |
|---|---|
| `cli.py` | 1389-line argparse front door for ~20 subcommands; imports nearly everything. |
| `dashboard_server.py` | Hand-rolled `http.server.ThreadingHTTPServer` admin dashboard + public scoreboard (session login, token rotation). |
| `dashboard_ui.py` | Self-contained HTML page strings. |
| `mcp_server.py` | FastMCP server exposing only safe deterministic tools. Optional `mcp` dep. |

---

## 3. The eight families

Registered in `families.py` across eight domains, each with declared `required_files`,
`compose_service_markers`, `modes`, `difficulties`, and `ScoringHints`.

| Family | Category | Modes | CVE-driven | Notes |
|---|---|---|---|---|
| `web_business_logic_tenant_export` | web | `red` | no | API + Redis + async worker; field-trust / predictable-job-id IDOR. Default family (`FAMILIES[0]`). |
| `crypto_token_forgery` | crypto | red | no | Single web service; JWT `alg:none` / weak-secret (CWE-347). |
| `network_lateral_pivot` | network | red, purple | no | Edge→internal pivot; disclosed/weak/relay-trust token classes. |
| `cloud_metadata_ssrf` | cloud | red | no | SSRF to metadata (`/internal/objects`). |
| `forensics_incident_triage` | forensics | — | no | Blue-leaning (forensics ∈ `_BLUE_CATEGORIES`). |
| `binary_heap_exploit` | binary | — | no | Likely `runtime.json` (non-HTTP) user. |
| `mobile_insecure_storage` | mobile | — | no | Insecure storage. |
| `scada_ics_modbus_takeover` | scada_ics | — | no | Modbus/ICS; likely `runtime.json` user. |

**Live-adversarial default scenarios** exist only for `crypto_token_forgery`, `cloud_metadata_ssrf`,
`network_lateral_pivot`, and `web_business_logic_tenant_export` (two-stage `_http_defense_scenario`:
`time:>=1`→`notify`, `time:>=2`→`patch_route`). The other four have no default scenario.

CVE categories (`cve_source.CATEGORIES`) mirror the eight domains: `web, scada_ics, network, crypto,
cloud, forensics, binary, mobile`.

---

## 4. End-to-end flow

```
spec  ──►  generation  ──►  static validation  ──►  runtime validation  ──►  scoring
(spec_generator)  (generator +     (validator)        (runtime_validator,        (score.py)
                   families/          │                 Docker; sibling/replay)      │
                   templates)         │                     │                        │
                                      ▼                     ▼                        ▼
                              challenge bundle        scenario run            competition scoring
                                                    (scenario / scenario_    (scoring_engine +
                                                     runtime)                 scoreboard +
                                                          │                   competition_service +
                                                          ▼                   events / postgres_events)
                                                    agent-eval                        │
                                                    (agent_eval)                       ▼
                                                                              dashboard (serve)
```

1. **Spec** — `spec` builds a `ChallengeSpec` (deterministic default, or anthropic/openai backend which
   emits only pedagogical text via `_LLM_SCHEMA`), validates it, writes `spec.json`.
2. **Generation** — `create` / `create-from-spec` / `create-from-cve` render a bundle (filesystem only,
   no Docker). CVE path themes the spec via `cve_blueprint`.
3. **Static validation** — `validate` checks required files, compose markers, YAML markers, scenario sanity.
4. **Runtime validation** — `validate-runtime` builds/launches/health-checks/solves/tears down (Docker).
   `validate-siblings` and `replay` prove variant uniqueness / non-transfer.
5. **Scoring (quality)** — `score` computes an AI-resistance score across 5 dimensions
   (`variant_uniqueness` .25, `statefulness` .20, `solver_depth` .20, `live_interaction` .15,
   `scanner_resistance` .20; +`scenario_resistance` .15 when scenario enabled). Bands strong/good/moderate/weak;
   integrity gates force `weak`.
6. **Scenario** — `run-scenario` runs the scripted timeline offline (deterministic) or `--runtime` (Docker).
7. **Agent-eval** — `eval-agent` drives an LLM agent against a live instance; `--adversarial` measures the
   delta with the scenario engine off vs. on.
8. **Competition/scoring** — `scoreboard` computes standings from event fixtures; `serve` runs the dashboard;
   `catalog`/`quickstart` bootstrap challenge sets.

Every effectful subcommand can persist a **report envelope** (`--report-dir`) that `report-index` summarizes.

---

## 5. Bundle layout & trust boundary

Rendered files split three ways; the file set is **family-defined** (`Family.required_files`), not global.

| Area | Files (examples) | Visibility |
|---|---|---|
| Player-facing | `challenge.yaml`, `docker-compose.yml`, `.env.example` (some families), `services/*/{Dockerfile,app.py/worker.py,requirements.txt}`, `public/description.md`, `public/hints.yaml` | **public** |
| Operator/grader | `private/solution.md`, `private/solver.py` (adaptive/class-agnostic), `private/variant.json` (flag, vuln_class, routes, tokens, class_params), `private/checkpoints.yaml`, `private/scenario_timeline.json` (if enabled), `private/detection_notes.md` (network purple), `private/runtime.json` (optional, non-HTTP families) | **private** |
| Operational | `tests/healthcheck.py`, `tests/validate_solver.py`, `tests/validate_variant.py` | **operational** |

**Trust boundary:** flag is never under `public/`; it is injected at runtime via `${CTFGEN_FLAG:-}` env
and only reachable by exploiting the service. Compose services carry hardening
(`no-new-privileges`, `cap_drop:[ALL]`, `mem_limit`, `pids_limit`, `internal:true` networks).

---

## 6. The MCP boundary

`mcp_server.py` (FastMCP, name `ctgenerator`, stdio) exposes **only pure / side-effect-bounded tools**:
`list_families`, `spec_schema`, `build_spec`, `validate_spec`, `create_from_spec`, `create_challenge`,
`validate_challenge`, `score_challenge`, `report_index_table`, `family_info`, `list_cves`,
`scenario_timeline_summary`. Plus one prompt `design_challenge`.

Enforced boundary properties:
- **Never imports** `scenario_runtime`, `agent_eval`, `dashboard_server`, or `subprocess`. Docker/host
  execution (`validate-runtime`, `replay`, `--runtime`, `eval-agent`) stays **CLI-only**.
- **Filesystem sandbox**: write tools resolve `output_dir` under a workspace root via `_resolve_in_workspace`;
  `..`/absolute-escape → `WorkspaceError`. Root = CWD, overridable by `CTFGEN_MCP_WORKSPACE`. Rationale:
  `force=True` does `shutil.rmtree` first — otherwise an arbitrary-delete primitive.
- **CVE snapshot-only**: no network `nvd` source reachable via MCP regardless of input.
- `mcp` dependency is lazy; missing → `RuntimeError` pointing at `pip install ctf-generator[mcp]`.

---

## 7. Optional extras (dependency edges)

| Extra | Module(s) | Trigger | Effect |
|---|---|---|---|
| `anthropic` / `openai` | `spec_generator`, `agent_eval` | `spec --backend anthropic\|openai`, `eval-agent` | Network LLM calls; lazy/injectable via Protocol. Defaults `claude-opus-4-8` / `gpt-5.1`. |
| CVE `nvd` | `cve_source` | `--source nvd` on `cve-*`/`create-from-cve` | Live NVD 2.0 fetch (network); optional TTL disk cache with `--cache-dir`. |
| `mcp` | `mcp_server` | running the MCP server | FastMCP over stdio. |
| `postgres` | `postgres_events` | durable event store | psycopg-backed `EventStore` (lazy). |
| `web` (built-in) | `dashboard_server`, `dashboard_ui` | `serve` | stdlib `http.server` dashboard (no framework, no CDN). |

All optional deps are imported **lazily inside their own module** — there is no single infrastructure seam
(each defines its own Protocol).

---

## 8. Known undocumented / implicit behavior (surfaced by the map)

These are real current behaviors that are easy to trip over and are not called out elsewhere:

- **`cli.py` has no `__main__` guard.** `python -m ctf_generator.cli` is a **silent no-op** (exits 0, does
  nothing). Only `python -m ctf_generator` (via `__main__.py` → `cli.main`) or the `ctfgen` console script
  actually dispatch.
- **No subcommand → exit code 2**, and help is printed to **stderr** (not stdout). Unknown command →
  `parser.error` (argparse exit 2).
- **`validate-runtime`/`replay`/`--runtime`/`eval-agent` execute bundle-shipped `tests/healthcheck.py` and
  `private/solver.py` on the host with the caller's privileges by default.** `--sandbox` (opt-in, only on
  `validate-runtime`) runs them in an ephemeral read-only container. This is the single most important
  as-built security caveat: **generation and untrusted-bundle execution share one process.**
- **PEP 668 host cannot `pip install`** (externally-managed environment) — installing `ctfgen` / optional
  extras requires a venv or an override; the tooling assumes it is importable/on path.
- **`tests/` dir must be on `PYTHONPATH`** for the suite to import the package layout as expected.
- **No YAML reader exists.** `validator`/`families` parse `challenge.yaml` with indentation-sensitive regex
  (`family_of`, `_scenario_enabled`); malformed indentation silently breaks parsing rather than erroring cleanly.
- **`spec.json` carries no version field.** Only the separate `ChallengeSpec.to_mapping()` metadata stamp
  embeds `spec_version` (inside `meta`). A persisted `spec.json` round-tripped via `spec_from_dict` has no
  version marker; `variant.json`, CVE cache, event JSONL, and scoreboard JSON likewise have none.
- **Schema versioning is write-only.** Three independent hard-coded `"1.0"` constants (`SPEC_VERSION`,
  `SCHEMA_VERSION`, `__version__`); **no consumer reads or validates any of them** — no negotiation, no
  migration, no upgrade path.
- **Two serializers for the same spec diverge:** `to_mapping()` emits `checkpoints` as `[{"name":...}]` with
  `meta`+`validation` blocks; `spec_to_dict` emits flat string checkpoints and no meta. Default specs are
  byte-identical only because non-default keys (`cve_refs`, `mode`, `scenario`) are conditionally emitted.
- **Load-bearing validation coupling:** a spec needs `len(checkpoints) >= ai_resistance.min_solver_steps`
  (default 5), so the default deterministic spec requires **≥5 checkpoints**.
- **`create --mode`/`--cve-ref` are no-ops with `--from-spec`**, and only build a spec at all when a
  non-default mode or any cve-ref is supplied (otherwise `create_challenge` builds its own default spec).
- **`serve --secure-cookie` is only meaningful behind a TLS-terminating proxy** — the built-in server is plain
  HTTP. If `--public-token` is omitted a random token is printed **once** to stdout.
- **`AIResistance.live_adversarial_engine`** is a Phase-5 knob that is **unwired** (default `False`).

---

## 9. Gaps vs. the productization target

The target is a secure, self-hosted platform split into four planes (Author Studio, Competition Control
Plane, Execution Plane, Evaluation Lab). Against that, today's system has these gaps **(all target/planned,
not current)**:

- **No plane separation / control-plane isolation.** Generation and Docker/host bundle execution run in one
  process (`runtime_validator._run` inline). Target: control plane **never** executes generated code and never
  mounts the Docker socket; execution runs on isolated workers.
- **No worker/job system.** Five modules (`runtime_validator`, `replay_validator`, `sibling_validator`,
  `scenario_runtime`, `agent_eval`) each reach into `runtime_validator` private helpers. Target: a
  PostgreSQL-backed job queue (`FOR UPDATE SKIP LOCKED`, leases, heartbeats, retries, idempotency, dead-letter)
  with an isolated rootless Docker/Podman + BuildKit runtime.
- **No persistence / repository layer.** State is scattered: JSONL event log, optional postgres events,
  ad-hoc per-bundle file reads. Target: PostgreSQL domain model + SQLAlchemy 2.x + Alembic migrations.
- **No auth / roles / audit / immutable versions.** Target: eight roles, authz, immutable content-addressed
  published artifacts, auditable privileged state changes, at-most-one solve per (team,challenge,competition).
- **Hand-rolled interfaces.** Bespoke `ThreadingHTTPServer` dashboard + write-only YAML emitter + regex config
  parsing. Target: maintained ASGI framework (FastAPI-class), Pydantic validation, structured JSON logging,
  shared application services behind `cli`/`api`/`web`/`mcp` adapters.
- **`cli.py` is a 1389-line god-module** with no interface/application separation. Target package shape:
  `domain / application / infrastructure / interfaces / workers` with strict dependency rules.
- **Schema versioning is advisory only** (§8). Target: real schema versioning with a migration/upgrade path.
- **No release/CI hardening** for deterministic-rebuild guarantees, FS-escape prevention as an enforced gate,
  or family SDK. Target: v0.1-alpha "reliable generator" stage items.
- **Python 3.11 today; target baseline is 3.12.**
