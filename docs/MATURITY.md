# Subsystem Maturity & Stability Tiers

**Version:** 0.1.0 · **Status date:** 2026-07-11

This document defines the stability tiers used across CTFGenerator and classifies
every current subsystem and challenge family by tier. It reflects the codebase **as
it exists today**; forward-looking notes are labelled **(planned)** and are not
guarantees.

CTFGenerator is a self-hosted platform for generating, validating, deploying, and
operating reproducible cybersecurity challenges. AI-resistance evaluation is one
differentiating subsystem, not the whole product; its maturity is tracked
independently below.

---

## Stability tiers

| Tier | Support guarantee | Breaking changes | UI/CLI/docs labeling |
|---|---|---|---|
| **Stable** | Supported for production use. Interface, on-disk shapes, and documented exit codes are held compatible within a minor series. | Only on a documented major/minor bump with migration notes. | No label required. |
| **Beta** | Usable and tested, on a path to Stable. Behavior is largely settled but details may still move. | Permitted between minor releases; called out in release notes. | SHOULD be marked "beta" in docs. |
| **Experimental** | Available for evaluation only. No compatibility promise; may change shape, be renamed, or be removed. Not recommended for unattended production use. | Any release, without notice. | **MUST** be labeled experimental in UI, CLI, and docs (see rule below). |
| **Deprecated** | Still present but scheduled for removal; superseded by a named replacement. | Removal in a future release after a deprecation window. | MUST be marked deprecated with the replacement named. |

**Note on 0.x semantics:** the whole product is pre-1.0. "Stable" here means *most
mature and safe to depend on within 0.x*, not a 1.0-level API contract. Schema
versioning is currently advisory only — `SPEC_VERSION`, `SCHEMA_VERSION`, and
`__version__` are write-only stamps with no consumer-side validation or migration
path (see `docs`/codebase map §12). Hardened schema versioning is **(planned,
v0.1-alpha)**.

---

## Rule: experimental features must be labeled

Any subsystem, family, flag, or metric classified **Experimental** MUST be labeled
as such everywhere it is surfaced:

- **CLI** — help text / command output for the feature identifies it as experimental.
- **UI** — the dashboard surface exposing it marks it experimental.
- **Docs** — the reference section for it carries an experimental tag.

The label is a hard requirement, not a courtesy: experimental features carry no
compatibility promise, so users must be able to see the tier at the point of use.

---

## Subsystem classification (0.1.0)

Tiers below describe *interface and behavioral stability*, not code correctness.
Track designations (e.g. "production-track") indicate the intended destination, not
the current tier.

| Subsystem | Modules | Tier | Notes |
|---|---|---|---|
| Deterministic generator | `generator.py`, `spec_generator.py` (deterministic backend), `models.py`, `families.py`, `yaml_writer.py`, `templates/*` | **Stable** | Most mature subsystem. Core invariant: identical (generator version, spec, family, seed) ⇒ identical artifacts. Pure, stdlib-only, no Docker. Deterministic `--backend deterministic` only. |
| Static validation | `validator.py` (`validate_challenge`) | **Stable** | Pure artifact checks: required files, compose markers, yaml markers, scenario-timeline sanity. |
| Spec model & JSON round-trip | `models.py`, `spec_generator.py` (`spec_to_dict`/`spec_from_dict`/`validate_spec`) | **Stable** | `spec.json` shape stable; note it carries no embedded version field today. |
| CLI surface (core commands) | `cli.py` — `create`, `spec` (deterministic), `validate`, `list-families`, `catalog`, `quickstart` | **Stable** | Documented flags, exit codes, and stdout/stderr conventions. |
| MCP server (pure tools) | `mcp_server.py` | **Stable** | Only side-effect-bounded, deterministic tools exposed; workspace-sandboxed writes; snapshot-only CVE access; never imports Docker/subprocess/agent-eval/dashboard. |
| Report envelope & index | `report_writer.py`, `report_index.py` | **Stable** | `SCHEMA_VERSION = "1.0"` envelope; JSON + self-contained HTML index. |
| CVE sourcing — snapshot | `cve_source.py` (`SnapshotCveSource`), `cve_blueprint.py` | **Stable** | Offline bundled fixture backend; `create-from-cve`/`cve-search`/`cve-show` on `--source snapshot`. |
| CVE sourcing — NVD (live) | `cve_source.py` (`NvdCveSource`, `CachingCveSource`) | **Beta** | Network-effectful `--source nvd`; depends on external NVD 2.0 availability and shape. Snapshot path is the supported default. |
| Runtime validation (Docker) | `runtime_validator.py` | **Beta** | Builds/launches bundle, health-checks, runs intended solver, tears down. Executes bundle code **on the host by default**; `--sandbox` is opt-in. Isolation is not yet a hardened boundary (see execution-plane target below). |
| Sibling / replay validation | `sibling_validator.py`, `replay_validator.py` | **Beta** | Reuses `runtime_validator` internals; proves variant uniqueness / non-transfer. |
| Scoring engines & scoreboard | `scoring_engine.py`, `scoreboard.py`, `score.py` (competition scoring path) | **Beta** | Pluggable engines (`time_decay` default); pure folds over solve events. Config validation present. |
| Competition event log | `events.py` (`InMemoryEventStore`, `JsonlEventStore`) | **Beta** | Append-only, lock-serialized JSONL/in-memory. No schema-version field on records. |
| Competition event log — Postgres | `postgres_events.py` | **Experimental** | Optional `psycopg`-backed durable store; lazy dep; not the default persistence path. Durable control-plane persistence is **(planned, v0.3-alpha)**. |
| Scenario engine (offline) | `scenario.py` | **Experimental** | Pure scripted trigger/response timeline; `run-scenario` offline. Condition DSL and event shapes may change. Live-adversarial knob `live_adversarial_engine` is unwired. |
| Scenario runtime (Docker) | `scenario_runtime.py` | **Experimental** | Docker/HTTP glue for `run-scenario --runtime`; reaches into `runtime_validator` privates. |
| Dashboard server | `dashboard_server.py`, `dashboard_ui.py` | **Experimental** | Hand-rolled stdlib `ThreadingHTTPServer` admin dashboard + public scoreboard (`serve`). Plain HTTP; `--secure-cookie` only meaningful behind a TLS proxy. **(planned)** replacement by a maintained ASGI stack. |
| Dashboard authentication | `dashboard_server.py` (session login, token rotation, `AuthConfig`) | **Experimental** | Bespoke session/cookie/token auth in the hand-rolled server. Not hardened for untrusted exposure; deploy behind a reverse proxy only. |
| Agent-eval harness | `agent_eval.py` | **Experimental** | LLM tool-using agent driven against a live Docker instance (`eval-agent`, `--adversarial`). Network + Docker + provider-key dependent. |
| Agent-eval "resistance" metric | `score.py` AI-resistance dimensions incl. `scenario_resistance`; blended agent-eval score | **Experimental** | The "resistance" metric is experimental and **being renamed per M19**. Bands/weights and the blended-score contract are not stable. |
| LLM spec backends | `spec_generator.py` (`AnthropicSpecBackend`, `OpenAISpecBackend`) | **Experimental** | Network-effectful `spec --backend anthropic\|openai`; LLM emits pedagogical text only. Optional provider deps. |

---

## Challenge family classification (0.1.0)

All eight families render deterministically and pass static validation. Tiering here
reflects **content maturity and validation depth**, per the productization plan's
distinction between production-track and experimental domains. Every family listed as
Experimental is subject to the labeling rule above.

| Family | Category | Modes | Track / Tier |
|---|---|---|---|
| `web_business_logic_tenant_export` | web | red | **Production-track** — reference family (API + Redis + async worker), fullest test surface (`validate_solver.py`, `validate_variant.py`). |
| `network_lateral_pivot` | network | red, purple | **Production-track** — red+purple, detection-notes/checkpoint grading. |
| `cloud_metadata_ssrf` | cloud | red | **Production-track**. |
| `forensics_incident_triage` | forensics | (blue-leaning) | **Production-track** — blue-category grading path. |
| `crypto_token_forgery` | crypto | red | **Experimental** — single-service template family. |
| `binary_heap_exploit` | binary | red | **Experimental** — likely non-HTTP (`runtime.json`) invocation; runtime path less exercised. |
| `mobile_insecure_storage` | mobile | red | **Experimental**. |
| `scada_ics_modbus_takeover` | scada_ics | red | **Experimental** — Modbus/non-HTTP invocation. |

Per-family default live-adversarial scenarios exist only for `crypto_token_forgery`,
`cloud_metadata_ssrf`, `network_lateral_pivot`, and `web_business_logic_tenant_export`;
those scenarios inherit the **Experimental** scenario-engine tier regardless of the
family's own track.

---

## Target-state note (planned)

The productization plan splits the system into four planes — Author Studio,
Competition Control Plane, Execution Plane, and Evaluation Lab — with a hard boundary:
generated vulnerable workloads must **never** execute on the control plane, and the
control plane must never mount the Docker socket. Under that model, today's
**Beta**/**Experimental** execution subsystems (`runtime_validator`,
`scenario_runtime`, `agent_eval`, sibling/replay) migrate to isolated Execution-Plane
and Evaluation-Lab workers before they can be promoted toward Stable. These promotions
are **(planned)** across release stages v0.2-alpha through v1.0 and are not in effect
at 0.1.0.
