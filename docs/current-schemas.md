# Current Data Schemas

> **HISTORICAL (M0 / v0.1.0 baseline).** Describes the pre-platform data shapes (spec/variant/
> report JSON, event log, CVE cache) and the schema-versioning gap of that era. Milestones
> M7–M18 are now shipped — persistence moved to a PostgreSQL system of record with SQLAlchemy
> ORM and Alembic migrations. For the current system see
> [`architecture/overview.md`](architecture/overview.md) and
> [`architecture/persistence-design.md`](architecture/persistence-design.md). This document is
> retained as a historical record.

**Milestone 0 deliverable.** Documents every data schema that exists in CTFGenerator
**today** (v0.1.0). All shapes below are transcribed from the codebase map; field names
and types match source. Where planned/target behavior is described it is labelled
**(planned)**.

Scope: `models.py`, `families.py`, `spec_generator.py`, `scenario.py`, `events.py`,
`scoring_engine.py`, `scoreboard.py`, `score.py`, `cve_source.py`, `cve_blueprint.py`,
`report_writer.py`, `report_index.py`, plus the on-disk JSON/YAML the generator emits.

> **Read this first — the schema-versioning gap.** No schema in this catalogue carries a
> negotiable identifier or a consumer-enforced version. Three write-only `"1.0"` string
> constants exist (`SPEC_VERSION`, `SCHEMA_VERSION`, `__version__`); nothing reads or
> branches on them. `spec.json`, `variant.json`, manifests, the event log, CVE caches, and
> scoreboard inputs carry **no version field at all**. See [§12](#12-schema-versioning-status-and-risk).
> Milestone 4 will introduce schema identifiers/versions and migration; until then any
> field change is a silent breaking change.

---

## 1. ChallengeSpec and the spec domain (`models.py`)

`ChallengeSpec` is the central `@dataclass(frozen=True)`. It composes several frozen
sub-dataclasses. The LLM never sets the security-relevant knobs; those are deterministic.

### ChallengeSpec

| Field | Type | Default |
|---|---|---|
| `title` | `str` | required |
| `category` | `str` | required |
| `difficulty` | `str` | required |
| `family` | `str` | required |
| `seed` | `str` | required |
| `learning_objectives` | `list[str]` | required |
| `checkpoints` | `list[str]` | required |
| `ai_resistance` | `AIResistance` | `AIResistance()` |
| `dynamic_variation` | `DynamicVariation` | `DynamicVariation()` |
| `cve_refs` | `list[str]` | `[]` |
| `cve_content_hash` | `str \| None` | `None` |
| `mode` | `str` | `"red"` (also `"scenario"`, `"blue"`) |
| `scenario` | `ScenarioSpec` | `ScenarioSpec()` |

### AIResistance (frozen; deterministic-only knobs)

| Field | Type | Default |
|---|---|---|
| `novelty_target` | `str` | `"high"` |
| `min_solver_steps` | `int` | `5` |
| `require_live_interaction` | `bool` | `True` |
| `decoy_density` | `str` | `"medium"` |
| `generic_scanner_usefulness` | `str` | `"low"` |
| `hidden_sibling_validation` | `bool` | `True` |
| `live_adversarial_engine` | `bool` | `False` (Phase-5, unwired) |

### DynamicVariation (frozen)

| Field | Type | Default |
|---|---|---|
| `per_user_schema` | `bool` | `True` |
| `per_user_routes` | `bool` | `True` |
| `per_user_seed_data` | `bool` | `True` |
| `per_user_auth_flow` | `bool` | `False` |
| `per_user_flag_path` | `bool` | `True` |

### Two serializers, deliberately different shapes

`ChallengeSpec` has **two** mappers that do **not** agree — a known trap:

| Serializer | `checkpoints` shape | Includes `meta`? | Includes `validation`? | Used for |
|---|---|---|---|---|
| `to_mapping()` | list of `{"name": <str>}` objects | **yes** | **yes** | stamped challenge-metadata (drives `challenge.yaml`) |
| `spec_to_dict()` (§3) | flat `list[str]` | no | no | the persisted `spec.json` |

`meta_mapping()` is a deterministic provenance stamp (no wall-clock):

```json
{ "generator_version": "<__version__>", "spec_version": "1.0",
  "family": "<family>", "seed": "<seed>" }
```

`to_mapping()` emits `meta`, the flat spec fields, `ai_resistance`, `dynamic_variation`,
`checkpoints` as `{"name": ...}` objects, and a fixed `validation` block
(`private_solver_required: true`, `ai_agent_eval_required: false`,
`variant_static_validation_required: true`). Conditional keys are emitted **only when
non-default** to keep default output byte-identical: `cve_refs` (if non-empty),
`cve_content_hash` (if not `None`), `mode` (if `!= "red"`), `scenario` (if not default).

### ScenarioSpec / TriggerSpec / ResponseSpec (frozen; live-timeline)

`ScenarioSpec` is disabled by default (`enabled=False`, empty `triggers`/`responses`).
`is_default()` is `True` iff disabled with both lists empty.

| Type | Fields |
|---|---|
| `ScenarioSpec` | `enabled: bool = False`, `triggers: list[TriggerSpec] = []`, `responses: list[ResponseSpec] = []` |
| `TriggerSpec` | `trigger_id: str` (req), `description: str = ""`, `condition: str = ""` (DSL, e.g. `"time:>=1"`, `"checkpoint:queues_export_job"`) |
| `ResponseSpec` | `response_id: str` (req), `description: str = ""`, `action: str = ""` (e.g. `reveal_hint`/`spawn_decoy`/`notify`/`patch_route`), `payload: dict[str,str] = {}` |

Each has a `to_mapping()`; `ScenarioSpec.to_mapping()` → `{"enabled", "triggers":[...], "responses":[...]}`.

### ChallengeSpec validation rules (`spec_generator.validate_spec`)

Returns `list[str]` of human-readable errors (empty = valid):

| # | Rule | Error on failure |
|---|---|---|
| 1 | `title.strip()` non-empty | `title is empty` |
| 2 | `family in families.family_names()` | `unknown family: <family>` |
| 3 | `difficulty in ["easy","medium","hard"]` | `unknown difficulty: <difficulty>` |
| 4 | `seed.strip()` non-empty | `seed is empty` |
| 5 | `len(learning_objectives) >= 1` | `at least one learning objective is required` |
| 6 | `len(checkpoints) >= ai_resistance.min_solver_steps` | error stating declared vs required count |
| 7 | each `cve_ref` matches `^CVE-\d{4}-\d{4,}$` | `invalid cve_ref: <ref>` |
| 8 | `mode in families.get(family).modes` (only if family known) | `mode <mode> is not valid for family <family>` |

Rule 6 is the load-bearing coupling: default `min_solver_steps=5` means a valid spec needs
**≥5 checkpoints**.

### LLM output schema (`_LLM_SCHEMA`)

The **only** shape an LLM backend may emit. It never produces code, flags, categories, or
`ai_resistance`; `category` comes authoritatively from the family registry.

```json
{ "type": "object", "additionalProperties": false,
  "properties": {
    "title": {"type": "string"},
    "learning_objectives": {"type": "array", "items": {"type": "string"}},
    "checkpoints": {"type": "array", "items": {"type": "string"}} },
  "required": ["title", "learning_objectives", "checkpoints"] }
```

---

## 2. Family registry types (`families.py`)

Process-wide registry `_REGISTRY: dict[str, Family]`. API: `register`, `get` (raises
`KeyError`), `is_registered`, `family_names()` (sorted), `families_for_mode`,
`families_for_category`, `family_of(challenge_yaml_text)` (regex-parses the top-level
`family:` line).

### Family (frozen)

| Field | Type | Default |
|---|---|---|
| `name` | `str` | required |
| `category` | `str` | required |
| `modes` | `tuple[str, ...]` | required |
| `render` | `FamilyRenderer` | required |
| `required_files` | `tuple[str, ...]` | required |
| `compose_service_markers` | `tuple[str, ...]` | `()` |
| `difficulties` | `tuple[str, ...]` | `("easy","medium","hard")` |
| `cve_driven` | `bool` | `False` |
| `llm_brief` | `str` | `"A security challenge."` |
| `default_spec_builder` | `DefaultSpecBuilder \| None` | `None` |
| `scoring_hints` | `ScoringHints` | `ScoringHints()` |
| `learning_objectives` | `tuple[str, ...]` | `tuple(_DEFAULT_OBJECTIVES)` |
| `checkpoints` | `tuple[str, ...]` | `tuple(_DEFAULT_CHECKPOINTS)` |
| `default_scenario` | `ScenarioSpec \| None` | `None` |

`FamilyRenderer` (Protocol): `(spec, rng, cve_record=None) -> dict[str,str]` (relative path → text).

### ScoringHints (frozen) — signals `score.py` reads per family

| Field | Type | Default |
|---|---|---|
| `has_worker` | `bool` | `True` |
| `has_queue` | `bool` | `True` |
| `live_interaction` | `bool` | `True` |
| `decoy_density` | `str` | `"medium"` |

### Family metadata that exists today (registered families)

Eight families across eight domains, all with `modes` and `difficulties`:

| Family | Category | Modes | Notable |
|---|---|---|---|
| `web_business_logic_tenant_export` | web | `("red",)` | compose markers `("worker:","redis")`, `cve_driven=False`, API+Redis+worker |
| `crypto_token_forgery` | crypto | — | default live-adversarial scenario target `/api/admin/` |
| `network_lateral_pivot` | network | red + purple | default scenario `/internal/flag` |
| `cloud_metadata_ssrf` | cloud | — | default scenario `/internal/objects` |
| `forensics_incident_triage` | forensics | — | blue-oriented |
| `binary_heap_exploit` | binary | — | likely `runtime.json` (non-HTTP) user |
| `mobile_insecure_storage` | mobile | — | — |
| `scada_ics_modbus_takeover` | scada_ics | — | Modbus; likely `runtime.json` user |

Phase-3 families are wired via a loop where each template module supplies `FAMILY_NAME`,
`CATEGORY`, `MODES`, `DIFFICULTIES`, `CVE_DRIVEN`, `LLM_BRIEF`, `COMPOSE_MARKERS`,
`SCORING_HINTS`, `REQUIRED_FILES`, `render`. Only four families ship a default
live-adversarial scenario (crypto, cloud, network, tenant_export); each is a two-stage
`_http_defense_scenario` (`time:>=1`→`notify`, `time:>=2`→`patch_route`).

MCP `family_info(name)` exposes the read-only subset:
`name, category, modes, difficulties, cve_driven, llm_brief, required_files`.

---

## 3. `spec.json` on-disk shape (`spec_generator`)

`write_spec` serializes `spec_to_dict(spec)` with `json.dumps(..., indent=2,
sort_keys=True)` + trailing newline. `load_spec`/`spec_from_dict` are the inverse.

```json
{
  "title": "<str>", "category": "<str>", "difficulty": "<str>",
  "family": "<str>", "seed": "<str>",
  "learning_objectives": ["<str>"],
  "checkpoints": ["<str>"],
  "ai_resistance": { "...vars(AIResistance)" },
  "dynamic_variation": { "...vars(DynamicVariation)" }
}
```

Conditional keys (only when non-default): `cve_refs` (list), `cve_content_hash` (str),
`mode` (if `!= "red"`), `scenario` (via `ScenarioSpec.to_mapping()`).

`spec_from_dict` defaults missing keys: `category="web"`, `difficulty="medium"`,
`family=FAMILIES[0]`, `mode="red"`, `ai_resistance`/`dynamic_variation` reconstructed via
`**kwargs`, `scenario` rebuilt from nested `triggers`/`responses` (else default).

> **No version marker.** `spec.json` carries no `spec_version`/`schema_version`. `spec_version`
> lives only in `ChallengeSpec.to_mapping()`'s `meta` block (which feeds `challenge.yaml`), not
> the persisted spec. A round-tripped `spec.json` is version-blind. See [§12](#12-schema-versioning-status-and-risk).

---

## 4. Scenario engine types (`scenario.py`) — single-run, in-memory

Explicitly **NOT** the persistent `events.Event`. These live only for one scenario run.

| Type | Key fields |
|---|---|
| `SimEvent` (frozen) | `tick: int`, `source: str`, `kind: str`, `target: str = ""`, `payload: dict[str,str] = {}`; `to_mapping()` |
| `SimEventBus` (mutable) | `_events: list[SimEvent]`; `publish`/`all`/`at_tick`/`since_tick` |
| `ScenarioState` (mutable) | `tick: int = 0`, `checkpoints: set[str]`, `flags: dict[str,str]`, `fired_triggers: set[str]`, `noise_count: int = 0` |
| `AttackerMove` (frozen) | `tick: int`, `response: ResponseSpec`, `precondition: str = ""` |
| `ScenarioResponseRecord` (frozen) | `tick, role, response_id, action, target` |
| `ScenarioRunReport` (mutable) | `challenge_path`, `ticks_run=0`, `timeline: list[SimEvent]`, `triggers_fired: list[str]`, `responses_applied`, `attacker_blocked: list[str]`, `final_state: ScenarioState \| None` |

`ScenarioRunReport.defender_disrupted_attacker` = `bool(attacker_blocked)`.
`run_scenario` runs exactly `max_ticks` (default `DEFAULT_MAX_TICKS = 20`).

**Condition DSL** (`evaluate_condition`, `&&`-joined clauses): `""`,
`time:+N/>=N/<=N/==N/<N/>N`, `event:<kind>`, `event:<source>:<kind>`,
`checkpoint:<name>`, `state:<key>=<value>`, `state:<key>!=<value>`,
`count:<kind><op><N>`. Unrecognized clause → `ValueError`.

---

## 5. Competition event log (`events.py`)

`Event` (frozen) is the persistent, cross-competition JSONL record.

| Field | Type | Notes |
|---|---|---|
| `seq` | `int` | required; strictly monotonic from 1 |
| `ts` | `str` | required; ISO-8601 UTC |
| `type` | `str` | required; e.g. `"solve"` |
| `team_id` | `str` | required |
| `challenge_id` | `str` | required |
| `payload` | `dict` | `{}` |

`JsonlEventStore` writes one JSON object per line (`_event_to_dict`, `sort_keys=True`) and
reloads via `Event(**data)`. Stores (`InMemoryEventStore`, `JsonlEventStore`) lock-serialize
`seq` assignment. `EventStore` Protocol: `append/since/all/latest_seq`.

> **No version field** on the JSONL line; reload relies on `Event(**data)` and defaults.

---

## 6. Scoring config, engines, and scoreboard structures

### Solve / submission types (`models.py`, all frozen, all `to_mapping()`)

| Type | Fields |
|---|---|
| `Submission` | `submission_id, team_id, challenge_id, submitted_at: datetime (isoformat), correct: bool, instance_seed: str\|None = None` |
| `SolveEvent` | `team_id, challenge_id, solved_at: datetime (isoformat), submission_id, instance_seed: str\|None = None` |

`solve_event_from_submission` raises `ValueError` if `correct` is `False`.

### Scoring configuration (`models.py`, frozen)

| Type | Fields (defaults) |
|---|---|
| `FirstBloodBonusConfig` | `enabled=True`, `bonus_points: int = 0`, `bonus_percent: float = 0.0` |
| `ChallengeScoringConfig` | `challenge_id` (req), `initial_value=500`, `minimum_value=100`, `decay_function="static"` (`static`/`linear`/`logarithmic`), `decay=0`, `first_blood_bonus=FirstBloodBonusConfig()` |
| `CompetitionConfig` | `competition_id, name` (req), `start_time, end_time: datetime` (req), `scoring_start_time: datetime\|None`, `freeze_time: datetime\|None`, `default_scoring: ChallengeScoringConfig\|None` |

### Scoreboard snapshots (`models.py`, frozen)

| Type | Fields |
|---|---|
| `ScoreboardEntry` | `team_id, score: int, solve_count: int, last_solve_at: datetime\|None, rank: int = 0` |
| `ScoreboardSnapshot` | `competition_id, generated_at: datetime, entries: list[ScoreboardEntry] = [], frozen: bool = False` |
| `ChallengeValueSnapshot` | `challenge_id, value: int, solve_count: int, computed_at: datetime` |

### Scoring engines (`scoring_engine.py`)

`ScoringEngine` Protocol: attr `name: str`; method
`challenge_value(challenge, solve_count, competition, now) -> float`. Registry default
`"time_decay"`.

| Engine | `name` |
|---|---|
| `StaticPointsEngine` | `static` |
| `DynamicDecayEngine` | `dynamic_decay` (honors `decay_function`/`decay`) |
| `TimeDecayEngine` | `time_decay` (**default**) |
| `AIResistanceWeightedEngine` | `ai_resistance` (wraps a base; `weights: dict[str,float]`, `default_weight=1.0`) |

`validate_competition_config` / `_validate_challenge_scoring` checks: `end_time > start_time`;
`scoring_start_time` and `freeze_time` (if set) within `[start,end]`;
`0 <= minimum_value <= initial_value`; `initial_value >= 0`; `decay_function ∈
("static","linear","logarithmic")`; `decay >= 0`; `bonus_points >= 0`;
`0.0 <= bonus_percent <= 100.0`. `solve_event_from_event` maps an `events.Event` of
`type=="solve"` (reads `submission_id`/`instance_seed` from `payload`).

### Scoreboard computation (`scoreboard.py`)

Pure folds, no own dataclasses. `compute_challenge_values(...) ->
list[ChallengeValueSnapshot]`; `compute_scoreboard(...) -> ScoreboardSnapshot` (retroactive
decay; single first-blood per challenge; `frozen = as_of is not None`). JSON loaders:
`load_events` (JSON array of `SolveEvent.to_mapping()`-shaped objects), `load_challenges`
(JSON array of `ChallengeScoringConfig`), `load_competition_config` (single object). Parse
defaults mirror the dataclass defaults.

### Static AI-resistance scoring (`score.py`)

| Type | Fields |
|---|---|
| `Dimension` (mutable) | `name: str`, `weight: float`, `score: float`, `notes: list[str] = []` |
| `ScoreReport` (mutable) | `errors, warnings, dimensions: list[Dimension], total: float = 0.0, band: str = ""`; `to_mapping()` |

`ScoreReport.to_mapping()` (the `result` block of a `score` report):

```json
{ "total": "<round(total,1)>", "band": "strong|good|moderate|weak",
  "dimensions": [ {"name","weight","score","notes":[]} ],
  "warnings": [], "errors": [] }
```

Dimensions (name/weight): `variant_uniqueness` 0.25, `statefulness` 0.20, `solver_depth`
0.20, `live_interaction` 0.15, `scanner_resistance` 0.20. When `scenario.enabled`, a sixth
`scenario_resistance` (0.15) is appended and the other five rescale ×0.85. Bands:
`strong≥85`, `good≥70`, `moderate≥50`, else `weak`. Integrity gates (embedded flag in
solver, or flag leaked to `public/` in non-`blue` mode) force `band="weak"`. `score.py`
reads the bundle from disk (`private/variant.json`, `private/solver.py`,
`docker-compose.yml`, `challenge.yaml`), parsing YAML textually rather than via the
dataclasses.

---

## 7. CVE record types (`cve_source.py`, `cve_blueprint.py`)

### CveRecord (frozen; `to_mapping()` emits all ten fields, lists copied)

| Field | Type |
|---|---|
| `cve_id` | `str` |
| `published` | `str` (e.g. `"2021-12-10"`) |
| `cvss_version` | `str` (`3.1`/`3.0`/`2.0`) |
| `cvss_score` | `float` |
| `cvss_severity` | `str` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`) |
| `cwe_ids` | `list[str]` |
| `category` | `str` (one of `CATEGORIES`) |
| `affected_products` | `list[str]` |
| `description` | `str` |
| `references` | `list[str]` |

`CATEGORIES = ("web","scada_ics","network","crypto","cloud","forensics","binary","mobile")`.
`CveSource` Protocol (`fetch`, `get`) has impls `SnapshotCveSource` (bundled fixture),
`NvdCveSource` (live NVD 2.0), `CachingCveSource` (TTL file cache).

**CVE cache file JSON** (`CachingCveSource`):

```json
{ "expires_at": "<float>", "records": [ "<CveRecord.to_mapping()>" ] }
```

> No version field on cache files or on `CveRecord`.

### CveBlueprint (frozen; `cve_blueprint.py`)

| Field | Type | Default |
|---|---|---|
| `family` | `str` | required |
| `difficulty` | `str` | required |
| `mode` | `str` | required |
| `cve_id` | `str` | required |
| `themed_title` | `str` | required |
| `themed_objectives` | `list[str]` | `[]` |
| `themed_checkpoints` | `list[str]` | `[]` |

`content_hash(record)` = SHA-256 over canonical JSON of `record.to_mapping()`, stored as
`ChallengeSpec.cve_content_hash`. `spec_from_cve` sets `cve_refs=[record.cve_id]`,
`cve_content_hash=content_hash(record)`, falls back to `_FALLBACK_FAMILY` if the intended
family is unregistered, and downgrades mode to a family-supported one.

---

## 8. Report envelope + index (`report_writer.py`, `report_index.py`)

### Report envelope — `build_report(...)`, written by `write_report`

`SCHEMA_VERSION = "1.0"`. Serialized with `json.dumps(..., indent=2, sort_keys=True,
default=str)`.

```json
{
  "schema_version": "1.0",
  "generator_version": "<__version__>",
  "command": "<str>",
  "subject": { "type": "...", "identifier": "..." },
  "timestamp": "<ISO-8601>",
  "git_commit": "<str or empty>",
  "status": "passed|failed",
  "result": { }
}
```

Filename (`_report_filename`): `<YYYYMMDDThhmmssZ>-<command>-<subject_slug>-<disc>.json`,
`disc` = first 8 hex of SHA-1 over `result`; collisions get `-<n>`.

### `result`-block serializers (all in `report_writer.py`)

| Serializer | Result keys |
|---|---|
| `serialize_validation` | `errors, warnings` |
| `serialize_runtime` | `errors, logs` |
| `serialize_siblings` | `errors, warnings, logs, sibling_a, sibling_b, changed_tokens` |
| `serialize_replay` | `errors, logs, solver_dir, target_dir, success` |
| `serialize_scoreboard` | `competition_id, generated_at, frozen, entries:[{team_id,score,solve_count,last_solve_at,rank}]` |
| `serialize_agent_eval` | `profile, solved, steps, elapsed_ticks, notes` |
| `serialize_adversarial_delta` | `challenge_path, profile, baseline, adversarial, scenario_report, success_dropped, step_delta, notes` |
| `_serialize_scenario_run_report` | `challenge_path, ticks_run, timeline:[SimEvent], triggers_fired, responses_applied:[{tick,role,response_id,action,target}], attacker_blocked, final_state:{tick,checkpoints,flags,fired_triggers,noise_count}\|null` |

The `score` command's `result` is `ScoreReport.to_mapping()` (§6).

### Report index (`report_index.py`)

| Type | Fields |
|---|---|
| `ReportRow` | `command, status, subject_type, subject_identifier, timestamp, git_commit_short (12 chars or "-"), score_total: float\|None (from result.total; bool rejected), source (filename)` |
| `ReportIndex` | `rows: list[ReportRow] = []`, `skipped: list[str] = []` |

`row_from_report` never raises; `load_index` scans `*.json` non-recursively, sorts by
`(timestamp, source)`. `render_table` / `render_html` (HTML title `"CTF Report Index"`).

---

## 9. On-disk generated-bundle shapes

A generation writes a self-contained bundle; the exact file set is **family-defined**
(`Family.required_files`), not global. Public = player-facing, private = operator/grader,
operational = probes.

| File | Vis. | Shape / contents |
|---|---|---|
| `challenge.yaml` | public | Canonical spec from `ChallengeSpec.to_mapping()` via `yaml_writer.dump_yaml`: `meta` (generator_version, spec_version, family, seed), title/category/difficulty, `learning_objectives`, `ai_resistance`, `dynamic_variation`, `checkpoints`, `validation` flags, optional `scenario`. Validator hard-requires markers `meta:`, `ai_resistance:`, `dynamic_variation:`, `checkpoints:`. |
| `docker-compose.yml` | public | Runtime topology; hardening (`no-new-privileges`, `cap_drop:[ALL]`, `mem_limit`, `pids_limit`); flag via `${CTFGEN_FLAG:-}`; internal services on `internal: true` net. Validator checks family `compose_service_markers`. |
| `.env.example` | public | Sample env (`CTFGEN_FLAG=...`); only some families emit it. |
| `services/*/{Dockerfile,app.py,worker.py,requirements.txt}` | public | Vulnerable-by-construction service source. |
| `public/description.md` | public | Player brief (routes, creds, flag format). |
| `public/hints.yaml` | public | Tiered level 1–3 hints. |
| `private/solution.md` | private | Instance-specific writeup. |
| `private/solver.py` | private | Adaptive/class-agnostic reference solver; exposes `--base-url`. |
| `private/variant.json` | private | Machine ground-truth: `meta`, `family`, `flag`, `vuln_class`, routes, creds/tokens, `class_params`. Consumed by replay/sibling/score. |
| `private/checkpoints.yaml` | private | Grading checkpoints (`name` + `required`) from `spec.checkpoints`. |
| `private/scenario_timeline.json` | private | Emitted only when `scenario.enabled`; replayable `triggers` + `responses`. Validator soft-checks presence + JSON validity. |
| `private/detection_notes.md` | private | Network/purple-mode blue-team notes. |
| `private/runtime.json` | private (optional) | **Manifest.** When present, overrides how health/solve scripts are invoked (`args`) for non-HTTP families (raw-TCP binary, Modbus). Read by `runtime_validator._load_runtime_manifest`. Not emitted by web families. |
| `tests/healthcheck.py` | operational | Stdlib probe of `/healthz`. |
| `tests/validate_solver.py`, `tests/validate_variant.py` | operational | pytest-style static token assertions. |

### `variant.json` (observed shape)

Consumed **textually** by `score.py`; observed keys: `meta`, `family`, `flag`,
`vuln_class`, `routes`, credentials/`tokens`, `class_params`. **No version field.**

**Trust boundary:** everything a player receives is `public/` + service source +
`challenge.yaml`; everything under `private/` is operator-side. The flag is never in
`public/`; it is injected at runtime via env.

### Scoreboard/serve JSON fixtures

The `scoreboard` CLI and `serve` consume plain JSON: `--events` (array of
`SolveEvent`-shaped), `--challenges` (array of `ChallengeScoringConfig`), `--config` (a
`CompetitionConfig`). `serve --events-file` persists as JSONL (`JsonlEventStore`). None
carry a version field.

---

## 10. `challenge.yaml` has no reader (parsing risk)

`yaml_writer.dump_yaml` is **write-only** — there is no YAML reader. `validator`,
`families.family_of`, and `score.py` re-parse `challenge.yaml` with
indentation-sensitive regex / line scanning. Any change to the emitted YAML layout can
silently break these string-matching parsers, independent of the versioning gap below.

---

## 11. Where schema identifiers/versions live today

| Constant | Location | Emitted in | Covers |
|---|---|---|---|
| `SPEC_VERSION = "1.0"` | `models.py` | `meta.spec_version` inside `ChallengeSpec.to_mapping()` → `challenge.yaml` | shape of the `meta` block / generated layout |
| `SCHEMA_VERSION = "1.0"` | `report_writer.py` | top-level `schema_version` of report envelope | report envelope only |
| `__version__` | `ctf_generator` package | `meta_mapping()` + `build_report()` `generator_version` | build provenance, not schema |

---

## 12. Schema versioning status and risk

**Versioning today is advisory, fragmented, and unenforced.** Three independent hard-coded
`"1.0"` constants exist; there is **no shared registry, no negotiation, no migration logic,
and no upgrade path**.

Absences (all **current**):

- **`spec.json` carries no version.** `spec_to_dict` emits no `spec_version`/`schema_version`;
  only the separate `to_mapping()` embeds `spec_version` in its `meta` block. A persisted
  `spec.json` round-tripped through `spec_from_dict` has no version marker.
- **`variant.json` has no version field** (consumed textually by `score.py`).
- **CVE cache files, competition/scoreboard/challenge JSON, and the JSONL event log carry
  no version field.** `CveRecord`, `Event`, and the scoreboard/config loaders rely on
  defaulting missing keys.
- **No consumer reads or validates any version constant.** `spec_from_dict`, `load_spec`,
  `row_from_report`, `load_competition_config`, etc. never inspect `spec_version` /
  `schema_version`. No branch on version, no compatibility check, no migration. The
  constants are **write-only stamps**.

### Compatibility risk this creates

| Risk | Consequence today |
|---|---|
| Field added/removed/renamed in any schema | Silent breaking change: old readers default missing keys or mis-parse; no error surfaces. |
| Bundle produced by generator vN read by vM | No detection; behavior undefined; violates the invariant that identical (generator version, spec, family version, seed) ⇒ identical artifacts once shapes drift. |
| Persisted event log / scoreboard fixtures replayed after a shape change | No version gate → possible silent misread; scoreboards may not be faithfully reconstructable. |
| `challenge.yaml` layout change | Breaks the write-only-YAML regex parsers (§10) with no version signal. |
| `"1.0"` bumped by a developer | Nothing reads it, so the bump has no effect — a false sense of safety. |

### Target (planned — Milestone 4 / v0.1-alpha "schema versioning")

- Introduce explicit, consumer-enforced schema identifiers + versions across `spec.json`,
  `variant.json`, `runtime.json`, report envelope, event log, and scoreboard/CVE JSON.
- Add a migration/compatibility path (readers branch on version; refuse or upgrade
  unknown/incompatible versions instead of silently defaulting).
- Back the key invariant that identical (generator version, spec, family version, seed) ⇒
  identical artifacts with a real version contract, not advisory strings.

These are **planned**; none exist in the current codebase.
