# Architecture

## Principle

AI may propose a challenge, but deterministic code should build, isolate, validate, and score it.

The platform should treat validation as the core product. A generated challenge is not useful until it is buildable, launchable, solvable, reasonably fair, and contained.

This principle extends past challenge generation to every content source added since
the MVP: a spec-drafting LLM, an MCP host's own model, or a live CVE feed may all
*propose* material -- themed titles, learning objectives, checkpoint names, or the
raw content of a real-world vulnerability record. None of them ever produce code,
routes, flags, or the security-relevant AI-resistance/dynamic-variation knobs, and
none of their output is persisted as the source of truth. The only durable input is
a `ChallengeSpec` plus its seed; everything else -- rendered files, live scenario
timelines, scoring, the competition scoreboard -- is rebuilt deterministically from
that spec by code that ships with the repository. A CVE record is folded into the
seed and hashed for provenance (see below) rather than stored as generated content,
so nothing about "what this challenge actually does" ever depends on an external
service being available or trustworthy at solve time.

## MVP Shape

The repository started with a local generator and validator CLI and has grown a CVE
content layer, a family/mode taxonomy, a live-adversarial scenario engine, an
AI-agent evaluation harness, and a competition platform (event log, scoring, and a
dashboard) on top of it. The full `ctfgen` command surface:

```text
ctfgen spec -> structured challenge spec (deterministic or LLM backend)
ctfgen create -> challenge folder (optionally --from-spec)
ctfgen create-from-cve -> challenge folder grounded in a real CVE record
ctfgen validate -> static artifact validation (family-aware)
ctfgen validate-runtime -> Docker build, launch, health check, solve, cleanup
ctfgen validate-siblings -> sibling generation, variant comparison, optional runtime replay
ctfgen score -> static AI-resistance scoring across five (or six) weighted dimensions
ctfgen replay -> run one challenge's solver against another's live instance
ctfgen report-index -> summarize persisted reports (table or static HTML)
ctfgen list-families -> list the registered challenge families
ctfgen cve-search / cve-show / cve-categories -> browse the CVE source
ctfgen run-scenario -> replay a challenge's live scenario timeline (offline, or --runtime against Docker)
ctfgen eval-agent -> run a scripted/AI solver agent against a live challenge (optionally --adversarial)
ctfgen list-scoring-engines -> list registered competition scoring engines
ctfgen scoreboard -> compute a competition scoreboard from JSON fixtures
ctfgen serve -> serve the live competition admin dashboard + public scoreboard
```

The validation, scoring, scenario, and scoreboard commands accept `--report-dir` to
persist their result as a JSON artifact (see Persisted Validation Reports below).

## Spec-First Generation

`spec_generator.py` decouples *what the challenge is* from *how it is rendered*.
A `SpecBackend` produces a validated `ChallengeSpec`; `create_challenge` renders
it deterministically. Two backends ship:

- `DeterministicSpecBackend` (default) — offline, no dependencies, byte-stable
  for a given seed.
- `AnthropicSpecBackend` — drafts metadata via the Claude Messages API
  (structured outputs + adaptive thinking). Requires the optional `[anthropic]`
  extra; default model `claude-opus-4-8`.
- `OpenAISpecBackend` — drafts metadata via OpenAI Chat Completions with a
  strict `json_schema` response format. Requires the optional `[openai]` extra;
  default model `gpt-5.1`.

Both LLM backends draft only the human-facing metadata (title, learning
objectives, checkpoints). They never emit code, flags, routes, or the
security-relevant AI-resistance knobs, which stay under deterministic control,
so a generated spec is always safe and structurally valid. Each provider's
client is injectable, so the prompt-building and response-parsing logic is
unit-tested without network access or credentials.

`models.ChallengeSpec` has grown alongside these content sources without breaking
the shape existing challenges serialize to:

- `family: str` -- which registered `Family` renders this spec (see Family & Mode
  Taxonomy below); defaulted and validated against the family registry.
- `mode: str` -- `"red"` (the original, only mode), or `"blue"` / `"purple"` for
  families that declare them. Only emitted into `challenge.yaml` when non-default,
  so a plain `"red"` spec still serializes byte-identically to before `mode` existed.
- `cve_refs: list[str]` and `cve_content_hash: str | None` -- provenance for a
  CVE-grounded instance (empty/`None` for the non-CVE default).
- `scenario: ScenarioSpec` -- an optional, disabled-by-default live timeline
  (`triggers` + `responses`) consumed by the scenario engine; also only emitted
  when non-default.

Every conditional field follows the same discipline: a default `ChallengeSpec`
(`red` mode, no CVE, scenario disabled) still round-trips to exactly the YAML the
MVP produced, so none of Phases 2-5 is a breaking change for existing challenges.

## CVE-Driven Content Layer

`cve_source.py` and `cve_blueprint.py` let a challenge be grounded in a real,
disclosed vulnerability instead of an invented scenario, while keeping the same
determinism guarantee as everything else in the pipeline.

**Injectable `CveSource`** (`cve_source.py`), mirroring the `CommandRunner`
pattern used by `runtime_validator.py`:

- `CveSource` is a `Protocol` with `fetch(...)` and `get(cve_id)`.
- `SnapshotCveSource` (default) is the offline, deterministic backend: a small,
  bundled, hand-curated set of real CVE records (Log4Shell, PrintNightmare,
  Heartbleed, EternalBlue, and others) spanning all eight category taxonomies.
  Stdlib-only, no network, safe as the default and test backend.
- `NvdCveSource` is the live backend, hitting the real NVD 2.0 REST API through
  an injectable `NvdFetcher` callable (default: stdlib `urllib`, lazily
  imported so it is never required at import time). Tests supply a fake
  fetcher and never touch the network.
- `CachingCveSource` wraps either source with a TTL file cache keyed by
  normalized query arguments, with an injectable `Clock` so expiry is testable
  without sleeping.
- `get_source(name, **kwargs)` is the factory (`"snapshot"` or `"nvd"`).
- `CWE_CATEGORY_HINTS` classifies a CVE into CTFGenerator's own category
  taxonomy (`CATEGORIES`: web/scada_ics/network/crypto/cloud/forensics/binary/
  mobile) from its CWE ids, used both for the bundled fixture and to classify
  live NVD records, which have no notion of this taxonomy on their own.

**`cve_blueprint.py` is a pure module** (no I/O, no randomness, no clock): the
same `CveRecord` + `base_seed` always produces byte-identical output.

- `fold_seed(base_seed, cve_id)` deterministically combines the generator's seed
  with the CVE id (`f"{base_seed}:{cve_id}"`), so re-generating a CVE-grounded
  challenge from the same base seed is always reproducible *without* the
  original CVE record needing to be stored anywhere -- the seed alone
  reconstructs the same themed content.
- `content_hash(record)` is a SHA-256 digest over the record's canonical JSON
  mapping, stamped onto `ChallengeSpec.cve_content_hash`. This is the
  provenance guarantee: if the upstream CVE source later changes or
  disappears, a challenge generated from the same seed still renders
  byte-identically, because the exact record content used at generation time
  is locked into the hash, not re-fetched.
- `CATEGORY_FAMILY_MAP` maps each of the eight CVE categories to its intended
  `Family` name (e.g. `"scada_ics"` -> `"scada_ics_modbus_takeover"`). If that
  family isn't registered (or doesn't support the blueprint's intended mode),
  `spec_from_cve` falls back to the always-registered
  `web_business_logic_tenant_export` family/mode while preserving the
  CVE-derived category, themed title, objectives, checkpoints, and provenance.
- `blueprint_from_cve` derives themed, human-facing metadata (title,
  objectives, checkpoints) plus intended family/difficulty/mode from a
  `CveRecord`; `difficulty_from_cvss` maps CVSS base score to
  easy/medium/hard. `spec_from_cve` lowers that blueprint into a full
  `ChallengeSpec`.

`generator.create_challenge_from_cve` wires this into rendering: it resolves a
CVE id via a `CveSource` (defaulting to the offline snapshot), builds the spec,
and renders it exactly like `create_challenge` -- including passing the
resolved `CveRecord` through to the family renderer, which may use its
description/CWE/affected-product fields to theme the rendered artifacts.

## Family & Mode Taxonomy

`families.py` is a small, process-wide registry (`register`/`get`/
`is_registered`/`family_names`) that turns "which challenge template renders
this spec" into data instead of an `if/elif` chain, so `generator.py`,
`validator.py`, and `score.py` all dispatch through it uniformly.

```python
class FamilyRenderer(Protocol):
    def __call__(self, spec: ChallengeSpec, rng: random.Random,
                 cve_record: CveRecord | None = None) -> dict[str, str]: ...

@dataclass(frozen=True)
class Family:
    name: str
    category: str
    modes: tuple[str, ...]
    render: FamilyRenderer
    required_files: tuple[str, ...]
    compose_service_markers: tuple[str, ...] = ()
    difficulties: tuple[str, ...] = ("easy", "medium", "hard")
    cve_driven: bool = False
    llm_brief: str = "A security challenge."
    scoring_hints: ScoringHints = field(default_factory=ScoringHints)
```

Eight families are registered at import time, one per CVE category, spanning the
offensive/defensive/purple mode split:

| Family | Category | Modes | CVE-driven |
| --- | --- | --- | --- |
| `web_business_logic_tenant_export` | web | red | no (the original, bootstrap family) |
| `scada_ics_modbus_takeover` | scada_ics | red, blue, purple | yes |
| `network_lateral_pivot` | network | red, purple | yes |
| `crypto_token_forgery` | crypto | red | yes |
| `cloud_metadata_ssrf` | cloud | red, purple | yes |
| `forensics_incident_triage` | forensics | blue | yes |
| `binary_heap_exploit` | binary | red | yes |
| `mobile_insecure_storage` | mobile | red, blue | yes |

`"red"` is an offensive (attacker) challenge, `"blue"` is a defensive
(incident-response/forensics-style) challenge, and `"purple"` families support
both postures from the same template. Each of the seven Phase-3 families
(everything but the bootstrap `web_business_logic_tenant_export`) is defined in
its own `templates/<name>.py` module exporting a fixed interface
(`FAMILY_NAME`/`CATEGORY`/`MODES`/`DIFFICULTIES`/`CVE_DRIVEN`/`LLM_BRIEF`/
`COMPOSE_MARKERS`/`SCORING_HINTS`/`REQUIRED_FILES`/`render`); `families.py`
loops over those modules once at import time to register them, so adding a
ninth family is adding one template module plus one line in that loop.

**Dispatch through the registry:**

- `generator.create_challenge` calls `families.get(spec.family).render(spec, rng,
  cve_record)` -- no per-family branching in the generator itself.
- `validator.validate_challenge` resolves the family from the rendered
  `challenge.yaml`'s top-level `family:` field (`families.family_of`) and checks
  that family's `required_files` / `compose_service_markers` exist, falling back
  to a minimal generic YAML sanity check when the family can't be resolved (an
  unregistered name, or no family line at all -- keeps older/foreign challenge
  folders from hard-failing validation).
- `score.score_challenge` resolves the same way and reads the family's
  `ScoringHints` (`has_worker`, `has_queue`, `live_interaction`, `decoy_density`)
  to decide which statefulness/live-interaction signals actually apply to that
  family, rather than assuming every challenge looks like the worker+queue
  bootstrap family. A family that doesn't call for a background worker isn't
  penalized in `statefulness` for lacking one; the defaults reproduce today's
  original hard-coded checks unchanged for `web_business_logic_tenant_export`.

## MCP Server

`mcp_server.py` runs CTFGenerator as an MCP *server* (`ctfgen-mcp`, stdio), so
an MCP host drives generation with the user's own model/subscription rather than
an API key: the host's model drafts the pedagogical metadata and calls the
server's tools, and the LLM never lives in CTFGenerator.

The exposed surface is deliberately pure: `list_families`, `spec_schema`,
`build_spec`, `validate_spec`, `create_from_spec`, `create_challenge`,
`validate_challenge`, `score_challenge`, `report_index_table`, `family_info`
(read-only family registry metadata), `list_cves` (always the offline
`SnapshotCveSource`, never `nvd`, so this tool stays read-only and side-effect
-free regardless of caller input), and `scenario_timeline_summary`
(read-only parse of a generated challenge's `private/scenario_timeline.json`),
plus a `design_challenge` prompt that primes a host model with the safety
boundary. Every Docker-driving or agent/dashboard command stays CLI-only (see
Security Boundary below), so connecting a model host to the server never hands
it container builds, host execution, live network access, or dashboard
credentials. The tool bodies are plain functions, unit-tested without the
optional `[mcp]` dependency; `build_server` wires them into a FastMCP instance
lazily. `build_spec` merges host-supplied metadata with the fixed safety knobs
and validates before returning, mirroring the LLM backends' boundary.

Every spec is checked by `validate_spec` (title, family, difficulty, objective
count, that checkpoint count meets `ai_resistance.min_solver_steps`, that `mode`
is one of the resolved family's declared modes, and that each `cve_refs` entry
matches `CVE-YYYY-NNNN+`) before it can be rendered. `ctfgen spec` writes a spec
as JSON; `ctfgen create --from-spec` loads, re-validates, and renders it — the
spec's own seed fully determines the instance.

Generated challenge folders contain:

```text
challenge.yaml
docker-compose.yml
services/
  api/
  worker/
public/
  description.md
  hints.yaml
private/
  solution.md
  solver.py
  checkpoints.yaml
  scenario_timeline.json   # only when spec.scenario.enabled
tests/
  healthcheck.py
  validate_solver.py
  validate_variant.py
```

## Challenge Generation Pipeline

Target pipeline:

```text
structured spec (deterministic, LLM-drafted metadata, MCP host, or CVE-grounded)
  -> family-registry dispatch                implemented (families.py)
  -> artifact rendering
  -> static validation                       family-aware
  -> container build                         implemented for local Docker
  -> isolated launch                         implemented for local Docker
  -> health check                            implemented
  -> private solver replay                   implemented
  -> sibling variant replay                  implemented for generated private solvers
  -> live-adversarial scenario replay        implemented, offline-deterministic + optional Docker/HTTP-backed
  -> AI-resistance scoring                   implemented as static artifact analysis + conditional scenario dimension
  -> AI-agent evaluation                     implemented, scripted/pluggable agent, baseline + adversarial-delta
  -> persisted validation reports            implemented as JSON report artifacts
  -> competition event log + scoring         implemented (events -> scoring_engine -> scoreboard)
  -> live dashboard / public scoreboard      implemented
  -> human review
  -> publish
```

## AI-Resistance Scoring

`ctfgen score` reads a generated challenge folder and rates it 0-100 across five
weighted dimensions (six when the challenge has a live scenario), then reports a
band (`strong`/`good`/`moderate`/`weak`):

- `variant_uniqueness` (0.25): how many dynamic-variation dimensions are enabled
  and how many per-instance route/token values appear in `variant.json`. Also
  annotates (non-scoring) which CVE(s) the instance is grounded in, if any.
- `statefulness` (0.20): presence of a background worker, a queue/state backend,
  and a solver that drives asynchronous job state -- gated by the resolved
  family's `ScoringHints` (a family that doesn't call for a worker/queue isn't
  penalized for lacking one).
- `solver_depth` (0.20): declared checkpoints and distinct HTTP interactions in
  the private solver, relative to `ai_resistance.min_solver_steps`.
- `live_interaction` (0.15): whether the solver discovers routes at runtime and
  polls a live endpoint rather than replaying hardcoded values -- also gated by
  `ScoringHints.live_interaction`.
- `scanner_resistance` (0.20): derived from `generic_scanner_usefulness` and
  `decoy_density`.

Scores are computed from the actual artifacts, not just the spec's declared
values, so a challenge that claims live interaction but ships a hardcoded solver
is flagged and scored down. `--min-score` turns the score into a CI gate.

**Conditional `scenario_resistance` dimension.** When `challenge.yaml` declares
`scenario.enabled: true`, `score.py` rescales the other five dimensions'
weights down proportionally (preserving their relative proportions) to make
room for a sixth, `scenario_resistance` (weight 0.15), computed purely from the
declared `scenario` block: more distinct `trigger_id`s/`response_id`s and a
wider variety of trigger conditions/response actions mean a player can't just
replay one recorded trace and expect it to still work once the live timeline
reacts. Non-scenario challenges (the default) never see this dimension or the
rescale, so today's five fixed weights (0.25/0.20/0.20/0.15/0.20) are unchanged
for every challenge generated before Phase 5.

`score_with_agent_eval` (see AI-Agent Evaluation below) layers an optional,
opt-in `blended_score` on top of the static score without ever modifying
`score_challenge`/`ScoreReport` themselves.

## Live-Adversarial Scenario Engine

The scenario engine is the platform's answer to "a shared writeup or a single
LLM prompt should stop working partway through the solve." It is split into a
pure, offline core and an optional effectful shell, exactly like the
CommandRunner pattern used elsewhere:

**`scenario.py` -- scripted, deterministic core.** No Docker, no HTTP, no
subprocess, no wall clock, no `random` module. Given the same scripted
`EventSource`, the same agents, and the same `max_ticks`, `run_scenario`
always produces a byte-identical `ScenarioRunReport` timeline.

- `EnvironmentController` (`rotate_credential`/`patch_route`/
  `quarantine_host`/`inject_noise`), `EventSource` (`poll(tick)`), and `Agent`
  (`decide(tick, events, state) -> list[ResponseSpec]`) are the three
  injectable Protocols. `NullEnvironmentController` (records intent, mutates
  nothing) and `ReplayEventSource` (a pre-scripted, tick-keyed event feed) are
  the deterministic test/offline defaults.
- `ScriptedDefender` evaluates `TriggerSpec.condition` each tick and fires the
  mapped `ResponseSpec`s (each trigger fires at most once). `ScriptedAttacker`
  runs a fixed, deterministic plan of `AttackerMove`s, each with an optional
  precondition; a blocked move becomes an observable `action="blocked"` event
  rather than silently no-op'ing.
- A tiny condition DSL (`evaluate_condition`) supports `time:`, `event:`,
  `checkpoint:`, `state:`, and `count:` clauses, joined with `&&`, interpreted
  the same way for both defender triggers and attacker preconditions.
- `run_scenario(challenge_path, environment, events, defender=None,
  attacker=None, spec=None, max_ticks=None)` ticks from 0 to `max_ticks`
  (default 20): poll exogenous events, apply the attacker's decisions, then
  the defender's -- both visible to each other within the same tick -- and
  returns a `ScenarioRunReport` (full timeline, fired triggers, applied
  responses, blocked attacker moves, final state).

**`scenario_runtime.py` -- Docker/HTTP-backed shell, CLI-only.** Supplies real
implementations of the same two Protocols so the identical `run_scenario` core
can drive an actual environment:

- `DockerEnvironmentController` runs real `docker compose exec`/`stop`
  commands (via an injected `runtime_validator.CommandRunner`, the same
  pattern `runtime_validator.py` uses) to rotate a credential, patch a route,
  or quarantine a host inside a live challenge stack.
- `HttpEventSource` polls a live challenge's `/scenario/state` endpoint (via
  an injected fetcher, default stdlib `urllib`) and turns observed
  checkpoints/events into `SimEvent`s; a fetch/parse failure becomes a
  `poll_error` event instead of aborting the run.
- `run_live_scenario` wires both into `scenario.run_scenario` unchanged.
  `ctfgen run-scenario --runtime` uses this path; without `--runtime` the same
  command runs the pure offline core.

This module is explicitly forbidden from being imported by `mcp_server.py` (a
regression test enforces it) -- see Security Boundary below.

**Why this is "real" AI-resistance.** A static writeup or a one-shot LLM
prompt captures one path through a fixed environment. A scenario-enabled
challenge can rotate the very credential or patch the very route a scripted
solve depends on *while the agent is mid-solve*, so replaying a recorded trace
(or a single generated exploit chain) against a fresh instance may simply stop
working partway through -- the agent has to notice the environment changed and
adapt, not just execute a plan. `agent_eval.run_adversarial_delta` (below)
measures this effect directly by re-running the same scripted agent against a
scenario-defended HTTP client and checking whether a prior solve flips to a
non-solve.

## Persisted Validation Reports

`validate`, `validate-runtime`, `validate-siblings`, `score`, `run-scenario`,
`eval-agent`, and `scoreboard` accept `--report-dir <dir>` to persist their
result as a JSON artifact. The writer lives in `report_writer.py`; the pure
validator/score/scenario/scoreboard functions are unchanged and serialization
plus I/O happen only at the CLI layer.

Each report is a versioned envelope:

```json
{
  "schema_version": "1.0",
  "command": "score",
  "subject": {"type": "challenge", "identifier": "invoice-drift"},
  "timestamp": "2026-07-03T05:05:48.619538+00:00",
  "git_commit": "f0b0fc3f...",
  "status": "passed",
  "result": { "...per-command payload..." }
}
```

Design guarantees:

- **Never overwrites.** Filenames combine the envelope timestamp, command,
  subject slug, and an sha1 content discriminator; a collision falls back to an
  exclusive-create retry with a numeric suffix.
- **Never fatal.** A failed report write is caught, warned to stderr, and leaves
  the command's exit code and stdout untouched.
- **Best-effort git.** `git_commit` is captured when available and is an empty
  string when git is missing, hangs, or the tree is not a repository.
- **Filename matches the envelope.** The timestamp encoded in the filename is
  derived from the report's own `timestamp` field, so the two never diverge.

`status` mirrors the process exit condition, so a report directory doubles as an
auditable pass/fail trail across runs.

## Competition Scoring & Platform

A live competition layers cleanly on top of the generation/validation/scoring
pipeline: none of these modules know how a challenge was generated, only how to
turn a log of submission events into points and standings.

```text
events.EventStore (append-only)
  -> scoring_engine.ScoringEngine (pluggable, per-challenge point value)
  -> scoreboard.compute_scoreboard (pure fold: events + config -> ScoreboardSnapshot)
  -> competition_service.CompetitionService (live façade: record/poll/progress/leaderboard)
  -> dashboard_server (admin dashboard + redacted public scoreboard, stdlib HTTP)
```

**`events.py`** is the append-only source of truth. `Event` is a frozen record
(`seq`, `ts`, `type`, `team_id`, `challenge_id`, `payload`) with a strictly
monotonic `seq`. `InMemoryEventStore` (volatile, process-local) and
`JsonlEventStore` (append-only file, resumes `seq` numbering across restarts)
both implement the same `EventStore` Protocol; the wall clock is an injectable
`Clock`, defaulting to `time.time`.

**`scoring_engine.py`** registers four pure `ScoringEngine`s (mirroring the
`families.py` registry pattern), each a pure function of its inputs -- no
internal wall-clock reads, callers always pass `now` explicitly:

- `StaticPointsEngine` (`"static"`) -- constant per-challenge value.
- `DynamicDecayEngine` (`"dynamic_decay"`) -- CTFd-style decay as `solve_count`
  rises (`static`/`linear`/`logarithmic`, per `ChallengeScoringConfig`).
- `TimeDecayEngine` (`"time_decay"`) -- **the default** (`get_scoring_engine()`
  with no name). Value decays linearly with elapsed competition time instead
  of solve count, so early solves are worth more regardless of how many other
  teams have solved it; `CompetitionConfig.freeze_time` caps the effective
  clock so value stops dropping once the scoreboard would be frozen.
- `AIResistanceWeightedEngine` (`"ai_resistance"`) -- wraps another engine and
  applies an advisory per-challenge weight multiplier (`challenge_id ->
  multiplier`, default 1.0/no-op). There is deliberately no automatic link
  from `ChallengeSpec.ai_resistance`/the static score into this engine's
  weights -- weights are supplied explicitly by the caller, keeping the engine
  free of any dependency on generation-time models.

**`scoreboard.py`** is a pure fold: `compute_scoreboard`/
`compute_challenge_values` take already-loaded `SolveEvent`s, a
`ChallengeScoringConfig` mapping, a `CompetitionConfig`, an engine, and an
`as_of` and return a byte-identical `ScoreboardSnapshot` for the same inputs.
Point values are **not** locked in at solve time: every recorded solve of a
challenge is worth that challenge's value *as recomputed at render time*
(retroactive decay, matching CTFd's actual behavior). A single first-blood
bonus per challenge is awarded to whichever solve sorts earliest under a
deterministic `(solved_at, submission_id, team_id)` tie-break. The three
`load_*` functions at the bottom of the module are the only I/O in it.

**`competition_service.py`** is the façade a dashboard/CLI/MCP tool would talk
to for a live competition: `ChallengeCatalog` resolves a challenge's scoring
config plus display metadata (title/category/mode); `project_progress` is a
pure fold of the event log into per-team solved/attempts state, independent of
scoring; `CompetitionService.record_event`/`feed_since`/`progress`/
`leaderboard`/`public_leaderboard` are the read/write surface. `leaderboard()`
returns the full internal `ScoreboardSnapshot`; `public_leaderboard()` returns
a **structurally redacted** subset -- only `display_name`, `rank`, `score`,
`solve_count` per entry, deliberately excluding team ids, per-challenge
detail, attempts, and solved-challenge lists.

**`dashboard_server.py`** is a stdlib-only (`http.server`/`hmac`/`hashlib`/
`secrets`) admin dashboard and public scoreboard, with no Flask/FastAPI
dependency. `dispatch(request, ...)` is the pure router tests call directly
with fake `DashboardRequest`s -- no real sockets in tests; `serve()` is the
thin, intentionally-untested `ThreadingHTTPServer` adapter for real traffic.
Two independent trust boundaries share the module:

- **Admin** routes (`/`, `/api/*`) require a session cookie from `POST
  /login`, PBKDF2-verified against `AuthConfig` (200k iterations by default).
  Every authenticated request **rotates** the session token (the old token
  stops working immediately), and every `POST` additionally requires a
  matching `X-CSRF-Token` header checked with `secrets.compare_digest`.
- **Public** routes (`/public/scoreboard`, `/public/feed`) require only a
  separate, static public scoreboard token (`X-Public-Token` header or
  `?token=`) -- never the admin session -- and expose nothing but the
  already-redacted `public_leaderboard()` view plus a redacted solve feed
  (`seq`/`ts`/`type`/`display_name` only). This is the URL an admin can hand
  out to contestants without handing out dashboard access.

## AI-Agent Evaluation

`agent_eval.py` closes the loop between the scenario engine and the score:
it measures how a solver agent actually fares against a *generated, live*
challenge (public surface only -- `public/description.md`, `public/hints.yaml`,
and live HTTP; never `private/`), and how much the live-adversarial scenario
degrades that success. CLI-only, effectful module (drives Docker/subprocess
via the same `runtime_validator.CommandRunner`) -- never importable from
`mcp_server.py`.

- `SolverAgent` is the injectable Protocol (`solve(base_url, public_dir, http,
  rng, max_steps, deadline) -> AgentTranscript`). `ScriptedSolverAgent` is the
  deterministic baseline: it extracts `` `METHOD /path` `` and header hints
  from the public files via regex, and tries each candidate in order, bounded
  by `max_steps`, without adapting to responses -- deliberately modeling "read
  the writeup once, replay it," the exact baseline the live-adversarial engine
  is meant to beat. `LlmSolverAgent` is a documented extension point (lazily
  imports `anthropic`/`openai`, currently a stub) for a real AI-agent
  evaluation.
- Three built-in `EVAL_PROFILES` scale the step/time budget:
  `one_shot_prompt` (1 step, models a single LLM guess), `writeup_replay`
  (8 steps, the fixed-plan baseline), and `tool_using_agent` (20 steps, models
  an iterative tool-calling agent).
- `run_agent_eval` builds/launches the challenge's Docker stack (reusing the
  same build/up/health-check/teardown sequence as
  `runtime_validator.validate_runtime`), runs one agent, and returns an
  `AgentEvalReport` (solved/steps/notes).
- `run_adversarial_delta` runs the same profile **twice** against the same
  live fixture: once as a plain baseline, once wrapped by
  `_ScenarioDefendedHTTPClient`, which applies a precomputed
  `scenario.ScenarioRunReport`'s `rotate_credential`/`patch_route`/
  `quarantine_host` effects -- from the tick each target broke onward, any
  request whose URL or headers mention that target is short-circuited to a
  `403` instead of reaching the real app. This is the empirical AI-resistance
  measurement: `AdversarialDeltaReport.success_dropped` is `True` exactly when
  live defense flipped a baseline solve into a non-solve, and `step_delta`
  reports how many extra steps the agent burned. `ctfgen eval-agent
  --adversarial` runs this end to end and can persist an
  `AdversarialDeltaReport` via `--report-dir`; `score.score_with_agent_eval`
  can blend a saved report's outcome (30% weight) into the static score.

## Injectability & Offline-Testability Discipline

Every module added since the MVP follows the same rule the original
`runtime_validator.CommandRunner` established: **any effect that touches the
network, a subprocess, the filesystem beyond plain reads/writes, the wall
clock, or randomness sits behind a small Protocol or injected callable, with a
deterministic fake supplied by the test suite.** Concretely:

| Effect | Protocol / injected callable | Deterministic fake / default |
| --- | --- | --- |
| Docker / subprocess | `runtime_validator.CommandRunner` | fake runner recording commands, scripted `CompletedProcess` |
| Live CVE fetch | `cve_source.CveSource` (`fetch`/`get`) | `SnapshotCveSource` (bundled fixture) |
| NVD HTTP fetch | `cve_source.NvdFetcher` | fake fetcher returning scripted JSON bytes |
| Cache TTL clock | `cve_source.Clock` | fixed clock function |
| Scenario environment mutation | `scenario.EnvironmentController` | `NullEnvironmentController` (records, no-ops) |
| Scenario exogenous events | `scenario.EventSource` | `ReplayEventSource` (tick-keyed script) |
| Scenario decision-making | `scenario.Agent` | `ScriptedDefender` / `ScriptedAttacker` |
| Live Docker env for a scenario | `scenario_runtime` reuses `CommandRunner` | same fake runner |
| Live scenario HTTP polling | `scenario_runtime.Fetcher` | fake fetcher returning scripted JSON text |
| Agent-eval HTTP | `agent_eval.HTTPClient` | fake client returning scripted `HTTPResponse`s |
| Agent decision-making | `agent_eval.SolverAgent` | `ScriptedSolverAgent` (pure regex-driven plan) |
| Competition event log | `events.EventStore` | `InMemoryEventStore` |
| Event/session timestamps | `events.Clock` / `dashboard_server.Clock` | fixed clock functions |
| Dashboard session tokens | `dashboard_server.SessionStore` / `TokenFactory` | `InMemorySessionStore` with a deterministic token factory |
| Competition scoring "now" | `scoring_engine`/`scoreboard` `now`/`as_of` args | explicit `datetime` passed by the caller, never read internally |

No module reaches for `random`, `time.time()`/`datetime.now()`, `subprocess`,
`urllib`, or a real socket except behind one of these seams, which is what lets
the entire pipeline -- generation, validation, scoring, the scenario engine,
agent evaluation, and the competition platform -- be exercised by the test
suite with zero Docker, zero network, and zero wall-clock dependence, while the
CLI wires in the real implementations for actual use.

## Security Boundary: MCP vs CLI

The MCP server (`mcp_server.py`) exposes a *pure, side-effect-bounded* subset
of CTFGenerator's capabilities: spec drafting, spec/challenge validation,
static scoring, filesystem rendering, and read-only registry/CVE/scenario
lookups. Every module that can build a container, run a live network request
against something the model doesn't control, drive an AI agent, or hand out
dashboard credentials is **CLI-only** and structurally forbidden from being
imported by the MCP server:

- `runtime_validator.py` (Docker build/launch/health-check/solve/cleanup)
- `replay_validator.py` and `sibling_validator.py` (drive Docker for
  cross-instance replay/comparison)
- `scenario_runtime.py` (real `docker compose exec`/`stop`, real HTTP against
  a live challenge)
- `agent_eval.py` (drives Docker + a solver agent, optionally an LLM, against
  a live instance)
- `dashboard_server.py` (owns admin credentials, session cookies, and the
  public scoreboard token)

A regression test in `tests/test_mcp_server.py` enforces this boundary at
import time, not just by convention: connecting an MCP host to
`ctfgen-mcp` can never result in that host's model triggering a container
build, a live exploit attempt, an AI-agent run, or dashboard access -- those
all remain commands a human runs directly via `ctfgen`.

## AI-Resistance Model

The generator should prefer challenges that are:

- Novel per generated instance
- Stateful
- Multi-step
- Environment-dependent
- Driven by realistic workflows
- Resistant to direct flag or writeup sharing
- Fair to humans through discoverable clues
- Resistant to live, mid-solve environment drift (scenario-enabled challenges)

The original challenge family uses an API and worker authorization mismatch. A
generic scanner is insufficient; the solver has to inspect live routes, read
operational notices, understand the queue workflow, and exploit a legacy trust
boundary. Seven further families extend this across scada_ics, network,
crypto, cloud, forensics, binary, and mobile categories, each with its own
required-file/compose-marker shape and scoring hints (see Family & Mode
Taxonomy above), and each optionally CVE-grounded and/or scenario-enabled.

Sibling validation generates two related challenges from the same family and
verifies that route names, support endpoints, tenant fields, tenants, and
invoice IDs differ. With `--runtime`, each sibling is built, launched, solved,
and cleaned up sequentially.

## Runtime Safety Defaults

Generated Docker Compose environments should default to:

- No host networking
- No Docker socket mounts
- Dropped Linux capabilities
- `no-new-privileges`
- Memory and process limits
- Internal service networks where possible
- Explicit published ports only for learner-facing services

## Module Map

```text
models.py            -- ChallengeSpec and every other serializable dataclass
                         (AIResistance, DynamicVariation, ScenarioSpec/
                         TriggerSpec/ResponseSpec, Submission/SolveEvent,
                         ChallengeScoringConfig/CompetitionConfig,
                         ScoreboardEntry/Snapshot, ChallengeValueSnapshot)
spec_generator.py     -- SpecBackend protocol; Deterministic/Anthropic/OpenAI backends
cve_source.py         -- injectable CveSource: Snapshot/Nvd/Caching, CveRecord
cve_blueprint.py      -- pure CveRecord -> themed ChallengeSpec transform
families.py           -- Family registry + FamilyRenderer protocol + ScoringHints
templates/*.py        -- one render module per family (tenant_export + 7 others)
generator.py          -- create_challenge / create_challenge_from_cve
validator.py          -- family-dispatched static artifact validation
score.py              -- family-aware AI-resistance scoring (+ scenario dimension)
scenario.py           -- pure, offline, deterministic scenario engine core
scenario_runtime.py   -- CLI-only Docker/HTTP-backed scenario environment
runtime_validator.py  -- CLI-only Docker build/launch/health/solve/cleanup
replay_validator.py   -- CLI-only cross-instance solver replay
sibling_validator.py  -- CLI-only sibling generation/comparison
agent_eval.py         -- CLI-only solver-agent harness + adversarial delta
events.py             -- append-only competition EventStore (in-memory/JSONL)
scoring_engine.py     -- pluggable ScoringEngine registry (4 engines)
scoreboard.py         -- pure event-log -> ScoreboardSnapshot fold
competition_service.py-- live competition façade (progress/leaderboard/events)
dashboard_server.py   -- CLI-only admin dashboard + public scoreboard (stdlib HTTP)
report_writer.py       -- versioned JSON report envelopes for CLI commands
report_index.py       -- summarize persisted report artifacts
mcp_server.py         -- pure-tools-only MCP surface (the security boundary)
cli.py                -- ctfgen entry point wiring all of the above
```

## Future Services

Remaining long-term platform components:

- Frontend: Next.js or another React-based admin and learner UI (today's admin
  surface is the stdlib JSON dashboard in `dashboard_server.py`)
- Database: PostgreSQL for durable competition/team/challenge storage (today's
  persistence is JSONL event logs and JSON report artifacts)
- Build/runtime: Docker BuildKit and Docker Compose first, Kubernetes later
- AI orchestration: a real `LlmSolverAgent` implementation and role-specific
  generation/repair loops beyond today's metadata-only spec backends
- Auth: multi-admin / role-based access beyond the single-admin-account model
  in `dashboard_server.AuthConfig`
