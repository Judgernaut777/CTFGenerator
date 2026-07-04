# CTFGenerator

CTFGenerator is a CVE-driven, multi-domain, live-adversarial CTF challenge
generator, validator, and competition platform.

Challenges are never stored as static artifacts to hand out — every challenge
is regenerated deterministically from a seed (optionally folded together with
a real CVE id) at build time. The same seed always reproduces byte-identical
routes, credentials, decoys, and flags, which is what makes static validation,
sibling-variant comparison, and cross-instance exploit replay possible.
Nothing about a specific instance is ever memoized to disk except the
rendered challenge folder itself.

## What's here

- **8 challenge domains** — web, scada_ics, network, crypto, cloud, forensics,
  binary, mobile — via 8 registered challenge families, each supporting a
  subset of offensive (`red`), defensive (`blue`), and hybrid (`purple`)
  modes.
- **CVE-driven generation** — ground a challenge in a real, named CVE
  (Log4Shell, PrintNightmare, Heartbleed, Zerologon, EternalBlue, and more)
  with difficulty and category derived from the CVE's own CVSS score and CWE
  classification.
- **A live-adversarial scenario engine** — a scripted timeline where a
  defender reacts to an attacker (or vice versa) while the challenge is
  running, so a static writeup goes stale mid-solve. Runs offline
  (deterministic, no Docker) or live against a running Docker instance.
- **AI-resistance scoring** — a static, per-challenge 0–100 score, plus an
  **AI-agent evaluation harness** that measures how a scripted solver agent
  actually fares against a live instance, with and without the live-adversarial
  engine turned on.
- **Competition scoring and a scoreboard** — four pluggable scoring engines
  (including CTFd-style solve-count decay and this project's own time-decay
  default) and a scoreboard computed from a competition's event log.
- **A live competition platform** — `ctfgen serve` runs a session-authenticated
  admin API with a live progress feed, plus a separately-tokened, redacted
  public scoreboard the admin can publish without exposing the admin surface.
- **An MCP server** — drive spec drafting from your own Claude/GPT
  subscription instead of an API key; everything that touches Docker or the
  host stays CLI-only and is never exposed to a model host.

## Install

No runtime dependencies; Python 3.11+:

```bash
python3 -m pip install -e .
ctfgen --version
```

## Quick Start

List the challenge families the generator can produce:

```bash
ctfgen list-families
```

Generate and statically validate a challenge:

```bash
ctfgen create --output challenges/invoice-drift --seed demo-001
ctfgen validate challenges/invoice-drift
```

Run the generated challenge:

```bash
cd challenges/invoice-drift
docker compose up --build
```

In another shell:

```bash
python3 private/solver.py --base-url http://127.0.0.1:8080
```

Run full Docker validation when Docker and image/package downloads are available:

```bash
ctfgen validate-runtime challenges/invoice-drift
```

That command runs static validation, `docker compose build`, `docker compose up -d`, the generated health check, the private solver, and cleanup with `docker compose down --volumes --remove-orphans`.

Score a generated challenge on AI-resistance dimensions:

```bash
ctfgen score challenges/invoice-drift
```

The score cross-checks the challenge spec's AI-resistance claims against what
the generated artifacts actually do (variant uniqueness, statefulness, solver
depth, live interaction, scanner resistance). Use `--json` for a machine-readable
report or `--min-score N` to gate generation in CI:

```bash
ctfgen score challenges/invoice-drift --min-score 80
```

## Challenge domains and families

The CVE category taxonomy (`ctfgen cve-categories`) and the family registry
(`ctfgen list-families`) share the same 8 categories. Each category maps to
exactly one registered family (`cve_blueprint.CATEGORY_FAMILY_MAP`):

| Category    | Family                            | Modes                | CVE-driven |
|-------------|------------------------------------|-----------------------|------------|
| web         | `web_business_logic_tenant_export` | red                   | no         |
| scada_ics   | `scada_ics_modbus_takeover`        | red, blue, purple     | yes        |
| network     | `network_lateral_pivot`            | red, purple           | yes        |
| crypto      | `crypto_token_forgery`             | red                   | yes        |
| cloud       | `cloud_metadata_ssrf`              | red, purple           | yes        |
| forensics   | `forensics_incident_triage`        | blue                  | yes        |
| binary      | `binary_heap_exploit`              | red                   | yes        |
| mobile      | `mobile_insecure_storage`          | red, blue             | yes        |

`web_business_logic_tenant_export` is the original, hand-built family and the
default for `create`/`spec`/`validate-siblings` when `--family` is omitted; it
is stateful (a background worker + queue) and not CVE-driven. The other seven
were added as CVE-groundable templates: `red` is an offensive exploit-the-flaw
challenge, `blue` is a defensive/incident-response challenge (e.g. forensics
triage), and `purple` is a hybrid.

## CVE-driven generation

Search, inspect, and generate from real, named CVEs. The default `snapshot`
source is a small bundled, offline, deterministic dataset (Log4Shell, Struts
S2-045/Equifax, Baron Samedit, Heartbleed, Zerologon, EternalBlue, SambaCry,
PrintNightmare, and more); pass `--source nvd` to query the live NVD 2.0 REST
API instead.

```bash
ctfgen cve-categories
ctfgen cve-search --category web --min-cvss 9.0 --limit 5
ctfgen cve-search --keyword heartbeat
ctfgen cve-show CVE-2021-44228
```

`cve-search`/`cve-show` accept `--cache-dir DIR` to TTL-cache results to disk
(useful with `--source nvd` to avoid hammering the live API).

Generate a challenge grounded in a specific CVE:

```bash
ctfgen create-from-cve CVE-2021-44228 --output challenges/log4shell --seed demo-001
# equivalently:
ctfgen create-from-cve --cve-id CVE-2021-44228 -o challenges/log4shell --seed demo-001
```

The CVE's category picks the family via `CATEGORY_FAMILY_MAP` above (`--family`
overrides it); its CVSS score picks the difficulty (`>= 9.0` → hard, `>= 7.0`
→ medium, else easy; `--difficulty` overrides it); its category also picks the
mode (`blue` for forensics, `red` otherwise — `create-from-cve` has no `--mode`
flag, so this is not overridable from the CLI). The instance seed is the CVE
id folded into your base seed (`{seed}:{cve_id}`), so regenerating the same
CVE with the same base seed is byte-identical, and generating several CVEs
from one base seed never collides. The title, learning objectives, and
solve-path checkpoints are themed from the CVE's CWE and affected product; a
SHA-256 hash of the CVE record is stored in the spec for drift detection.

## The live-adversarial engine

The real AI-resistance mechanism: a scripted timeline where a defender reacts
live to an attacker (or vice versa) while the challenge runs, so a solver that
only replays a static writeup finds its plan going stale mid-solve — a
rotated credential, a patched route, a quarantined host. Challenges generated
from a spec with a `scenario` block write a flat, replayable timeline to
`private/scenario_timeline.json`.

Run a challenge's scenario offline — fully deterministic, no Docker, no
network, no wall clock:

```bash
ctfgen run-scenario challenges/log4shell
ctfgen run-scenario challenges/log4shell --max-ticks 30 --json
```

Prints each tick's timeline events, which triggers fired, and which attacker
moves were blocked. A challenge with no recorded timeline runs an inert
scenario (0 triggers) rather than erroring.

Run the same scenario against a real, running Docker instance instead — this
drives `docker compose` for defender actions (rotate a credential, patch a
route, quarantine a host, inject noise) and polls the live app's HTTP state
endpoint for attacker/sensor events:

```bash
ctfgen run-scenario challenges/log4shell --runtime --base-url http://127.0.0.1:8080
```

## AI-resistance scoring vs. competition scoring

These are two different scoring systems. `ctfgen score` (above) rates one
generated challenge's AI-resistance out of 100. Everything below is
*competition* scoring — how many points a team earns for solving a challenge
during a live event.

List the registered competition scoring engines:

```bash
ctfgen list-scoring-engines
```

```
ai_resistance
dynamic_decay
static
time_decay (default)
```

- `static` — a constant value per challenge, regardless of solve count or time.
- `dynamic_decay` — CTFd-style value decay as `solve_count` rises (`linear` or
  `logarithmic`, per `ChallengeScoringConfig.decay_function`/`.decay`).
- `time_decay` — **the default engine.** Value decays linearly with *elapsed
  competition time* instead of solve count, rewarding early solves regardless
  of how many teams have solved it.
- `ai_resistance` — wraps another engine and applies an advisory per-challenge
  weight multiplier (a no-op passthrough unless weights are supplied).

Compute a scoreboard from a competition's event log and challenge configs
(all plain JSON fixtures):

```bash
ctfgen scoreboard \
  --events events.json \
  --challenges challenges.json \
  --config config.json \
  --engine time_decay \
  --json
```

`--engine` defaults to `time_decay` when omitted. `--as-of ISO-8601-TIMESTAMP`
computes a frozen historical snapshot instead of scoring as of now. `events.json`
is a JSON array of solve events (`team_id`, `challenge_id`, `solved_at`,
`submission_id`); `challenges.json` is a JSON array of
`ChallengeScoringConfig` records (`challenge_id`, `initial_value`,
`minimum_value`, `decay_function`, `decay`); `config.json` is a single
`CompetitionConfig` object (`competition_id`, `name`, `start_time`,
`end_time`, and optionally `scoring_start_time`/`freeze_time`).

## AI-agent evaluation

Measures how an AI agent actually fares against a *live* challenge instance —
using only its public surface (`public/description.md`, `public/hints.yaml`,
and live HTTP access), never the private solution — and how much the
live-adversarial engine degrades that success. This is the empirical
AI-resistance signal: a large "solved without defense" vs. "solved with
defense" gap means a challenge resists a scripted, live-reacting adversary,
not just a static writeup.

```bash
ctfgen eval-agent challenges/log4shell --profile writeup_replay
```

Three built-in profiles, all driving the same deterministic baseline agent
(`ScriptedSolverAgent`, which extracts a plan from `public/` and does not
adapt to responses) with different step/time budgets:

| Profile             | Steps | Models                                          |
|----------------------|-------|--------------------------------------------------|
| `one_shot_prompt`     | 1     | a single best-guess request (one-shot LLM prompt) |
| `writeup_replay`      | 8     | replays a fixed plan without adapting            |
| `tool_using_agent`    | 20    | a larger budget, models an iterative tool-caller  |

Add `--adversarial` to run the same profile twice — scenario engine off, then
on — and report the delta:

```bash
ctfgen eval-agent challenges/log4shell --profile writeup_replay --adversarial
```

```
Adversarial delta for challenges/log4shell [writeup_replay]
  baseline:    solved=True steps=2
  adversarial: solved=False steps=5
  success_dropped=True step_delta=3
```

`success_dropped=True` means live defense flipped a solve into a non-solve —
direct evidence the live-adversarial engine, not just the static challenge
design, is doing the AI-resisting.

## The competition platform

`ctfgen serve` runs the live competition backend: a session-authenticated
admin JSON API with a live progress feed, and a separately-tokened public
scoreboard endpoint that can be shared with contestants/spectators without
exposing the admin surface at all.

```bash
ctfgen serve --admin-user admin --admin-password 'change-me' \
  --events-file events.jsonl --challenges challenges.json --config config.json
```

`--public-token` fixes the public scoreboard token; if omitted, one is
generated randomly and printed once at startup. `--events-file` persists the
event log to JSONL (default: in-memory only, lost on restart). `--challenges`
and `--config` accept the same JSON shapes as `scoreboard` above; both default
to an empty catalog / a permissive year-long placeholder competition when
omitted.

Admin routes (`POST /login`, `GET /`, `/api/progress`, `/api/leaderboard`,
`/api/feed`, `POST /api/event`) require a session cookie from `/login` (a
PBKDF2-hashed username/password check); every authenticated request rotates
the session token, and every `POST` additionally requires a matching
`X-CSRF-Token` header. Public routes (`GET /public/scoreboard`, `GET
/public/feed`) require only the separate public token (`X-Public-Token` header
or `?token=`) and expose nothing but a redacted leaderboard (display name,
rank, score, solve count — no team ids, no per-challenge detail) and a
redacted solve feed.

## Structured specs and LLM-drafted metadata

Generate a structured challenge spec before rendering any code, then render
from it. The default backend is deterministic and offline:

```bash
ctfgen spec --output specs/invoice-drift.json --seed demo-001 --difficulty hard
ctfgen create --output challenges/invoice-drift --from-spec specs/invoice-drift.json
```

`spec`/`create` also take `--mode` (default `red`) and repeatable `--cve-ref
CVE-ID` to fold CVE provenance into a hand-built spec without going through
`create-from-cve`.

Two optional LLM backends draft the pedagogical metadata (title, learning
objectives, checkpoints) — never code, flags, or the security-relevant
AI-resistance knobs, which stay deterministic. Each is behind its own extra and
needs that provider's API key; the generated spec is validated before it can be
rendered. The `--model` flag defaults per provider (`claude-opus-4-8` for
Anthropic, `gpt-5.1` for OpenAI):

```bash
pip install -e '.[anthropic]'   # needs ANTHROPIC_API_KEY (or an `ant auth login` profile)
ctfgen spec --output specs/drift.json --backend anthropic

pip install -e '.[openai]'      # needs OPENAI_API_KEY
ctfgen spec --output specs/drift.json --backend openai
```

## Sibling validation and exploit replay

Generate and compare sibling variants:

```bash
ctfgen validate-siblings --output challenges/invoice-siblings --seed demo-001 --force
```

Run full Docker validation for each sibling sequentially:

```bash
ctfgen validate-siblings --output challenges/invoice-siblings --seed demo-001 --force --runtime
```

Cross-sibling exploit replay proves an exploit generalizes rather than being a
memorized answer: it points one sibling's solver at the *other* sibling's live
instance and requires it to extract the flag. Add `--cross-replay` to a runtime
sibling run:

```bash
ctfgen validate-siblings --output challenges/invoice-siblings --seed demo-001 --force --runtime --cross-replay
```

Or replay any solver against any target instance directly:

```bash
ctfgen replay challenges/invoice-a challenges/invoice-b
```

Both build and launch the target with Docker, run the solver against it, and
tear it down. A solver that hardcoded one instance's routes/flag fails here; the
generated solvers discover routes and tokens at runtime, so they succeed.

## Reports and dashboards

Persist a validation/score/CVE/scenario/scoreboard/eval-agent result as a JSON
artifact with `--report-dir` (supported by `validate`, `validate-runtime`,
`validate-siblings`, `score`, `replay`, `create-from-cve`, `run-scenario`,
`scoreboard`, and `eval-agent`):

```bash
ctfgen score challenges/invoice-drift --report-dir /tmp/reports
```

Each report is a timestamped, versioned JSON envelope (`schema_version`,
`generator_version`, `command`, `subject`, `timestamp`, `git_commit`, `status`,
`result`). Reports are never overwritten, and a failed report write never changes
the command's exit code, so the flag is safe to add in CI to build an auditable
validation trail. Generated challenges also carry a `meta` block (generator
version, spec version, family, seed) in `challenge.yaml` and `private/variant.json`
so any instance is traceable back to the build that produced it.

Summarize accumulated report artifacts as a table, or a self-contained HTML
dashboard:

```bash
ctfgen report-index /tmp/reports
ctfgen report-index /tmp/reports --html /tmp/reports/index.html
```

### Use your own subscription via MCP

Instead of an API key, run CTFGenerator as an MCP server and let an MCP host
(Claude Desktop/Code, or any other client) drive it with the model you already
pay for. The host's model drafts the metadata and calls the server's tools; the
LLM never lives in CTFGenerator.

```bash
pip install -e '.[mcp]'
ctfgen-mcp   # speaks MCP over stdio
```

Point your host at that command (e.g. in Claude Desktop's MCP config). The
server exposes only pure, side-effect-bounded tools — `list_families`,
`spec_schema`, `build_spec`, `validate_spec`, `create_from_spec`,
`create_challenge`, `validate_challenge`, `score_challenge`,
`report_index_table`, `family_info`, `list_cves`, `scenario_timeline_summary`
— plus a `design_challenge` prompt. `list_cves` always reads the bundled
offline CVE snapshot (never the live NVD source, and never a fetch of any
kind), and `scenario_timeline_summary` only parses an already-generated
challenge's `private/scenario_timeline.json`, so nothing exposed over MCP
touches the network. **Docker, AI-agent evaluation, and the competition
dashboard are deliberately not exposed over MCP** — `validate-runtime`,
`replay`, `validate-siblings --runtime`, `run-scenario --runtime`,
`eval-agent`, and `serve` all stay CLI-only, so connecting a model host to
this server never hands it container builds, host execution, or a live
scoreboard/admin surface. Run those from the CLI.

## Host a competition

Want to run a live event end-to-end — generate a batch of challenges, build a
catalog, launch the session-authenticated admin dashboard, publish a public
scoreboard, and record solves? See **[docs/HOSTING.md](docs/HOSTING.md)** for
the full copy-pasteable walkthrough, including `ctfgen quickstart`, `ctfgen
catalog`, `ctfgen serve --challenges-dir`, the browser admin UI at `/login`
and `/`, the public scoreboard at `/public?token=...`, scoring-engine choices,
the optional `[postgres]` durable event store, and the session/CSRF/public-
token security model.

## Development

To work on the tool without installing it, run the package directly from the
source tree with `PYTHONPATH=src` (the `ctfgen` invocations above map to
`python3 -m ctf_generator`):

```bash
PYTHONPATH=src python3 -m ctf_generator create --output /tmp/invoice-drift --seed demo-001 --force
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m compileall -q src tests
```

## Optional extras

| Extra       | Adds                                              | Needs                          |
|-------------|----------------------------------------------------|---------------------------------|
| `anthropic` | Claude-backed `spec --backend anthropic`           | `ANTHROPIC_API_KEY`             |
| `openai`    | GPT-backed `spec --backend openai`                 | `OPENAI_API_KEY`                |
| `mcp`       | The `ctfgen-mcp` MCP server                        | an MCP host                     |
| `cve`       | Opt-in marker for live NVD lookups (`--source nvd`)| network access (stdlib `urllib`)|
| `web`       | Opt-in marker for `ctfgen serve`                   | nothing (stdlib `http.server`)  |
| `dev`       | `pytest` for the test suite                        | —                                |

`cve` and `web` carry no package dependencies of their own — both the NVD
client and the dashboard server are stdlib-only; the extras exist as
documentation/opt-in markers, not as installable requirements.

## License

CTFGenerator is proprietary, for-profit software — see [LICENSE](LICENSE).
Copyright (c) 2026 Judgernaut777, all rights reserved. Commercial use requires a
paid license from the copyright holder; there is no open-source grant.
