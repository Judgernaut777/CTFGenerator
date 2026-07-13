# CTFGenerator

CTFGenerator is an AI-resistant CTF platform: a deterministic, CVE-driven,
multi-domain challenge **generator core** plus a **self-hosted competition
platform** for running live events end-to-end.

Challenges are never stored as static artifacts to hand out — every challenge
is regenerated deterministically from a seed (optionally folded together with
a real CVE id) at build time. The same seed always reproduces byte-identical
routes, credentials, decoys, and flags, which is what makes static validation,
sibling-variant comparison, and cross-instance exploit replay possible.
Nothing about a specific instance is ever memoized to disk except the
rendered challenge folder itself.

**New here?** [docs/getting-started.md](docs/getting-started.md) routes the
four audiences — operator/deployer, challenge author, contestant, CLI user —
to the right doc.

## The two halves

- **The generator core** — a dependency-free Python engine that drafts specs,
  renders deterministic challenge bundles, grounds them in real CVEs, runs the
  live-adversarial scenario engine, and scores/evaluates AI-resistance. Driven
  by the `ctfgen create|spec|validate|score|...` commands (below), and usable
  entirely offline.
- **The self-hosted platform (M6+)** — a FastAPI control plane, PostgreSQL,
  auth/RBAC, organizer + contestant web apps, and isolated workers that build
  and run challenges off the control plane. This is the supported product; the
  generator core is the engine underneath it.

## The platform

- **Control plane** — a FastAPI JSON API served at `/api/v1`
  (`src/ctf_generator/interfaces/api/`). Eighteen routers cover competitions,
  teams, users, challenge definitions/versions, submissions, scoreboard,
  instances, builds, evaluations, publications, artifacts, jobs, audit, auth,
  system, plus optional OIDC and a plane-isolated worker gateway. The live
  contract is the OpenAPI document at `/api/v1/openapi.json`, with Swagger UI
  at `/api/v1/docs`.
- **Auth + RBAC (M10)** — local password login and hash-only bearer sessions,
  optional OIDC authorization-code+PKCE federation, and per-competition role
  scoping. Eight competition roles (`player`, `captain`, `author`, `organizer`,
  `admin`, `observer`, `judge`, `support`; `domain/identity/models.py`
  `VALID_ROLES`) plus two deployment-global system roles (`admin`, `support`).
  See [docs/adr/007-authentication-and-sessions.md](docs/adr/007-authentication-and-sessions.md)
  and [docs/security/oidc.md](docs/security/oidc.md).
- **Web apps (M11/M12)** — a server-rendered sub-app mounted at `/app`
  (`src/ctf_generator/interfaces/web/`): the organizer dashboard and the
  contestant portal, sharing one hardened stack (cookie session bridge over the
  M10 auth service, per-response CSP nonce, double-submit CSRF, no CDN, no JS).
  See [docs/web/contestant-portal.md](docs/web/contestant-portal.md).
- **Workers + job queue (M7/M8)** — a PostgreSQL-backed job queue (`SKIP
  LOCKED` leasing, retries, dead-letter, idempotency) feeds isolated workers
  that build and run generated (untrusted) workloads off the control plane. The
  worker reaches the platform only through the worker gateway with a scoped,
  short-lived credential — an auth plane disjoint from human sessions. See
  [docs/security/runtime-isolation.md](docs/security/runtime-isolation.md).
- **Challenge SDK** — the supported, semver-stable authoring surface
  (`ctf_generator.sdk`); families register through an explicit plugin boundary
  instead of editing a central hub. See
  [docs/CHALLENGE_SDK.md](docs/CHALLENGE_SDK.md).
- **Platform CLI** — `ctfgen <area> <verb>` is an HTTP client for a running
  deployment (auth, competition, team, user, challenge-def, challenge-version,
  publication, submission, instance, job, build, system), authenticated with a
  scoped session token. It is a separate half of the `ctfgen` entry point from
  the generator commands. See [docs/supported-cli.md](docs/supported-cli.md).
- **Deploy stack** — a supported Docker deployment (`deploy/`: API and worker
  images, a compose stack, an entrypoint, and a verify script) behind a TLS
  reverse proxy. See [docs/HOSTING.md](docs/HOSTING.md) and
  [docs/operations/configuration.md](docs/operations/configuration.md).

> **Legacy note.** A single-process stdlib dashboard (`ctfgen serve`) still
> ships for the offline/demo path — a session-authenticated admin API plus a
> separately-tokened public scoreboard over a fixture/JSONL store. It is not the
> supported platform; use the control plane above for real events. The legacy
> walkthrough is §1 onward of [docs/HOSTING.md](docs/HOSTING.md).

## Install

The generator core has no runtime dependencies (Python 3.11+):

```bash
python3 -m pip install -e .
ctfgen --version
```

The platform surfaces are opt-in extras (`.[api]`, `.[db]`, `.[web]`,
`.[cli]`, `.[deploy]`, …) — see [Optional extras](#optional-extras).

## Quick Start (generator core)

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

Compute the advisory AI-resistance score for a generated challenge:

```bash
ctfgen score challenges/invoice-drift
```

The score is a static, advisory quality signal (see
[Three signals of AI-resistance](#three-signals-of-ai-resistance) for what it
does and does not mean). Use `--json` for a machine-readable report or
`--min-score N` to gate generation in CI:

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

## Three signals of AI-resistance

AI-resistance has three distinct signals — do not conflate them. All three are
about *how well a challenge resists an AI solver*, and are separate from
*competition* scoring (how many points a team earns, further below).

1. **The mechanism** — variant regeneration + the live-adversarial engine
   (above). This is what actually resists a solver: a rotating instance and a
   live-reacting defender, not a design claim.
2. **The advisory heuristic** — `ctfgen score` produces a static, per-challenge
   0–100 quality signal by cross-checking the spec's AI-resistance *claims*
   against what the generated artifacts actually do (variant uniqueness,
   statefulness, solver depth, live interaction, scanner resistance). It is an
   **advisory quality signal, not a measured guarantee** — a high score means
   the design has the ingredients, not that a real agent failed.
3. **The measured signal** — the Evaluation Lab (`ctfgen eval-agent`, below)
   runs an actual scripted solver agent against a *live* instance and measures
   the outcome, with and without the live-adversarial engine. This is the
   empirical evidence; the heuristic score is only a proxy for it.

### AI-agent evaluation (the measured signal)

Measures how an AI agent actually fares against a *live* challenge instance —
using only its public surface (`public/description.md`, `public/hints.yaml`,
and live HTTP access), never the private solution — and how much the
live-adversarial engine degrades that success. A large "solved without defense"
vs. "solved with defense" gap means a challenge resists a scripted,
live-reacting adversary, not just a static writeup.

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

## Competition scoring and scoreboard

Distinct from AI-resistance: competition scoring is how many points a team
earns for solving a challenge during a live event.

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

## Use your own subscription via MCP

Instead of an API key, run the generator core as an MCP server and let an MCP
host (Claude Desktop/Code, or any other client) drive it with the model you
already pay for. The host's model drafts the metadata and calls the server's
tools; the LLM never lives in CTFGenerator.

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

To run a live event end-to-end on the supported platform — deploy the control
plane, PostgreSQL, and isolated workers; seed an admin; author and publish
challenges; open the organizer and contestant web apps; record solves — see
**[docs/HOSTING.md](docs/HOSTING.md)** (§0 is the supported platform;
[docs/operations/configuration.md](docs/operations/configuration.md) is the
`CTFGEN_*` env reference). The legacy single-process `ctfgen serve` demo path is
§1 onward of the same document.

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

| Extra       | Adds                                                     | Needs                            |
|-------------|----------------------------------------------------------|-----------------------------------|
| `api`       | The FastAPI control plane at `/api/v1`                    | fastapi, uvicorn, pydantic, httpx |
| `db`        | The persistence layer (PostgreSQL)                       | sqlalchemy, alembic, psycopg      |
| `web`       | The organizer + contestant web sub-app at `/app`         | jinja2                            |
| `oidc`      | OIDC authorization-code+PKCE federated login             | pyjwt[crypto]                     |
| `cli`       | The supported platform CLI (`ctfgen <area> <verb>`)      | httpx                             |
| `worker`    | The networked worker run loop (`ctfgen-worker`)          | httpx                             |
| `deploy`    | Meta-extra: `api` + `db` + `web` + `oidc` + `postgres`   | —                                 |
| `anthropic` | Claude-backed `spec --backend anthropic`                 | `ANTHROPIC_API_KEY`               |
| `openai`    | GPT-backed `spec --backend openai`                       | `OPENAI_API_KEY`                  |
| `mcp`       | The `ctfgen-mcp` MCP server                              | an MCP host                       |
| `cve`       | Opt-in marker for live NVD lookups (`--source nvd`)      | network access (stdlib `urllib`)  |
| `dev`       | `pytest` for the test suite                              | —                                 |

The generator core (`ctfgen create|spec|validate|score|...`) needs none of
these; the platform surfaces do. `cve` carries no dependencies of its own — the
NVD client is stdlib-only; the extra is an opt-in marker.

## License

CTFGenerator is proprietary, for-profit software — see [LICENSE](LICENSE).
Copyright (c) 2026 Judgernaut777, all rights reserved. Commercial use requires a
paid license from the copyright holder; there is no open-source grant.
</content>
</invoke>
