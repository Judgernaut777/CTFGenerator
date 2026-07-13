# Current CLI Reference (`ctfgen`)

> **HISTORICAL (M0 / v0.1.0 baseline).** Reference for the pre-platform generator CLI — every
> legacy subcommand and flag, the MCP tool/prompt surface, PEP 668 host invocation notes, and a
> pure-vs-Docker classification, all grounded in the v0.1.0 codebase map. The `ctfgen <area>
> <verb>` platform CLI that the "Target/Planned" columns anticipated shipped in **M13**: it talks
> to the platform HTTP API with a session token — see
> **[docs/supported-cli.md](supported-cli.md)** for the supported surface (auth + per-area verbs)
> and the enforced MCP boundary. The `ctfgen` dispatcher still delegates to the legacy generator
> commands documented below unchanged, so this file remains their reference; for the current
> system as a whole see [`architecture/overview.md`](architecture/overview.md).

`prog = ctfgen` — "Generate and validate AI-resistant CTF challenge environments."

- `--version` prints `ctfgen <version>` and exits.
- With **no subcommand**, `main` prints help to **stderr** and returns exit code **2**.
- An unrecognized subcommand falls through to `parser.error("unknown command: …")` (argparse exit 2).
- The god-module `cli.py` (~1389 lines) inlines all command logic and imports nearly every subsystem.

---

## Invocation on this host (PEP 668 / externally-managed environment)

There is **no `__main__` guard inside `cli.py`** and no installed `ctfgen` console script on this box.
Package code lives under `src/`, so run the CLI by putting `src` on `PYTHONPATH` and calling
`cli.main()` directly:

```bash
cd /home/mini/CTFGenerator
PYTHONPATH=src python3 -c 'from ctf_generator.cli import main; main()' <subcommand> [flags]
```

Notes:
- `main()` reads `sys.argv`, so arguments after the `-c` program string are consumed normally.
- The package also ships `src/ctf_generator/__main__.py` (`python -m ctf_generator` → `cli.main`),
  which works **only** when `ctf_generator` is importable (i.e. `PYTHONPATH=src` or an install).
- Effectful subcommands additionally need Docker (`docker compose`) and/or network access — see the
  Effect column below.

### Reporting convention
Any subcommand that accepts `--report-dir` calls `_write_cli_report`, a best-effort JSON artifact
write. If `--report-dir` is unset it no-ops; on failure it warns to stderr and never changes stdout
or the exit code.

### Effect legend
- **Pure** — no Docker/network/sockets; filesystem read/write only.
- **Effectful (Docker)** — builds/launches containers, may execute bundle-shipped code.
- **Effectful (network)** — opens a socket or fetches remote data (LLM provider, NVD, HTTP bind).

---

## Command index by lifecycle

The `ctgen` column marks the **Target/Planned** `ctgen <area> <verb>` layout (see the last section).
It is aspirational; today only the flat `ctfgen <command>` names exist.

### Authoring
| Command | Effect | Purpose | Planned `ctgen <area> <verb>` |
|---|---|---|---|
| `spec` | Pure / **network** w/ `--backend anthropic\|openai` | Draft + validate a spec JSON before rendering | `author spec` |
| `create` | Pure | Render a challenge bundle from seed/family (or `--from-spec`) | `author create` |
| `create-from-cve` | Pure / **network** w/ `--source nvd` | Render a bundle grounded in a real CVE | `author create-from-cve` |
| `list-families` | Pure | List generatable families | `author families` |
| `quickstart` | Pure | Generate a web+crypto+CVE sample set, print next commands | `author quickstart` |
| `catalog` | Pure | Scan a dir of challenges into a `ChallengeScoringConfig` JSON | `author catalog` |

### Validation
| Command | Effect | Purpose | Planned `ctgen <area> <verb>` |
|---|---|---|---|
| `validate` | Pure | Static artifact validation | `validate static` |
| `validate-runtime` | **Docker** | Build/launch/health/solve/teardown | `validate runtime` |
| `validate-siblings` | Pure / **Docker** w/ `--runtime` | Generate siblings, verify they differ | `validate siblings` |
| `replay` | **Docker** | Run one bundle's solver vs another's live instance | `validate replay` |
| `run-scenario` | Pure / **Docker** w/ `--runtime` | Run a challenge's scripted scenario timeline | `validate scenario` |

### Scoring (challenge quality)
| Command | Effect | Purpose | Planned `ctgen <area> <verb>` |
|---|---|---|---|
| `score` | Pure | AI-resistance dimension scoring | `score challenge` |

### Competition serving
| Command | Effect | Purpose | Planned `ctgen <area> <verb>` |
|---|---|---|---|
| `list-scoring-engines` | Pure | List registered competition scoring engines | `compete engines` |
| `scoreboard` | Pure | Compute a scoreboard from JSON fixtures | `compete scoreboard` |
| `eval-agent` | **Docker** | AI-agent evaluation vs a live instance | `evaluate agent` |
| `serve` | **network** (binds socket) | Serve admin dashboard + public scoreboard | `compete serve` |
| `report-index` | Pure | Summarize JSON report artifacts as table/HTML | `report index` |

### CVE
| Command | Effect | Purpose | Planned `ctgen <area> <verb>` |
|---|---|---|---|
| `cve-search` | Pure / **network** w/ `--source nvd` | Search CVE records | `cve search` |
| `cve-show` | Pure / **network** w/ `--source nvd` | Show one CVE record | `cve show` |
| `cve-categories` | Pure | List the CVE category taxonomy | `cve categories` |
| `create-from-cve` | Pure / **network** w/ `--source nvd` | (see Authoring) | `cve create` / `author create-from-cve` |

---

## Authoring commands

### `create` — Pure
Renders a challenge bundle; no Docker.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--output`, `-o` | Path | — | **yes** |
| `--seed` | str | `demo-001` | no |
| `--title` | str | `Invoice Drift` | no |
| `--difficulty` | `easy\|medium\|hard` | `medium` | no |
| `--family` | choice (`FAMILIES`) | `web_business_logic_tenant_export` | no |
| `--force` | flag | False | no |
| `--from-spec` | Path | None | no |
| `--mode` | str | `red` | no |
| `--cve-ref` (dest `cve_refs`, append) | list[str] | `[]` | no |

Behavior: with `--from-spec`, loads + validates the spec JSON; read error → `Could not read spec …`
(stderr) exit **1**; validation failure → `Spec validation failed:` + bullets exit **1**.
`--mode`/`--cve-ref` apply only without `--from-spec`, and only build a spec when mode is non-default
or a cve-ref is supplied (else `create_challenge` builds its own default spec). `FileExistsError`
(output exists, no `--force`) → stderr exit **1**. Success → `Generated challenge at <path>` exit
**0**. No `--report-dir`.

### `spec` — Pure by default; Effectful (network) with `--backend anthropic|openai`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--output`, `-o` | Path | — | **yes** |
| `--seed` | str | `demo-001` | no |
| `--title` | str | `Invoice Drift` | no |
| `--difficulty` | `easy\|medium\|hard` | `medium` | no |
| `--family` | choice | `web_business_logic_tenant_export` | no |
| `--mode` | str | `red` | no |
| `--cve-ref` (dest `cve_refs`, repeatable) | list[str] | `[]` | no |
| `--backend` | `deterministic\|anthropic\|openai` | `deterministic` | no |
| `--model` | str | None | no |

Behavior: builds the backend, calls `.generate(...)`; backend/LLM exception → `Spec generation
failed: …` (stderr) exit **1**. Applies `--mode`/`--cve-ref` overrides only when non-default.
Validates; failure → `Spec validation failed:` + errors exit **1**. Success → writes JSON, prints
`Wrote <backend> spec to <path>` exit **0**. No `--report-dir`. Default models:
`anthropic`=`claude-opus-4-8`, `openai`=`gpt-5.1`.

### `create-from-cve` — Pure with snapshot; Effectful (network) with `--source nvd`
CVE id required via positional **or** `--cve-id` (flag wins); neither → `parser.error` (exit 2).

| Flag / positional | Type | Default | Required |
|---|---|---|---|
| `cve_id` (positional) | str | None | no* |
| `--cve-id` (dest `cve_id_flag`) | str | None | no* |
| `--output`, `-o` | Path | — | **yes** |
| `--seed` | str | `demo-001` | no |
| `--difficulty` | `easy\|medium\|hard` | None | no |
| `--family` | choice | None | no |
| `--title` | str | None | no |
| `--force` | flag | False | no |
| `--source` | `snapshot\|nvd` | `snapshot` | no |
| `--report-dir` | Path | None | no |

Behavior: builds a CVE source (no cache), calls `create_challenge_from_cve(...)`. `FileExistsError`/
`ValueError` → stderr exit **1**. Success → writes report (status `passed`, payload
`{output, cve_id}`), prints `Generated challenge from <cve_id> at <path>` exit **0**.

### `list-families` — Pure
No flags. Prints each family in `FAMILIES` one per line, exit **0**.

### `quickstart` — Pure
Generates three samples under `--output` (all `force=True`): `web-sample`
(`web_business_logic_tenant_export`), `crypto-sample` (`crypto_token_forgery`),
`cve-log4shell-sample` via `create_challenge_from_cve` for `CVE-2021-44228` (snapshot). Prints the
created list then `Next steps:` with exact `ctfgen catalog` / `serve` commands and dashboard URLs.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--output`, `-o` | Path | — | **yes** |
| `--seed` | str | `quickstart-001` | no |

Exit **0**.

### `catalog` — Pure
Scans immediate subdirs containing a `challenge.yaml` (falls back to the dir itself if it is a single
challenge), building one default-scoring entry per challenge (`challenge_id` = folder name,
`title`/`category` from the YAML). Output usable by `serve --challenges`.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--challenges-dir` | Path | — | **yes** |
| `--output`, `-o` | Path | None (stdout) | no |

With `--output`: creates parent dirs, writes JSON + newline, prints `Wrote catalog with <n>
challenge(s) to <path>`. Else prints JSON. Exit **0**.

---

## Validation commands

### `validate` — Pure

| Positional / flag | Type | Default | Required |
|---|---|---|---|
| `challenge_path` (positional) | Path | — | **yes** |
| `--report-dir` | Path | None | no |

Runs `validate_challenge`, writes a report. Errors → `Validation failed:` + bullets exit **1**.
Success → `Validation passed` + `warning: <w>` per warning, exit **0**.

### `validate-runtime` — Effectful (Docker)
Builds, launches, health-checks, solves, tears down.

| Positional / flag | Type | Default | Required |
|---|---|---|---|
| `challenge_path` (positional) | Path | — | **yes** |
| `--base-url` | str | `http://127.0.0.1:8080` | no |
| `--timeout` | int | 90 | no |
| `--keep-running` | flag | False | no |
| `--report-dir` | Path | None | no |
| `--sandbox` | flag | False | no |

**Security note:** unless `--sandbox`, it prints a stderr WARNING that the bundle's
`tests/healthcheck.py` and `private/solver.py` run **on the host with your privileges**. `--sandbox`
runs them inside an ephemeral read-only container instead. Runs `validate_runtime(...)`, writes
report, prints all `report.logs`. Errors → `Runtime validation failed:` + errors exit **1**.
Success → `Runtime validation passed` exit **0**.

### `validate-siblings` — Pure by default; Effectful (Docker) with `--runtime`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--output`, `-o` | Path | — | **yes** |
| `--seed` | str | `demo-001` | no |
| `--title` | str | `Invoice Drift` | no |
| `--difficulty` | `easy\|medium\|hard` | `medium` | no |
| `--family` | choice | `web_business_logic_tenant_export` | no |
| `--force` | flag | False | no |
| `--runtime` | flag | False | no |
| `--cross-replay` | flag | False | no |
| `--timeout` | int | 90 | no |
| `--report-dir` | Path | None | no |

`--cross-replay` without `--runtime` → `parser.error` (exit 2). Runs `validate_siblings(...)`, writes
report, prints logs. Errors → `Sibling validation failed:` + errors exit **1**. Success → prints
`Sibling A:`, `Sibling B:`, `Changed fields:` with bulleted `changed_tokens`, per-warning lines,
then `Sibling validation passed` exit **0**.

### `replay` — Effectful (Docker)
Replays one bundle's solver against another's live instance.

| Positional / flag | Type | Default | Required |
|---|---|---|---|
| `solver_dir` (positional) | Path | — | **yes** |
| `target_dir` (positional) | Path | — | **yes** |
| `--base-url` | str | `http://127.0.0.1:8080` | no |
| `--timeout` | int | 90 | no |
| `--keep-running` | flag | False | no |
| `--report-dir` | Path | None | no |

Runs `cross_replay(...)`, subject id `<solver>-vs-<target>`, writes report, prints logs. Errors →
`Replay failed:` + errors exit **1**. Success → `Replay passed: <solver>'s solver extracted the flag
from <target>` exit **0**.

### `run-scenario` — Pure (offline) by default; Effectful (Docker) with `--runtime`

| Positional / flag | Type | Default | Required |
|---|---|---|---|
| `challenge_dir` (positional) | Path | — | **yes** |
| `--max-ticks` | int | None (engine default) | no |
| `--json` | flag | False | no |
| `--report-dir` | Path | None | no |
| `--runtime` | flag | False | no |
| `--base-url` | str | `http://127.0.0.1:8080` (only with `--runtime`) | no |

Two dispatch branches:
- **`--runtime` (Docker)**: loads `private/scenario_timeline.json` (or empty `ScenarioSpec`), runs
  `scenario_runtime.run_live_scenario(...)`. `--json` → indented sorted JSON; else `Ran live scenario
  for <dir> (<n> ticks)` + per-event lines + `Triggers fired:` + `Attacker moves blocked:`.
- **offline (default)**: `NullEnvironmentController` + empty `ReplayEventSource` (touches nothing
  real). `--json` → JSON; else `Ran scenario for <dir> (<n> ticks)` + events + summaries.

Writes report. Exit **0** in both.

---

## Scoring command

### `score` — Pure

| Positional / flag | Type | Default | Required |
|---|---|---|---|
| `challenge_path` (positional) | Path | — | **yes** |
| `--json` | flag | False | no |
| `--min-score` | float | None | no |
| `--report-dir` | Path | None | no |

Runs `score_challenge`. If the report has errors → writes report `failed`, prints `Scoring failed:`
+ errors exit **1**. Else with `--json` prints the report mapping as indented sorted JSON; without it
prints `AI-resistance heuristic (advisory): <total>/100 (<band>)`, each dimension `- <name> [w=<weight>]: <score>`
plus notes, then warnings. `--min-score` triggers a threshold check: `failed` if `total < min-score`
else `passed`; report written; below threshold → `score <total> is below threshold <min>` exit **1**,
else exit **0**. (Dimensions/bands: see §8 of the schema catalogue — `variant_uniqueness`,
`statefulness`, `solver_depth`, `live_interaction`, `scanner_resistance`, +`scenario_resistance` when
scenario enabled; bands strong/good/moderate/weak.)

---

## Competition-serving commands

### `list-scoring-engines` — Pure
No flags. Prints each engine name, appending ` (default)` to `time_decay`, exit **0**.
Registered engines: `static`, `dynamic_decay`, `time_decay` (default), `ai_resistance`.

### `scoreboard` — Pure
Computes a scoreboard from JSON fixtures.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--events` | Path (JSON array of `SolveEvent`) | — | **yes** |
| `--challenges` | Path (JSON array of `ChallengeScoringConfig`) | — | **yes** |
| `--config` | Path (JSON `CompetitionConfig`) | — | **yes** |
| `--engine` | str | None → `time_decay` | no |
| `--as-of` | ISO-8601 str | None | no |
| `--json` | flag | False | no |
| `--report-dir` | Path | None | no |

Load error (`OSError`/`JSONDecodeError`/`KeyError`/`ValueError`) → `Could not load scoreboard inputs:
…` (stderr) exit **1**. Unknown engine `KeyError` → stderr exit **1**. `--as-of` parsed via
`datetime.fromisoformat` for a frozen snapshot. Writes report (subject id = `config.competition_id`).
`--json` → indented sorted JSON; else `Scoreboard for <id> (frozen=<bool>)` then
`<rank>. <team_id> - <score> pts (<n> solves)` per entry. Exit **0**.

### `eval-agent` — Effectful (Docker)
Runs an AI-agent evaluation against a live instance.

| Positional / flag | Type | Default | Required |
|---|---|---|---|
| `challenge_dir` (positional) | Path | — | **yes** |
| `--profile` | str | — | **yes** |
| `--adversarial` | flag | False | no |
| `--base-url` | str | `http://127.0.0.1:8080` | no |
| `--report-dir` | Path | None | no |

With `--adversarial`: `agent_eval.run_adversarial_delta(...)` (same eval twice, scenario engine off
then on), writes report, prints baseline/adversarial `solved`/`steps`, `success_dropped`,
`step_delta`. Else `agent_eval.run_agent_eval(...)`, writes report, prints `Agent eval for <dir>
[<profile>]: solved=<bool> steps=<n>` plus per-note lines. Exit **0**.

### `serve` — Effectful (network)
Serves the live competition admin dashboard + public scoreboard over the stdlib
`ThreadingHTTPServer` (binds a socket, `serve_forever` blocks). Not Docker.

| Flag | Type | Default | Required |
|---|---|---|---|
| `--host` | str | `127.0.0.1` | no |
| `--port` | int | 8000 | no |
| `--admin-user` | str | — | **yes** |
| `--admin-password` | str | — | **yes** |
| `--events-file` | Path (JSONL persistence) | None (in-memory) | no |
| `--challenges` | Path (JSON `ChallengeScoringConfig[]`) | None (empty catalog) | no |
| `--config` | Path (JSON `CompetitionConfig`) | None (permissive placeholder) | no |
| `--public-token` | str | None (random, printed once) | no |
| `--challenges-dir` | Path | None | no |
| `--secure-cookie` | flag | False | no |

Builds a `CompetitionService`: event store = `JsonlEventStore` if `--events-file` else
`InMemoryEventStore`; catalog from `--challenges-dir` (in-process scan) else `--challenges` else
empty; config from `--config` else `_default_serve_config()` (single always-open window `ctfgen-live`,
365-day). If `--public-token` omitted, prints `public scoreboard token: <token>`. `--secure-cookie`
adds the Secure attribute (meaningful only behind a TLS-terminating proxy; the built-in server is
plain HTTP). Prints `Serving CTFGenerator dashboard on http://<host>:<port>`, serves until
KeyboardInterrupt, closes. Routes: admin `/`, public `/public/scoreboard`, `/public/feed` (all
inline, no external CDN). Exit **0**.

### `report-index` — Pure
Summarizes JSON report artifacts as a table (+ optional HTML).

| Positional / flag | Type | Default | Required |
|---|---|---|---|
| `report_dir` (positional) | Path | — | **yes** |
| `--html` | Path | None | no |

Prints `render_table(index)` to stdout. With `--html`, creates parent dirs, writes a self-contained
static HTML dashboard; on `OSError` prints `warning: failed to write HTML dashboard: …` (stderr) but
still returns **0**. Exit **0**.

---

## CVE commands

### `cve-search` — Pure with `--source snapshot`; Effectful (network) with `--source nvd`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--category` | choice (`cve_source.CATEGORIES`) | None | no |
| `--min-cvss` | float | 0.0 | no |
| `--keyword` | str | None | no |
| `--limit` | int | 20 | no |
| `--source` | `snapshot\|nvd` | `snapshot` | no |
| `--cache-dir` | Path | None | no |

Builds a CVE source (TTL disk-cache wrapper when `--cache-dir` given), fetches, prints
`<cve_id>  [<severity> <score>]  <category>` then indented description per record. None →
`No matching CVEs found`. Exit **0**.

### `cve-show` — Pure with snapshot; Effectful (network) with `nvd`

| Positional / flag | Type | Default | Required |
|---|---|---|---|
| `cve_id` (positional) | str | — | **yes** |
| `--source` | `snapshot\|nvd` | `snapshot` | no |
| `--cache-dir` | Path | None | no |

`source.get(cve_id)`; None → `unknown CVE id: <id>` (stderr) exit **1**. Else prints each
`key: value` of the record mapping, exit **0**.

### `cve-categories` — Pure
No flags. Prints each category (`cve_source.CATEGORIES`:
`web, scada_ics, network, crypto, cloud, forensics, binary, mobile`) one per line, exit **0**.

---

## MCP server (`mcp_server.py`)

FastMCP server, default name `ctfgenerator`, run over **stdio** via `main()`. Tools are plain
functions registered from the `TOOLS` list (unit-testable without the optional `mcp` dependency,
which is imported lazily; missing `mcp` raises a `RuntimeError` pointing at
`pip install ctf-generator[mcp]`).

### Security boundary (current)
Only **pure, side-effect-bounded** tools are exposed. Everything that shells out to Docker or executes
bundle code (`validate-runtime`, `replay`, `validate-siblings --runtime`, `eval-agent`,
`run-scenario --runtime`) stays **CLI-only**. The module imports only `families`, `report_index`,
`spec_generator`, `generator.create_challenge`, `score.score_challenge`,
`validator.validate_challenge`, and lazily `cve_source`; it **never** imports `scenario_runtime`,
`agent_eval`, `dashboard_server`, or `subprocess`. CVE access is **snapshot-only** (no `nvd`/network
reachable via MCP regardless of caller input).

### Filesystem sandbox
Write tools (`create_challenge`, `create_from_spec`) resolve caller `output_dir` against a workspace
root via `_resolve_in_workspace`. Paths escaping the root (absolute-outside or `..`) raise
`WorkspaceError`, returned as `{"ok": False, "errors": [...]}`. Root defaults to process CWD,
overridable via `CTFGEN_MCP_WORKSPACE` env var or `set_workspace_root()` (tests). Rationale: a
semi-trusted model host with `force=True` (which `shutil.rmtree`s first) would otherwise get an
arbitrary host write + recursive-delete primitive.

### Tools (in `TOOLS` order)
| Tool | Purpose | Effect |
|---|---|---|
| `list_families()` | `{families, difficulties}` from `spec_generator`. | Pure |
| `spec_schema()` | `{metadata_schema (_LLM_SCHEMA), families, difficulties, note}`. | Pure |
| `build_spec(family, difficulty, seed, title="", learning_objectives=None, checkpoints=None, mode="red", cve_refs=None)` | Assemble + validate a spec from host metadata (or the deterministic default). Returns `{ok, errors, spec}`. | Pure |
| `validate_spec(spec)` | Structurally validate a spec dict → `{ok, errors}`. | Pure |
| `create_from_spec(spec, output_dir, force=False, mode=None, cve_refs=None)` | Render a bundle from a spec dict; validates first; sandboxed `output_dir`. → `{ok, output_dir}` / `{ok:False, errors}`. | FS write only, **no Docker** |
| `create_challenge(output_dir, seed, title="Invoice Drift", difficulty="medium", family=FAMILIES[0], force=False, mode="red", cve_refs=None)` | Render a bundle deterministically from a seed; sandboxed `output_dir`. → `{ok, output_dir}`. | FS write only, **no Docker** |
| `validate_challenge(challenge_dir)` | Static artifact validation → `{ok, errors, warnings}`. | Pure |
| `score_challenge(challenge_dir)` | AI-resistance score mapping. | Pure |
| `report_index_table(report_dir)` | Summarize persisted JSON reports → `{table}`. | Pure (read-only FS) |
| `family_info(name)` | Registry metadata for one family (`name, category, modes, difficulties, cve_driven, llm_brief, required_files`); unknown → `{ok:False, errors}`. | Pure |
| `list_cves(category=None, keyword=None, limit=10)` | Curated CVEs from the bundled **snapshot** source only → `{cves:[...]}`. | Pure, offline |
| `scenario_timeline_summary(challenge_dir)` | Read-only summary of `private/scenario_timeline.json` (`enabled`, `trigger_count`, `response_count`); `present:False` if absent. | Pure (read-only FS) |

### Prompt
- `design_challenge` → `DESIGN_PROMPT`: instructs the host model to supply only human-facing
  pedagogical metadata (title, learning objectives, ordered checkpoints) and never
  code/exploits/flags/routes/AI-resistance knobs (all generated deterministically server-side);
  advises calling `list_families` and `spec_schema` first, then `build_spec`, then `create_from_spec`.

---

## Pure vs Docker-driving — summary

| Class | Commands / tools |
|---|---|
| **Pure** (CLI) | `create`, `spec` (deterministic), `validate`, `validate-siblings` (no `--runtime`), `score`, `list-families`, `report-index`, `cve-search`/`cve-show`/`cve-categories`/`create-from-cve` (snapshot), `run-scenario` (offline), `list-scoring-engines`, `scoreboard`, `catalog`, `quickstart` |
| **Effectful (Docker)** | `validate-runtime`, `replay`, `validate-siblings --runtime` (+ `--cross-replay`), `run-scenario --runtime`, `eval-agent` |
| **Effectful (network)** | `spec --backend anthropic\|openai`, `cve-*`/`create-from-cve --source nvd`, `serve` (socket bind) |
| **MCP tools** | All pure; write tools do FS-only writes inside a sandboxed workspace; no Docker/network path exists |

Because `validate-runtime` (and by extension the other Docker commands) executes bundle-shipped
`solver.py`/`healthcheck.py` **on the host by default** (`--sandbox`/container isolation is opt-in),
these commands are the current locus of the "generate and execute untrusted code in one process"
concern.

---

## Target/Planned: `ctgen <area> <verb>` layout

**Planned, not implemented.** The productization plan splits `cli.py` (the current god-module) into a
thin interface over an `application/` layer shared with the REST API and MCP, and reorganizes the flat
command names into a `<area> <verb>` grammar. The `ctgen <area> <verb>` column in the lifecycle
tables above is the intended mapping. Proposed areas:

| Area | Covers (planned) | Maps roughly to today's |
|---|---|---|
| `author` | spec, create, create-from-cve, families, quickstart, catalog | Author Studio plane |
| `validate` | static, runtime, siblings, replay, scenario | Execution-plane-backed validation |
| `score` | challenge quality (AI-resistance) | `score` |
| `evaluate` | agent eval, adversarial delta, generalization | Evaluation Lab plane |
| `compete` | engines, scoreboard, serve | Competition Control plane |
| `cve` | search, show, categories, create | CVE grounding |
| `report` | index / dashboards | reporting |

Alignment notes for the refactor:
- **Highest-priority boundary:** the Competition Control plane must **never** execute generated
  challenge code and must **never** hold Docker socket access. In the target split, `validate
  runtime`, `validate replay`, `validate scenario --runtime`, and `evaluate agent` move to the
  isolated **Execution Plane** (workers) and are reached from the control plane only through explicit
  job-result contracts — not by inlining `runtime_validator` as the CLI does today.
- CLI and API are to share the same application services; no business logic in arg parsers or route
  handlers.
- Names, flags, exit codes, and effect classes documented above describe **v0.1.0 current behavior**
  and are the baseline the refactor must preserve or consciously supersede.
