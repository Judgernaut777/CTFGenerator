# Architecture

## Principle

AI may propose a challenge, but deterministic code should build, isolate, validate, and score it.

The platform should treat validation as the core product. A generated challenge is not useful until it is buildable, launchable, solvable, reasonably fair, and contained.

## MVP Shape

The repository currently starts with a local generator and validator CLI:

```text
ctfgen spec -> structured challenge spec (deterministic or LLM backend)
ctfgen create -> challenge folder (optionally --from-spec)
ctfgen validate -> static artifact validation
ctfgen validate-runtime -> Docker build, launch, health check, solve, cleanup
ctfgen validate-siblings -> sibling generation, variant comparison, optional runtime replay
ctfgen score -> static AI-resistance scoring across five dimensions
ctfgen replay -> run one challenge's solver against another's live instance
ctfgen report-index -> summarize persisted reports (table or static HTML)
```

The validation and scoring commands accept `--report-dir` to persist their
result as a JSON artifact (see Persisted Validation Reports below).

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

## MCP Server

`mcp_server.py` runs CTFGenerator as an MCP *server* (`ctfgen-mcp`, stdio), so
an MCP host drives generation with the user's own model/subscription rather than
an API key: the host's model drafts the pedagogical metadata and calls the
server's tools, and the LLM never lives in CTFGenerator.

The exposed surface is deliberately pure: `list_families`, `spec_schema`,
`build_spec`, `validate_spec`, `create_from_spec`, `create_challenge`,
`validate_challenge`, `score_challenge`, and `report_index_table`, plus a
`design_challenge` prompt that primes a host model with the safety boundary.
Every Docker-driving command (`validate-runtime`, `replay`, `validate-siblings
--runtime`) stays CLI-only, so connecting a model host to the server never hands
it container builds or host execution. The tool bodies are plain functions,
unit-tested without the optional `[mcp]` dependency; `build_server` wires them
into a FastMCP instance lazily. `build_spec` merges host-supplied metadata with
the fixed safety knobs and validates before returning, mirroring the LLM
backends' boundary.

Every spec is checked by `validate_spec` (title, family, difficulty, objective
count, and that checkpoint count meets `ai_resistance.min_solver_steps`) before
it can be rendered. `ctfgen spec` writes a spec as JSON; `ctfgen create
--from-spec` loads, re-validates, and renders it — the spec's own seed fully
determines the instance.

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
tests/
  healthcheck.py
  validate_solver.py
  validate_variant.py
```

## Challenge Generation Pipeline

Target pipeline:

```text
structured spec
  -> artifact rendering
  -> static validation
  -> container build                  implemented for local Docker
  -> isolated launch                  implemented for local Docker
  -> health check                     implemented
  -> private solver replay            implemented
  -> sibling variant replay           implemented for generated private solvers
  -> AI-resistance scoring            implemented as static artifact analysis
  -> persisted validation reports     implemented as JSON report artifacts
  -> AI-agent evaluation
  -> human review
  -> publish
```

## AI-Resistance Scoring

`ctfgen score` reads a generated challenge folder and rates it 0-100 across five
weighted dimensions, then reports a band (`strong`/`good`/`moderate`/`weak`):

- `variant_uniqueness` (0.25): how many dynamic-variation dimensions are enabled
  and how many per-instance route/token values appear in `variant.json`.
- `statefulness` (0.20): presence of a background worker, a queue/state backend,
  and a solver that drives asynchronous job state.
- `solver_depth` (0.20): declared checkpoints and distinct HTTP interactions in
  the private solver, relative to `ai_resistance.min_solver_steps`.
- `live_interaction` (0.15): whether the solver discovers routes at runtime and
  polls a live endpoint rather than replaying hardcoded values.
- `scanner_resistance` (0.20): derived from `generic_scanner_usefulness` and
  `decoy_density`.

Scores are computed from the actual artifacts, not just the spec's declared
values, so a challenge that claims live interaction but ships a hardcoded solver
is flagged and scored down. `--min-score` turns the score into a CI gate.

## Persisted Validation Reports

`validate`, `validate-runtime`, `validate-siblings`, and `score` accept
`--report-dir <dir>` to persist their result as a JSON artifact. The writer
lives in `report_writer.py`; the pure validator/score functions are unchanged
and serialization plus I/O happen only at the CLI layer.

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

## AI-Resistance Model

The generator should prefer challenges that are:

- Novel per generated instance
- Stateful
- Multi-step
- Environment-dependent
- Driven by realistic workflows
- Resistant to direct flag or writeup sharing
- Fair to humans through discoverable clues

The first challenge family uses an API and worker authorization mismatch. A generic scanner is insufficient; the solver has to inspect live routes, read operational notices, understand the queue workflow, and exploit a legacy trust boundary.

Sibling validation generates two related challenges from the same family and verifies that route names, support endpoints, tenant fields, tenants, and invoice IDs differ. With `--runtime`, each sibling is built, launched, solved, and cleaned up sequentially.

## Runtime Safety Defaults

Generated Docker Compose environments should default to:

- No host networking
- No Docker socket mounts
- Dropped Linux capabilities
- `no-new-privileges`
- Memory and process limits
- Internal service networks where possible
- Explicit published ports only for learner-facing services

## Future Services

Long-term platform components:

- Frontend: Next.js or another React-based admin and learner UI
- API: FastAPI service for users, challenges, sessions, and submissions
- Queue: Redis plus worker processes
- Database: PostgreSQL
- Build/runtime: Docker BuildKit and Docker Compose first, Kubernetes later
- AI orchestration: structured outputs, role-specific generation, repair loop
- Validation: health checks, private solver, sibling replay, AI-agent bench
