# CTFGenerator

CTFGenerator is an early MVP for generating, validating, and eventually hosting AI-resistant CTF environments.

The first build target is a local CLI that produces a Dockerized business-logic web challenge family. The generated challenge is intentionally stateful and variant-driven so it is less vulnerable to direct writeup sharing or one-shot AI prompting.

## Current MVP

- Python CLI: `ctfgen`
- Structured challenge metadata: `challenge.yaml`
- One challenge family: `web_business_logic_tenant_export`
- Dockerized API and worker services
- Dynamic per-generation routes, seed data, tenant names, invoice IDs, and flag
- Private solver and solution writeup
- Static validator for generated artifacts

## Quick Start

Install the package (no runtime dependencies; Python 3.11+):

```bash
python3 -m pip install -e .
ctfgen --version
```

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

Generate and compare sibling variants:

```bash
ctfgen validate-siblings --output challenges/invoice-siblings --seed demo-001 --force
```

Run full Docker validation for each sibling sequentially:

```bash
ctfgen validate-siblings --output challenges/invoice-siblings --seed demo-001 --force --runtime
```

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

Persist a validation/score result as a JSON artifact with `--report-dir`
(supported by `validate`, `validate-runtime`, `validate-siblings`, and `score`):

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

Summarize accumulated report artifacts as a table, or a self-contained HTML
dashboard:

```bash
ctfgen report-index /tmp/reports
ctfgen report-index /tmp/reports --html /tmp/reports/index.html
```

Generate a structured challenge spec before rendering any code, then render from
it. The default backend is deterministic and offline:

```bash
ctfgen spec --output specs/invoice-drift.json --seed demo-001 --difficulty hard
ctfgen create --output challenges/invoice-drift --from-spec specs/invoice-drift.json
```

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
server exposes only pure tools — `list_families`, `spec_schema`, `build_spec`,
`validate_spec`, `create_from_spec`, `create_challenge`, `validate_challenge`,
`score_challenge`, `report_index_table` — plus a `design_challenge` prompt.
Docker-driving commands (`validate-runtime`, `replay`, `validate-siblings
--runtime`) are deliberately **not** exposed over MCP, so connecting a model
host never hands it container builds or host execution; run those from the CLI.

## Development

To work on the tool without installing it, run the package directly from the
source tree with `PYTHONPATH=src` (the `ctfgen` invocations above map to
`python3 -m ctf_generator`):

```bash
PYTHONPATH=src python3 -m ctf_generator create --output /tmp/invoice-drift --seed demo-001 --force
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m compileall -q src tests
```

## Product Direction

The long-term platform should generate challenge specs first, then build and validate deterministic artifacts:

1. Generate a structured challenge spec.
2. Render source code, Docker files, public description, hints, private solution, and solver.
3. Build and launch an isolated environment.
4. Run health checks and a private solver.
5. Run AI-agent evaluation against the challenge.
6. Require human review before publishing.

The generator should prioritize:

- Fresh per-user variants
- Stateful live workflows
- Multi-step solve paths
- Realistic decoys
- Hidden sibling validation
- Private solver replay
- AI-resistance scoring

## Next Engineering Targets

1. Add AI-agent evaluation profiles that complement the static AI-resistance score.
2. Grow the `report-index` viewer into an interactive web admin UI for generation and review approval.

Implemented: the structured spec generator with a pluggable backend (`spec` /
`create --from-spec`), the generic exploit-replay interface (`replay` /
`validate-siblings --cross-replay`), challenge version metadata (the `meta`
blocks), and a static report dashboard (`report-index --html`).

## License

CTFGenerator is proprietary, for-profit software — see [LICENSE](LICENSE).
Copyright (c) 2026 Judgernaut777, all rights reserved. Commercial use requires a
paid license from the copyright holder; there is no open-source grant.
