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

```bash
python3 -m pip install -e .
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

For development without installing the package:

```bash
PYTHONPATH=src python3 -m ctf_generator create --output /tmp/invoice-drift --seed demo-001 --force
PYTHONPATH=src python3 -m ctf_generator validate /tmp/invoice-drift
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run full Docker validation when Docker and image/package downloads are available:

```bash
PYTHONPATH=src python3 -m ctf_generator validate-runtime /tmp/invoice-drift
```

That command runs static validation, `docker compose build`, `docker compose up -d`, the generated health check, the private solver, and cleanup with `docker compose down --volumes --remove-orphans`.

Generate and compare sibling variants:

```bash
PYTHONPATH=src python3 -m ctf_generator validate-siblings --output /tmp/invoice-siblings --seed demo-001 --force
```

Run full Docker validation for each sibling sequentially:

```bash
PYTHONPATH=src python3 -m ctf_generator validate-siblings --output /tmp/invoice-siblings --seed demo-001 --force --runtime
```

Score a generated challenge on AI-resistance dimensions:

```bash
PYTHONPATH=src python3 -m ctf_generator score /tmp/invoice-drift
```

The score cross-checks the challenge spec's AI-resistance claims against what
the generated artifacts actually do (variant uniqueness, statefulness, solver
depth, live interaction, scanner resistance). Use `--json` for a machine-readable
report or `--min-score N` to gate generation in CI:

```bash
PYTHONPATH=src python3 -m ctf_generator score /tmp/invoice-drift --min-score 80
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

## Deploy Key

This machine has a dedicated deploy key for the repository:

- Public key: `/home/mini/.ssh/ctfgenerator_deploy_key.pub`
- Private key: `/home/mini/.ssh/ctfgenerator_deploy_key`
- SSH alias: `github-ctfgenerator`

Remote URL:

```bash
git@github-ctfgenerator:Judgernaut777/CTFGenerator.git
```

## Next Engineering Targets

1. Add an LLM-backed spec generator that emits structured challenge metadata before code.
2. Add AI-agent evaluation profiles that complement the static AI-resistance score.
3. Add a minimal web admin UI for generation, validation logs, and review approval.
4. Add persisted validation reports and challenge version metadata.
5. Add a generic exploit replay interface that tests one solver strategy across hidden siblings.
