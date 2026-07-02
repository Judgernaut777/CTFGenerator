# Architecture

## Principle

AI may propose a challenge, but deterministic code should build, isolate, validate, and score it.

The platform should treat validation as the core product. A generated challenge is not useful until it is buildable, launchable, solvable, reasonably fair, and contained.

## MVP Shape

The repository currently starts with a local generator CLI:

```text
ctfgen create -> challenge folder
ctfgen validate -> static artifact validation
```

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
  -> container build
  -> isolated launch
  -> health check
  -> private solver replay
  -> sibling variant replay
  -> AI-agent evaluation
  -> human review
  -> publish
```

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

