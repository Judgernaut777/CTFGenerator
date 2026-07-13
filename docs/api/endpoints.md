# CTFGenerator Control-Plane REST API — index

**Status: IMPLEMENTED.** The `/api/v1` control plane is live and served by the
FastAPI app in `src/ctf_generator/interfaces/api/`. This file is an **index and
how-to**, not a source of truth: it deliberately does not re-transcribe every
path, parameter, or schema, because that copy would drift.

- **The authoritative, always-current contract is the generated OpenAPI 3.1
  document the running server serves at `GET /api/v1/openapi.json`.** It is
  produced from the actual route handlers, so it cannot fall out of sync with
  the code.
- Interactive Swagger UI: `GET /api/v1/docs`. ReDoc: `GET /api/v1/redoc`.
- App identity: title `CTFGenerator Control-Plane API`, version `0.1.0`,
  OpenAPI `3.1.0`.
- Base path: `/api/v1`. Media type: `application/json` (UTF-8).

The historical design draft (`openapi-draft.yaml` in this directory) is
**superseded** — see that file's stub. Do not treat it as current.

## Obtaining the schema

From a running server (adjust host/port to your deployment):

```
curl -s http://localhost:8000/api/v1/openapi.json
```

Without a running server, generate the same document from the app object:

```
PYTHONPATH=src:tests .venv/bin/python3 -c \
  "import json; from ctf_generator.interfaces.api.app import app; \
   print(json.dumps(app.openapi()))"
```

To list just the paths:

```
PYTHONPATH=src:tests .venv/bin/python3 -c \
  "from ctf_generator.interfaces.api.app import app; \
   print('\n'.join(sorted(app.openapi()['paths'])))"
```

Both require the `[api]` extra installed in the environment.

## Resource families

The surface is grouped by router (`src/ctf_generator/interfaces/api/routers/`).
Paths below are the family roots — consult the generated schema for the exact
methods, path parameters, request/response bodies, and status codes of each.

| Family | Root path(s) | Purpose |
|--------|--------------|---------|
| Auth | `/auth/login`, `/auth/logout`, `/auth/refresh`, `/auth/me` | Local password login; session issue, refresh, and revocation; resolve the current principal. |
| Users | `/users`, `/users/{user_id}` | Operator / participant account CRUD. |
| Teams | `/teams`, `/teams/{competition_id}/{name}` | Competing teams, scoped per competition. |
| Competitions | `/competitions`, `/competitions/{competition_id}` | Competition configuration CRUD. |
| Publications | `/competitions/{competition_id}/publications`, `/competitions/{competition_id}/publications/{definition_slug}/{version_no}` | Publish (and inspect) challenge versions into a competition. |
| Artifacts | `/competitions/{competition_id}/challenges/{definition_slug}/{version_no}/artifact` | Fetch the built, published challenge artifact for a competition. |
| Challenge definitions | `/challenge-definitions`, `/challenge-definitions/{slug}`, `/challenge-definitions/{slug}/builds` | Logical challenge catalog and per-definition build history/triggers. |
| Challenge versions | `/challenge-versions`, `/challenge-versions/{definition_slug}/{version_no}`, `/challenge-versions/{definition_slug}/{version_no}/publish`, `/challenge-versions/{slug}/{version_no}/evaluations` | Immutable, deterministically generated version snapshots; publish and evaluation-run entry points. |
| Builds | `/builds/{build_id}` | Build-job status for a challenge version. |
| Evaluations | `/evaluations/{eval_run_id}` | Evaluation-lab run status and results. |
| Instances | `/instances`, `/instances/{instance_id}`, `/instances/{instance_id}/{stop,reset,delete}`, `/competitions/{competition_id}/instances` | Running challenge-instance lifecycle operations (stop / reset / delete) and per-competition listing. |
| Submissions | `/competitions/{competition_id}/submissions`, `/submissions/{submission_id}` | Contestant flag submissions and single-submission read. |
| Scoreboard | `/competitions/{competition_id}/scoreboard`, `/competitions/{competition_id}/scoreboard/lag` | Standings snapshot and projection-lag telemetry. |
| Jobs | `/jobs/{job_id}`, `/jobs/{job_id}/{cancel,retry}`, `/jobs/dead-letter` | PostgreSQL job-queue administration (inspect, cancel, retry, dead-letter). |
| Audit | `/audit` | Read window over the append-only audit-event log. |
| System | `/system/{health,live,ready,version,metrics}` | Liveness / readiness / version / metrics probes. |
| Worker | `/worker/auth`, `/worker/jobs/{claim,{job_id}/{start,heartbeat,complete,fail}}`, `/worker/instances/{instance_id}/...` | Worker-plane gateway: scoped worker authentication, job claim/heartbeat/complete/fail, and instance fact/transition reporting. Disjoint from the human auth plane. |

## Cross-cutting conventions

Shared behavior — the `ctfgen.error` envelope, cursor pagination, `ETag` /
`If-Match` optimistic concurrency, principal-scoped idempotency, rate limiting,
and the `X-Request-Id` correlation header — is expressed directly in the
generated schema (component schemas, parameters, and per-operation responses).
Read it there rather than relying on a prose copy here.

## Known limitations

See [`slice-a-limitations.md`](./slice-a-limitations.md) for items that are
intentionally deferred or resolved in later milestones, recorded so they are not
silent gaps.
