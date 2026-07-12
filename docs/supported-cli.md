# Supported platform CLI + MCP boundary (M13)

The `ctfgen` command has two halves behind one entry point:

- **The supported platform CLI** — `ctfgen <area> <verb>` — talks to the platform
  **HTTP API** (`/api/v1`) with a session bearer token. This is the supported way
  to operate a running deployment from a terminal or CI.
- **The legacy generator commands** — `ctfgen create|spec|validate|...` — the
  standalone challenge generator/validator. The dispatcher delegates any
  non-platform first token to them **unchanged** (see
  [docs/current-cli.md](current-cli.md)).

The dispatcher routes by the first token only: a known platform *area* goes to the
HTTP CLI, everything else to the legacy generator. The platform side is imported
lazily, so an install **without** the `[cli]` extra still runs every generator
command; a platform command without the extra prints a clean
`pip install 'ctf-generator[cli]'` hint (never a traceback).

## Why HTTP, not the database

The API is the supported boundary: it enforces authentication, per-competition
authorization, audit, rate limiting, idempotency, and pagination. A CLI talking
straight to PostgreSQL would bypass all of that and require database credentials
on operator machines. So the platform CLI is an HTTP client with a scoped session
token — least privilege, and identical to how the web UI and API consumers reach
the platform.

The one exception is **bootstrap**: `ctfgen-admin bootstrap-admin` seeds the first
admin credential directly against the database (there is no API session before the
first admin exists), exactly like `createsuperuser`. It is a separate console
script and needs the `[db]` extra + `CTFGEN_DATABASE_URL`.

## Install

```
pip install 'ctf-generator[cli]'      # httpx only — the platform CLI
```

`[cli]` deliberately does **not** pull in `fastapi`/`uvicorn` (that is the server
side, `[api]`).

## Auth

```
ctfgen auth login [--email you@org] [--api-url https://ctf.example]
ctfgen auth whoami
ctfgen auth logout
```

- The password comes from `$CTFGEN_PASSWORD` or an interactive prompt — **never**
  a flag (a flag leaks via `ps`/shell history). The password and the token are
  never echoed or logged.
- On success a session `{api_url, token, expires_at, subject}` is written to
  `$CTFGEN_CONFIG` / `$XDG_CONFIG_HOME/ctfgen/credentials.json` /
  `~/.config/ctfgen/credentials.json` with mode **0600** (dir 0700). A
  group/world-readable credentials file is **refused** on load.
- Requests attach `Authorization: Bearer <token>`. On a `401` the client tries
  **one** `/auth/refresh`, persists the rotated token, and retries once; if that
  fails it tells you to `ctfgen login` (exit code 3). Redirects are disabled so
  the bearer never crosses origin.
- CI can supply a bearer out-of-band via **`$CTFGEN_API_TOKEN`** (env only — there
  is no `--token` flag, for the same argv-leak reason). When the stored session is
  in use, an explicit `--api-url` that differs from the session's origin is
  **refused** (the stored token is never sent to another host).

Global per-verb options: `--api-url` (env `CTFGEN_API_URL`, default
`http://127.0.0.1:8000`) and `--json` (raw JSON instead of a table).

## Command areas

Reads render a table (public columns only — never a token, flag, instance seed,
`secret_ref`, `external_ref`, or internal endpoint); `--json` prints the raw API
body. Writes send an `Idempotency-Key` where the route honors it (accept
`--idempotency-key` to pin one; otherwise a fresh key per run). List verbs accept
`--limit` and follow the API cursor.

| Area | Verbs |
|---|---|
| `auth` | `login`, `logout`, `whoami` |
| `competition` | `create`, `list`, `get`, `update` (optimistic-concurrency `If-Match`), `scoreboard` |
| `team` | `create`, `list`, `get` |
| `user` | `create`, `list`, `get` |
| `challenge-def` | `create`, `list`, `get`, `update` |
| `challenge-version` | `create`, `list`, `get`, `publish` |
| `publication` | `attach`, `list`, `detach` |
| `submission` | `submit`, `list`, `get` |
| `instance` | `list`, `get`, `request`, `stop`, `reset`, `delete` |
| `job` | `list` (dead-letter), `get`, `cancel`, `retry` |
| `build` | `trigger`, `list`, `get` |
| `system` | `health` |

Errors surface cleanly: a `403`/`404`/`409`/`422` prints the API error `code` +
`request_id` on stderr (exit 1); an auth failure is exit 3; a transport failure is
a friendly "cannot reach the API"; a missing required argument is an argparse
usage error (exit 2). No command ever prints a Python traceback.

### Known gap (no invented route)

There is currently **no API endpoint to grant or list a competition/team
membership** (a `Membership` is seeded out of band). So there is deliberately no
`team member add` / `member list` command — the CLI does not fake an operation the
platform does not expose. Add the membership grant route in a later milestone to
unlock it.

## MCP security boundary (enforced)

`ctfgen-mcp` runs CTFGenerator **as** an MCP server (stdio) so an MCP host drives
it with the user's own model — no API key. It exposes **only pure** generator/
schema/scoring tools (list families, build/validate a spec, create/validate/score
a challenge bundle in a workspace sandbox, read CVE snapshots, summarize reports).

Two boundaries are enforced by tests (`tests/test_mcp_server.py`):

1. **No effectful tool is exposed.** Docker-driving/challenge-executing commands
   (`validate_runtime`, `replay`, `cross_replay`, `validate_siblings`) are
   CLI-only and never registered as MCP tools.
2. **No effectful or data-plane import** (four complementary checks):
   - a **static AST scan** of `mcp_server.py` (walking into tool bodies, so a lazy
     import inside a tool is caught) forbidding any import of an effectful/standalone
     module (`subprocess`, `scenario_runtime`, `agent_eval`, `dashboard_server`, the
     legacy `competition_service`, and the Docker-driving `runtime_validator`/
     `replay_validator`/`sibling_validator`/`report_writer`/`dashboard_ui`) or the
     platform data plane (`application.*`, `infrastructure.*`, `interfaces.api/web/cli`,
     `workers`, `sqlalchemy`, `fastapi`, `httpx`, `docker`, `psycopg`, `alembic`);
   - a **shell-exec source guard** forbidding `os.system`/`os.popen`/`os.exec*`/
     `os.spawn*`/`os.posix_spawn*` — the exec primitives that reach a shell WITHOUT
     importing `subprocess`/`docker`;
   - a **fresh-interpreter `sys.modules` check** after `import mcp_server`, catching
     *transitive* reach a source scan cannot see;
   - a **call-time probe** that invokes every pure tool (build/validate/create/
     score a bundle in a temp workspace, list CVEs, …) in a fresh interpreter and
     re-checks `sys.modules`, catching a lazy/`importlib` effectful import that only
     fires when a tool is *called*.

So a model driving the MCP server can generate and inspect challenge artifacts in a
sandbox, but can **never** reach a shell, a container build, or the platform
database/services. Operating the platform (competitions, submissions, instances) is
the authenticated CLI/API surface for humans, not an MCP tool.
