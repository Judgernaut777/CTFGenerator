# Configuration reference (`CTFGEN_*` env vars)

The M6+ platform is configured entirely through environment variables — **secrets
are never committed** (no DSN/token/password in `alembic.ini`, a Dockerfile, or a
compose file; rotation = change the env, never a code edit). `deploy/.env.example`
is a copy-paste starting point with placeholders; the real `.env` is gitignored.

Which process needs which:
- **Control plane** (`uvicorn ctf_generator.interfaces.api.app:app`, `[deploy]`
  extra): the API/web/auth vars.
- **Worker gateway** (`uvicorn ctf_generator.interfaces.api.worker_app:worker_app`):
  the same DB/log vars, the worker-facing listener only.
- **Worker** (`ctfgen-worker`, `[worker]` extra, on an isolated host): the
  `CTFGEN_WORKER_*` vars — **no DB DSN, no signing key**, only its scoped token.
- **Admin bootstrap** (`ctfgen-admin bootstrap-admin`, `[db]`): `CTFGEN_DATABASE_URL`
  + `CTFGEN_BOOTSTRAP_ADMIN_PASSWORD`.
- **CLI** (`ctfgen <area> <verb>`, `[cli]`): `CTFGEN_API_URL` / `CTFGEN_API_TOKEN`.

## Control plane (API / web / auth)

| Var | Controls | Default |
|---|---|---|
| `CTFGEN_DATABASE_URL` **(required)** | PostgreSQL DSN, the source of truth. **Secret** — env only. | — (fatal if unset) |
| `CTFGEN_ARTIFACT_ROOT` | Local-FS artifact store root (M14c public bundles). | unset → downloads 404 (not fatal) |
| `CTFGEN_DB_ECHO` | Echo SQL (debug). | off (`=1` on) |
| `CTFGEN_API_RATE_LIMIT` | API rate limiting on/off. | **on** (`=0` off) |
| `CTFGEN_API_TRUSTED_PROXY` | Trust `X-Forwarded-For` for the rate-limit key. **Set `=1` only behind a trusted TLS proxy** (else a client can spoof it). | off |
| `CTFGEN_API_INSECURE_STUB_AUTH` | Dev stub bearer auth. **NEVER in production.** | off |
| `CTFGEN_API_DEV_TOKEN` | Stub admin token (with the above). Dev only. | — |
| `CTFGEN_WEB_ENABLED` | Mount the `/app` organizer web UI. | on (`=0` disables) |
| `CTFGEN_WEB_COOKIE_INSECURE` | Drop `Secure` on the session cookie. **Leave unset in prod** (TLS terminates at the proxy → cookies must be `Secure`). | secure (`=1` insecure) |
| `CTFGEN_WEB_CSRF_SECRET` | CSRF HMAC key. **Secret** — set a stable value in prod (else it's random per process → sessions break across restarts/replicas). | random per process |
| `CTFGEN_LOG_FORMAT` | `json` (structured, default) or `text`. | json |
| `CTFGEN_LOG_LEVEL` | Log level. | INFO |

## OIDC (federated login — all four required to enable; else OIDC is off)

| Var | Controls |
|---|---|
| `CTFGEN_OIDC_ISSUER` / `CTFGEN_OIDC_CLIENT_ID` / `CTFGEN_OIDC_CLIENT_SECRET` / `CTFGEN_OIDC_REDIRECT_URI` | The IdP config. `CLIENT_SECRET` is a **secret** — env only, never logged. |
| `CTFGEN_OIDC_SCOPES` | Space-separated scopes (default `openid email`). |
| `CTFGEN_OIDC_ALLOWED_DOMAINS` | Comma-separated email-domain allow-list. |
| `CTFGEN_OIDC_AUTO_PROVISION` | Auto-create users on first login (default off). |

## Worker (isolated host)

| Var | Controls | Default |
|---|---|---|
| `CTFGEN_WORKER_TRANSPORT` | `http` (networked, default) — anything else exits 2 (the in-process single-host client is programmatic). | http |
| `CTFGEN_WORKER_CONTROL_PLANE_URL` **(required)** | The worker-gateway base URL. | — |
| `CTFGEN_WORKER_TOKEN` **(required)** | The scoped bearer credential (`ctfw1.<id>.<secret>`) — the worker's **only** secret. Env only. | — |
| `CTFGEN_WORKER_NAME` **(required)** | The registered worker name. | — |
| `CTFGEN_WORKER_LEASE_SECONDS` | Job lease duration. | 60 |

## Admin bootstrap / CLI / misc

| Var | Controls |
|---|---|
| `CTFGEN_BOOTSTRAP_ADMIN_PASSWORD` | First-admin seed password for `ctfgen-admin bootstrap-admin`. **Secret.** |
| `CTFGEN_API_URL` / `CTFGEN_API_TOKEN` | CLI client target / bearer (`CTFGEN_API_TOKEN` is a **secret**, env only — no `--token` flag by design). |
| `CTFGEN_CONFIG` / `XDG_CONFIG_HOME` | CLI credentials-file path (0600). |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | LLM spec/eval provider keys (SDK-convention env). **Secrets** — never logged (redaction filter enforces it). |

**Never logged / never committed** (the redaction filter + secret-management policy):
`CTFGEN_DATABASE_URL` (password), `CTFGEN_WEB_CSRF_SECRET`, `CTFGEN_OIDC_CLIENT_SECRET`,
`CTFGEN_WORKER_TOKEN`, `CTFGEN_BOOTSTRAP_ADMIN_PASSWORD`, `CTFGEN_API_TOKEN`, provider
keys, session tokens.
