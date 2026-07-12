# Secret Management

Status: security workstream deliverable (plan milestone: `SecretReference`).
This document states the rules for handling secrets in CTFGenerator, distinguishes
**current** behavior (grounded in the codebase) from **target** behavior (labeled
*planned*), and defines the never-log list and rotation guidance.

Scope note: this is the productization target. The current repo is a pure-Python
deterministic generator/validator plus a stdlib dashboard; several secret classes
below (worker registration tokens, artifact-store credentials, a durable secret
store) belong to planes that are *planned*, not yet built.

---

## 1. Core rule — no secret values in configuration records

> **Secret VALUES are never stored in ordinary configuration records.**
> Configuration persists a **`SecretReference`** pointer (name / handle / version)
> that is resolved at use time against the environment or a secret store. The
> value itself lives only in process memory for the duration of use.

**Current state:** there is no `SecretReference` type and no secret store. Secrets
are supplied out-of-band — via CLI flags, environment variables, or runtime env
injection — and the code holds them only in memory (e.g. `dashboard_server.py`
uses the `secrets` module for session/token material; `postgres_events.py` reads a
DSN). No secret value is written into `spec.json`, `challenge.yaml`, `variant.json`,
report envelopes, the JSONL event log, or the CVE cache.

**Target (planned):** a `SecretReference` model stored in configuration/domain
records, resolved by an infrastructure secret adapter (env-backed in dev, external
secret store in prod). Domain and application layers see references, never values.

---

## 2. Secret classes

| Secret class | Current handling (grounded) | Target handling (planned) |
|---|---|---|
| **Provider API keys** (Anthropic, OpenAI) | Env-only. The `anthropic`/`openai` SDKs are imported lazily in `spec_generator.py` and `agent_eval.py` and read the key from the environment (SDK convention: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`). Never a CLI flag, never committed, never logged. | `SecretReference` resolved via secret store; per-environment scoping. |
| **Dashboard admin credentials** | Passed as `serve --admin-user` / `--admin-password` (required flags). Verified in-process by `dashboard_server.py` using hand-rolled PBKDF2 session handling. | Reference-based; hashed at rest in the PG control-plane domain model. |
| **Session / signing keys** | Generated in-process via the stdlib `secrets` module (session login, token rotation); never persisted, never logged. `--secure-cookie` adds the `Secure` cookie attribute (meaningful only behind a TLS-terminating proxy — the built-in server is plain HTTP). | Managed signing key via `SecretReference`; rotation without restart. |
| **Public scoreboard token** | `serve --public-token`, or randomly generated and **printed once** to stdout when omitted. Read-only scoreboard access. | Reference-backed, rotatable token record. |
| **Database credentials** | `postgres_events.py` uses a psycopg DSN (lazy import). The DSN carries credentials and is supplied via the environment/connection config, not persisted by the app. | DSN/credentials via `SecretReference`; SQLAlchemy 2.x engine config resolves the reference at startup. |
| **Challenge flag** | Injected into containers at runtime via `${CTFGEN_FLAG:-}` in `docker-compose.yml`. Never written to `public/`; only reachable by exploiting the service. Lives in `private/variant.json` as instance ground truth (operator side only). | Per-instance flag issued by the control plane; injected on the isolated execution worker only. |
| **Worker credentials** (M7) | Implemented: sha256-at-rest scoped bearer credentials (`ctfw1.<credential_id>.<secret>`). The secret is a server-generated 256-bit random value; only its sha256 hex is persisted (`worker_credentials.token_hash`, whose 64-hex CHECK makes storing a plaintext `ctfw1.` token structurally impossible). Default 24h TTL, atomically rotated (revoke-old + insert-new in one transaction; a partial UNIQUE guarantees at most one live credential per worker), centrally revocable. The plaintext exists only in the one-time `IssuedCredential` return value (`secret` field is repr-suppressed). The service never accepts a caller-chosen token value. The bootstrap *enrollment* token authorizing `register_worker` remains env-only and is never persisted. | Per-job scoped artifact handles layered on the same scheme. |
| **Artifact-store credentials** (S3-compatible) | *Not present* — current artifact storage is local-filesystem report/bundle writes only. | *Planned:* S3-compatible credentials via `SecretReference`; published artifacts are immutable + content-addressed. |

Note on the MCP workspace: `CTFGEN_MCP_WORKSPACE` is an env var but it is a
**filesystem sandbox root**, not a secret. Listed here only to disambiguate.

---

## 3. Repo convention — never committed, never logged

- No secret is a committed file. The generator emits `.env.example` (sample env
  such as `CTFGEN_FLAG=...`) for **some** families as a template — it contains no
  real value.
- The `private/` bundle tree (flag, solver, variant ground truth, solution) is the
  operator/grader side and is never served to contestants; it is not a config
  secret store and must not carry provider keys or DB credentials.
- Provider keys are env-only by construction: no code path writes them to disk or
  into any report/spec/YAML/event record.

---

## 4. Never-log list

These values MUST NEVER appear in logs, reports, report envelopes, the event log,
error messages, stack traces, or stdout/stderr diagnostics:

| Never log | Reason |
|---|---|
| Challenge **flags** | Zero public flag leakage is a hard invariant. |
| **Session tokens** and signing keys | Session hijacking. |
| **Public scoreboard token** | Printed once at startup; not re-emitted. |
| **Provider API keys** (Anthropic/OpenAI) | Credential exfiltration. |
| **Database credentials / DSN** | Full data-plane compromise. |
| **Admin passwords** | Account takeover. |
| Worker credential secrets (the `ctfw1.` bearer token / its secret part) | Worker impersonation; only the sha256 hash is ever at rest. |
| Artifact-store credentials *(planned)* | Artifact tampering / exfiltration. |

Structured JSON logging (target baseline) must redact by field name; secret-bearing
fields carry a `SecretReference` in records, so logging a record logs the pointer,
not the value.

---

## 5. Rotation guidance

| Secret | Rotation approach |
|---|---|
| Session / signing keys | *Current:* per-process; regenerated on restart, plus in-process token rotation in `dashboard_server.py`. *Target:* rotate the signing key via secret store without dropping the service. |
| Public scoreboard token | Regenerate by restarting `serve` without `--public-token` (new token printed once), or rotate the reference *(planned)*. |
| Provider API keys | Rotate at the provider, update the environment / secret store; no code or committed file changes needed (env-only). |
| Database credentials | Rotate in the store/DSN source; the app reads at startup. *Target:* rotate the `SecretReference` and reconnect. |
| Admin credentials | *Current:* restart `serve` with new `--admin-user`/`--admin-password`. *Target:* rotate the hashed credential in the domain model. |
| Worker credentials | Short-lived (24h default TTL), scoped; `rotate_credential()` revokes the old and issues the new in one transaction (no zero- or two-valid window); `revoke_worker()` kills the worker and its live credential together. |
| Artifact-store credentials *(planned)* | Rotate in the store; content-addressed immutable artifacts are unaffected by key change. |

General rule: rotating a secret should require changing only the environment or the
secret store — never a code edit and never a committed file.

---

## 6. Current → target summary

| Aspect | Current | Target (planned) |
|---|---|---|
| Secret indirection | Env vars, CLI flags, in-memory `secrets` | `SecretReference` pointers in config/domain records |
| Backing store | None (env / process memory) | Secret-store adapter (env dev, external store prod) |
| Session auth | Hand-rolled PBKDF2 in `dashboard_server.py` | Control-plane authn over PG domain model |
| Transport | Plain HTTP stdlib server (`--secure-cookie` only meaningful behind TLS proxy) | Reverse proxy with TLS terminating in front of ASGI app |
| DB creds | psycopg DSN from env | `SecretReference`-resolved SQLAlchemy engine |
| Provider keys | Env-only, lazy SDK read | Env-only, resolved via reference; unchanged never-commit/never-log rule |
