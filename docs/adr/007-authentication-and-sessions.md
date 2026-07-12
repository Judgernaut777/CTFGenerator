# Title: ADR-007 — Local password authentication + server-side sessions

> Use stdlib PBKDF2-HMAC-SHA256 password credentials and opaque, hash-at-rest
> server-side session tokens as the real authentication for the control-plane
> API, replacing the M9 `StubAuthenticator` seam — with authorization staying the
> existing flat role→permission model this slice.

## Status

**Accepted**

## Date

`2026-07-12`

## Context

This decision touches the **Authentication** required axis (ADR-000 §"When an ADR
is REQUIRED"). The M9 API shipped a real permission model (`deps.Permission`,
`ROLE_PERMISSIONS`) behind an `Authenticator` **seam**, but the only
implementation was `StubAuthenticator` — a static `token → Principal` table gated
behind the explicit insecure flag `CTFGEN_API_INSECURE_STUB_AUTH=1`. No request
could be authenticated from real data. M10 slice a closes that.

Grounded current state:

- The identity domain (`domain/identity/models.py`) models `User` (email +
  display name — **no** credential), `Team`, and `Membership` (a per-competition
  `role` in the eight `VALID_ROLES`). Roles are **competition-scoped** via
  `Membership`.
- The execution plane already models **hash-at-rest, scoped, short-lived**
  machine credentials (`WorkerCredential`: sha256-at-rest, partial-unique live
  credential, revoke-only mutation with a plpgsql freeze trigger). That
  discipline is the template for user credentials + sessions.
- Product requirements: REQ-COMP-007 (RBAC over the eight roles), REQ-INV-011
  (never log tokens/secrets), REQ-PLAT-012 (multi-tenant SaaS + SAML are
  **non-goals**).

Constraints / invariants this decision must uphold:

- **Minimal blast radius.** Every existing `require_permission` check and all
  current API tests must keep passing; a real `Principal` must resolve
  permissions through the *unchanged* flat `ROLE_PERMISSIONS`.
- **No new dependency.** Password hashing must be stdlib (consistent with the
  codebase; `Prompt Guard`/heavy libs are explicitly avoided elsewhere).
- **Secrets never logged/returned** (REQ-INV-011): a password, its hash, a salt,
  and the raw session token never appear in logs or responses (except the raw
  token returned exactly once at login/refresh).
- **Two known prototype bugs must not recur:** (a) a login timing side-channel
  that revealed whether an email existed (the KDF was skipped for unknown
  emails); (b) per-request session rotation that self-DoS'd concurrent page
  polls to `/login`.
- Domain stays stdlib-pure (the AST boundary test): hashing/secret generation
  live in application/infrastructure, not the domain.

## Decision

We will add **local password authentication + opaque server-side sessions** and
wire a real `DbAuthenticator` as the production default, keeping authorization as
the existing flat permission model. Per-competition role *scoping* and
cross-resource tenancy remain M10 slice b.

### Role tiers (single deployment; no `org` concept — SaaS is a non-goal)

- **System roles** (deployment-global, on the auth account): `admin`, `support`
  — stored in `user_system_roles`, constrained to `VALID_SYSTEM_ROLES` (⊂
  `VALID_ROLES`).
- **Competition roles** (per-competition, via `Membership`): `organizer`,
  `author`, `judge`, `observer`, `captain`, `player`.

A resolved `Principal`'s flat `roles` = system roles ∪ every competition role the
user holds across all memberships; `permissions` resolves from that flat set via
the **unchanged** `ROLE_PERMISSIONS`, so `require_permission` is byte-for-byte the
same behavior. `Principal` gains optional `system_roles` and a `memberships`
mapping (`competition_id → (role, team_name)`), populated best-effort for M10b to
tighten to per-competition scoping. `principal_for(...)` keeps its existing
signature (new params optional), so every existing caller is unaffected.

### Password storage — pluggable `PasswordHasher`, PBKDF2 default

A narrow `PasswordHasher` seam (`hash` / `verify` / `needs_rehash`). Default:
`Pbkdf2Sha256Hasher` (stdlib `hashlib.pbkdf2_hmac`), **≥600 000** iterations
(OWASP floor) with a per-password 16-byte random salt. The encoded hash is a
portable, self-describing string:

```
pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
```

`verify` reads the algorithm + parameters out of the stored string (constant-time
via `hmac.compare_digest`), so raising the iteration count or dropping in a future
`Argon2Hasher` never invalidates existing credentials; `needs_rehash` lets the
service transparently upgrade a credential on the next successful login. **Login
runs the KDF even for an unknown email** (verify against a dummy hash) so response
timing does not reveal account existence (closes prototype bug (a)).

### Sessions — opaque bearer tokens, hash-at-rest

Tokens are `secrets.token_urlsafe(32)` (256 bits), returned to the client **once**
inside a `repr`-suppressed `IssuedSession`. Only the **sha256 hex** of the token
is stored (`sessions.token_hash`, 64-hex CHECK → a plaintext token can never
satisfy the CHECK and be stored by mistake). A session carries `user_email`,
`issued_at`, `expires_at` (default **12h** TTL), `rotated_from`, `revoked_at`.
Resolution hashes the presented token, looks up the row, and checks liveness
(not expired, not revoked). **Refresh** rotates (issue new, revoke old, link
`rotated_from`); **logout** revokes. Rotation happens **only** on the explicit
`/auth/refresh` call — never per request (closes prototype bug (b)).

### The real authenticator + the seam swap

`DbAuthenticator` (interfaces) delegates to the application `AuthService.resolve`
(hash token → live session → load system roles + memberships → layer-neutral
`ResolvedPrincipal`) and maps it onto the API `Principal` via `principal_for`. Any
failure (missing / invalid / expired / revoked) surfaces as a single generic
`AuthenticationError` → 401, never leaking which check failed, never echoing the
token. It is the production default in the module-level app; `StubAuthenticator`
survives only behind the existing insecure flag for dev/test.

### Persistence (canonical aggregate pattern; migration `0011`)

- `auth_credentials` — one credential per user (`UNIQUE (user_id)`), mutable in
  place (a password change rotates `password_hash`); FK RESTRICT to `users`.
- `sessions` — keyed by `token_hash` (UNIQUE), FK RESTRICT to `users`,
  self-FK `rotated_from`, partial live index. **Near-append-only**: an
  `auth_sessions_freeze()` trigger permits only the `revoked_at` NULL→value
  stamp (`to_jsonb` diff), and DELETE/TRUNCATE hit the shared `reject_mutation()`
  (owned by `0004`, reused by name — the exact worker-credential discipline).
- `user_system_roles` — PK `(user_id, role)`, CHECK `role ∈ {admin, support}`;
  revocable (a plain delete).

### Admin bootstrap (no chicken-and-egg lockout, no default password)

A `ctfgen-admin bootstrap-admin` console entry idempotently ensures the first
admin: it creates the user if absent, sets a password **only if no credential
exists** (never resets one), and grants the `admin` system role. The password
comes from `--password`, then `CTFGEN_BOOTSTRAP_ADMIN_PASSWORD`, then an
interactive `getpass` prompt — **never a hardcoded default**.

## Consequences

### Positive
- Real authentication from real data; the M9 stub seam is genuinely closed.
- Existing authorization is untouched — flat `ROLE_PERMISSIONS` still governs
  every route, so the whole existing API test suite passes unchanged.
- Zero new dependencies; hash parameters and the whole hashing algorithm are
  upgradeable without a data migration.
- Secrets are structurally protected: hash-at-rest, `repr`-suppressed one-time
  token, DB CHECK/trigger backstops, and no secret ever logged.

### Negative
- PBKDF2 is CPU-heavier than a memory-hard KDF (Argon2); mitigated by the
  drop-in hasher seam and `needs_rehash` upgrade path.
- Authorization is still **coarse** this slice: any principal with
  `competition:write` can write **any** competition (IDOR-class). Explicitly
  deferred to M10b.

### Neutral
- `Principal` now carries `system_roles` + `memberships`; future slices consume
  them for per-competition scoping (M10b) without a wire change.
- Session TTL / hasher iterations are configuration, not code.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| JWT / stateless tokens | Can't revoke before expiry without server state anyway; opaque server-side sessions give instant logout/rotation and leak nothing in the token. Revisit only if horizontal scale demands it. |
| Argon2 / bcrypt now | Adds a native dependency, against the stdlib-only constraint; the `PasswordHasher` seam makes Argon2 a later drop-in with no data migration. |
| Reuse `WorkerCredential` for users | Worker creds are *server-generated* 256-bit machine secrets (unsalted sha256 is sufficient); user passwords are low-entropy and human-chosen — they require a salted, high-iteration KDF. Different threat model → separate aggregate. |
| Per-request sliding rotation | The exact prototype self-DoS bug; rotation is confined to explicit `/auth/refresh`. |
| Sliding-window / stateless timing (skip KDF on unknown email) | The exact prototype account-enumeration side channel; login always runs the KDF. |
| OIDC / SSO now | REQ-PLAT-012 excludes SAML; OIDC is deferred to M10c. Local auth is the base every deployment needs first. |
