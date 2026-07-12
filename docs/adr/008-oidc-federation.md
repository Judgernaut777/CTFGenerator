# Title: ADR-008 — OIDC/OAuth2 federated login (issues a local session)

> Add **OpenID Connect authorization-code login** (PKCE, discovery, JWKS ID-token
> verification) as an *alternative authentication method* that, on success, issues
> a **normal M10a local session** — reusing the existing opaque, hash-at-rest
> session model unchanged. OIDC is a login method, **not** a new bearer type; no
> ID/access token from the IdP ever becomes an API bearer. This is an addendum to
> ADR-007. SAML remains a permanent non-goal (REQ-PLAT-012).

## Status

**Accepted** (implementation verified against a fake IdP double; live IdP
verification is credential-blocked — see §"Verification & credential block").

## Date

`2026-07-12`

## Context

ADR-007 shipped local-password auth + opaque server-side sessions behind the
`Authenticator` seam, and explicitly deferred OIDC/SSO to M10c ("Local auth is the
base every deployment needs first"). Many deployments federate identity to a
central IdP (Google Workspace, Okta, Keycloak, Entra ID). We add that **without**
weakening or forking the session model, and without hand-rolling any crypto.

Constraints / invariants this decision must uphold:

- **Reuse the M10a session model.** After a federated login the user holds an
  ordinary local session (opaque `secrets.token_urlsafe` token, sha256-at-rest,
  12h TTL, `/auth/refresh` rotation, `/auth/logout` revocation). All downstream
  API auth is the *existing* session bearer resolved by `DbAuthenticator`. There
  is **no** second bearer type and **no** OIDC-specific principal.
- **No hand-rolled crypto** (ADR-005 dependency discipline): ID-token signature /
  JWKS verification uses the vetted **PyJWT + cryptography** stack (`[oidc]`
  extra), asymmetric algs only. Discovery / token-exchange HTTP reuses `httpx`
  (already in `[api]`).
- **Secrets never logged/returned** (REQ-INV-011): the `client_secret`, the
  authorization `code`, and the raw ID token never appear in logs or responses —
  only the one-time local session token is returned (once), exactly as password
  login.
- **Opt-in / fail-clean.** Absent config ⇒ OIDC is simply not enabled: the
  endpoints are not mounted and return a clean `404 not_found` envelope, never a
  500. Local auth is entirely unaffected.
- **SAML stays a non-goal** (REQ-PLAT-012). Only OIDC/OAuth2 is added.

## Decision

Add an `application/auth/oidc` package (config, discovery, `OidcService`) + an
`interfaces/api/routers/oidc.py` router, wired **conditionally** in `create_app`.

### Federated-login → local-session model

1. `GET /api/v1/auth/oidc/login` builds the IdP authorization URL and **302**
   redirects to it. It mints, per attempt: a **state** (CSRF, 256-bit), a
   **nonce** (replay), and a **PKCE** `code_verifier` + S256 `code_challenge`, and
   persists a short-lived, **one-time-use** login transaction
   (`state_hash → {nonce, code_verifier, redirect_uri, expires_at}`) server-side.
2. The IdP authenticates the user and redirects back to
   `GET /api/v1/auth/oidc/callback?code=&state=`.
3. The callback **consumes** the transaction by `state` (unknown / expired /
   already-consumed ⇒ reject: CSRF + one-time-use), exchanges the `code` at the
   token endpoint with the PKCE `code_verifier` + client auth, and **validates the
   ID token**: signature via JWKS (RS256/ES256 — `alg:none` and HS\* confusion
   rejected), `iss` (== configured issuer), `aud` (== `client_id`), `exp`/`iat`
   (small leeway), and `nonce` (== the transaction's nonce). It requires a
   verified `email` (`email_verified` respected when present), applies the
   optional allowed-domains policy, maps to a local user (provisioning it iff
   `auto_provision`), and issues a **local session** for that email via the new
   no-password `AuthService.issue_federated_session` path. It returns
   `{token, expires_at}` — the **same shape** as `/auth/login`.

### Issuer mix-up defense

Discovery fetches `<issuer>/.well-known/openid-configuration` (cached) and rejects
the document unless its `issuer` **exactly** equals the configured issuer; the
ID token's `iss` is then checked against that same configured issuer. `redirect_uri`
is exact-match and bound into the transaction.

### The no-password session-issuance path

`AuthService.issue_federated_session(email, now)` issues a session for an
**already externally-authenticated** identity by reusing the *same* internal
`_issue_session` (same repository, same hasher policy, same TTL/rotation model).
It does **not** touch passwords and fails loud if the user does not exist
(provisioning is the OIDC service's responsibility, done first). The session model
is **not** forked.

### Persistence (canonical aggregate pattern; migration `0012`)

`oidc_login_transactions` — a transient, pre-auth CSRF/PKCE store keyed by
`state_hash` (sha256 hex of the state; the 64-hex CHECK makes storing a plaintext
state structurally impossible — the exact `sessions.token_hash` discipline). Rows
are **deleted on consume** (one-time-use by construction) and pruned on expiry; it
carries no FK (pre-authentication) and no freeze trigger (DELETE is its normal
operation, unlike the append-only auth aggregates).

### Configuration (module app, from env; absent ⇒ disabled)

`OidcProviderConfig.from_env()` reads `CTFGEN_OIDC_ISSUER`,
`CTFGEN_OIDC_CLIENT_ID`, `CTFGEN_OIDC_CLIENT_SECRET`, `CTFGEN_OIDC_REDIRECT_URI`
(all four required to enable), plus optional `CTFGEN_OIDC_SCOPES` (default
`openid email`), `CTFGEN_OIDC_ALLOWED_DOMAINS`, `CTFGEN_OIDC_AUTO_PROVISION`. The
`client_secret` is `repr`-suppressed and never logged.

## Consequences

### Positive
- Deployments can federate identity to any OIDC IdP with no change to the session,
  authorization, or the rest of the API — federated users are ordinary sessioned
  principals through the existing `ROLE_PERMISSIONS`.
- All the hard security properties (PKCE, state/nonce, JWKS asymmetric-only
  signature, iss/aud/exp, issuer mix-up) are enforced by a vetted library + narrow
  server-side transaction store, and are covered by attack-driving tests.

### Negative
- Adds the `[oidc]` extra (PyJWT + cryptography). Isolated behind the extra; the
  stdlib-only gate is unchanged and OIDC tests skip without it.
- Provisioned federated users land with **no** roles (no system role, no
  membership); an organizer/admin grants roles afterwards. Intentional
  least-privilege (an IdP account is not authorization).

### Neutral
- OIDC is per-deployment configuration, not code. One IdP per deployment this
  slice (multi-IdP is a later concern).

## Verification & credential block

The full adapter + flow is verified end-to-end against a **fake IdP double** (an
in-test RSA keypair serving discovery + JWKS + token-exchange and minting signed
ID tokens with configurable claims), including the whole security matrix
(tampered/`none`/wrong-`aud`/wrong-`iss`/expired/bad-nonce tokens; unknown /
expired / **replayed** state; PKCE verifier mismatch; disallowed domain;
`email_verified=false`; never-log). **Live verification against a real IdP
(Google / Okta / Keycloak / Entra) is credential-blocked** — no IdP is configured
on this host — and is the one unverified live path. See `docs/security/oidc.md`.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| Make the OIDC ID token / access token the API bearer | Couples every request to IdP token lifetime/JWKS, can't revoke instantly, and leaks claims in the bearer. Federated login → local session gives instant logout/rotation and one bearer type. |
| Hand-roll JWT/JWKS verification | Signature/alg-confusion bugs are exactly where auth breaks. Use PyJWT + cryptography (vetted), asymmetric-only. |
| Skip PKCE (confidential client has a secret) | PKCE S256 closes code-interception even for confidential clients and is mandatory in current OAuth guidance; it is cheap and always on. |
| Store the login transaction in the sessions table | The session table is append-only with a freeze trigger and an FK to `users`; a pre-auth CSRF/PKCE record is transient, userless, and delete-on-consume. A narrow dedicated table is the correct, narrowest fit. |
| SAML | Permanent non-goal (REQ-PLAT-012). |
