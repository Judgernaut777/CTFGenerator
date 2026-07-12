# OIDC / OAuth2 federated login (M10c)

CTFGenerator supports **OpenID Connect authorization-code login (with PKCE)** as
an alternative authentication method to local passwords. See ADR-008 for the
decision record.

## Model: federated login → a normal local session

OIDC is a **login method, not a bearer type.** The flow authenticates the user at
an external IdP and then issues an **ordinary M10a local session** (the same
opaque `secrets.token_urlsafe` token, sha256-at-rest, 12h TTL,
`/auth/refresh` rotation, `/auth/logout` revocation). All downstream API auth is
the existing session bearer resolved by `DbAuthenticator`. **No OIDC ID token or
access token ever becomes an API bearer**, and there is no OIDC-specific
principal — a federated user is an ordinary sessioned `Principal` through the same
`ROLE_PERMISSIONS`.

```
GET /api/v1/auth/oidc/login     -> 302 to the IdP authorization endpoint
        (state + nonce + PKCE S256 minted; one-time login transaction persisted)
   ... user authenticates at the IdP ...
GET /api/v1/auth/oidc/callback?code=&state=
        -> consume the transaction (CSRF + one-time-use + expiry)
        -> exchange code at the token endpoint (PKCE verifier + client auth)
        -> validate the ID token (JWKS signature, iss/aud/exp/iat, nonce)
        -> map/provision the local user
        -> issue a LOCAL session; return {token, expires_at}  (== /auth/login)
```

When OIDC is **not** configured, the `/auth/oidc/*` routes are not mounted and the
API returns a clean `404 not_found` envelope (feature-disabled) — never a 500 —
and local password auth is entirely unaffected.

## Security properties (where each is enforced + tested)

| Property | Enforced in | Tested by |
|---|---|---|
| **PKCE S256 mandatory** | `pkce.code_challenge_s256`; `oidc/service.build_authorization_url` sends `code_challenge`+`method=S256`; verifier bound in the transaction and sent at exchange | `test_oidc_unit.PkceHelperTests`; `test_login_redirect_carries_state_nonce_and_pkce`; `test_pkce_verifier_mismatch_rejected` |
| **State one-time-use + expiring (CSRF)** | `OidcLoginTransaction` (state stored as sha256); `SqlAlchemyOidcLoginTransactionRepository.consume` deletes on read + rejects expired | `test_unknown_state_rejected`; `test_expired_state_rejected`; `test_replayed_state_is_one_time_use` |
| **Nonce bound + checked (replay)** | `service._verify_id_token` (nonce == transaction nonce; PyJWT doesn't check nonce) | `test_missing_nonce_rejected`; `test_wrong_nonce_replay_rejected` |
| **ID-token signature via JWKS** | `service._select_signing_key` + `jwt.decode(verify_signature=True)` | `test_tampered_signature_rejected` |
| **Asymmetric algs only (`alg:none` + HS\* confusion rejected)** | `config.ALLOWED_ID_TOKEN_ALGORITHMS` (RS/ES only); config rejects HS\*/none in the allow-list; `jwt.decode(algorithms=...)` | `test_alg_none_token_rejected`; `test_hs256_key_confusion_rejected`; `test_symmetric_alg_in_allowlist_rejected` |
| **`iss` == configured issuer** | `jwt.decode(issuer=...)`; discovery issuer-match | `test_wrong_issuer_rejected`; `test_issuer_mixup_is_rejected` |
| **`aud` == client_id** | `jwt.decode(audience=...)` | `test_wrong_audience_rejected` |
| **`exp` / `iat` (small leeway)** | `jwt.decode(require=[exp,iat,...], leeway=...)` | `test_expired_id_token_rejected` |
| **Issuer mix-up defense** | `discovery.fetch_discovery` (discovered issuer must exactly equal configured) | `test_issuer_mixup_is_rejected` |
| **`email_verified` respected** | `service._verified_email` | `test_email_not_verified_rejected` |
| **Email domain allow-list** | `config.domain_allowed` | `test_disallowed_email_domain_rejected`; `test_oidc_unit` domain tests |
| **`redirect_uri` exact-match** | bound in the transaction; sent at exchange; the IdP exact-matches | fake IdP token endpoint |
| **Never log/return secret/code/id_token** | `service` logs nothing; audit records only issuer + subject; access log records only the PATH | `test_client_secret_code_and_id_token_never_logged` (REQ-INV-011) |

## Verification status — LIVE IdP is credential-blocked

The full adapter + flow is **implemented and verified end-to-end against a fake
IdP double** (`tests/fixtures/fake_idp.py` — an in-test RSA keypair serving
discovery + JWKS + token exchange and minting signed ID tokens), including the
entire security matrix above.

**Live verification against a real IdP (Google / Okta / Keycloak / Entra) is
CREDENTIAL-BLOCKED**: no IdP is configured on this host, so a real
discovery/JWKS/token round trip against a production provider is the **one
unverified live path**. Enabling it is purely operator configuration (below) — no
code change. SAML remains a **permanent non-goal** (REQ-PLAT-012).

## Enabling it (operator configuration)

Set these environment variables for the module-level app; if any of the first
four is absent, OIDC stays disabled:

| Variable | Required | Meaning |
|---|---|---|
| `CTFGEN_OIDC_ISSUER` | yes | IdP issuer URL (e.g. `https://accounts.google.com`) |
| `CTFGEN_OIDC_CLIENT_ID` | yes | This deployment's OAuth client id |
| `CTFGEN_OIDC_CLIENT_SECRET` | yes | Client secret (never logged; `repr`-suppressed) |
| `CTFGEN_OIDC_REDIRECT_URI` | yes | Exact callback URL (`…/api/v1/auth/oidc/callback`) |
| `CTFGEN_OIDC_SCOPES` | no | Space-separated; `openid` + `email` are always included (default `openid email`) |
| `CTFGEN_OIDC_ALLOWED_DOMAINS` | no | Comma-separated email-domain allow-list |
| `CTFGEN_OIDC_AUTO_PROVISION` | no | `1`/`true` to create a local user on first federated login |

Register `CTFGEN_OIDC_REDIRECT_URI` as an authorized redirect URI at the IdP.
Auto-provisioned users land with **no roles** (no system role, no membership) —
an admin/organizer grants roles afterwards (an IdP account is not authorization).
Requires installing the `[oidc]` extra (`pyjwt[crypto]`).
