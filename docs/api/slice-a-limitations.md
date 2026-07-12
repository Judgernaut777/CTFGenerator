# M9 slice-a API — known limitations (DEFERRED-TO-M10)

The slice-a control-plane API (`/api/v1`) ships the resource CRUD, the
`ctfgen.error` envelope, cursor pagination, ETag optimistic concurrency,
principal-scoped idempotency, rate limiting, and an audit hook. The following are
**intentionally deferred** and recorded here so they are not silent gaps. None of
them is closed by weakening a design — each is an additive M10 wiring change.

- **Tenancy / resource-ownership authorization (IDOR-class) — RESOLVED (M10b).**
  Competition-tier permissions are now authorized against the TARGET competition
  via the caller's per-competition membership, not the flat role union: an
  `organizer` of competition A is `403` on `competition:write` (and `team:write`,
  `publication:write`, `submission:read`, `scoreboard`, `instance:operate`)
  against competition B. See the *M10 slice b* section below; the check lives in
  `deps.require_competition_permission` / `deps.assert_competition_permission`.

- **Audit of DENIED / errored privileged attempts — RESOLVED (M10b).** A thin
  seam in the exception handlers (`errors._emit_denied_audit`) now records an
  `AuditSink` event with `outcome="denied"` on every `AuthorizationError` (403)
  and `AuthenticationError` (401) — `actor` is the resolved principal subject
  (else `anonymous`), `action` the HTTP method, `target` the request PATH. It
  never records the query string, request body, or token. See *M10 slice b*.

- **ETag is a content validator, not a row version — intentional for slice-a.**
  The catalog tables carry no monotonic `version` / `updated_at` column, so the
  ETag is a stable content hash (`concurrency.compute_etag`). The guarded update
  reads the current aggregate `SELECT ... FOR UPDATE`, so a stale `If-Match`
  reliably yields `412` under READ COMMITTED. A later slice can introduce a row
  `version` column and swap the validator's source **without any wire-contract
  change** (the client still sends/receives opaque `ETag` / `If-Match`).

## M9 slice-b (contestant loop) — residual gaps

Slice-b adds the contestant competition-loop surface (users, submissions,
scoreboard) on the same foundation. Its authorization is still coarse; the
following are recorded so they are not silent gaps, and each closes with M10 auth
wiring, not by weakening a design.

- **Submission tenancy is now per-competition — RESOLVED (M10b).**
  `submission_team_scope(principal, competition_id)` derives the caller's team
  from its membership IN THAT COMPETITION (`memberships[competition_id]`), not a
  flat `Principal.team`. A `player`/`captain` is confined to its team in that
  competition; an organizer-of-this-competition / admin / staff is unrestricted
  within it; a team-scoped caller not placed on a team there is **denied
  entirely** (fail closed: 403 submit, 403 list, 404 read-by-id). The same-named
  team leak is closed: a player of team Red in competition X has NO standing in
  competition Y (a same-named Y team is unreachable — `403` cross-competition,
  before the per-team check). Cross-team WITHIN a competition still returns `404`
  on read-by-id (never confirm existence to a same-competition non-owner).

- **User registration `role` is validated, not persisted — by design this slice.**
  `POST /users` validates the requested `role` against `VALID_ROLES` (422 on an
  unknown role) and records it in the audit trail, but the global user profile
  stores only `email` + `display_name`. Role/team placement is competition-scoped
  (a `Membership`) and is assigned through the membership surface (M9c/M11), not
  the global profile — so the create/get response never claims to have stored a
  role. No credential is modelled (authN is M10).

- **Scoreboard reads are projection-only and never fold on GET — intentional.**
  `GET …/scoreboard` serves the cached projection as-is; it never triggers a
  projection run, so a just-recorded solve appears only after the `ScoreProjector`
  has folded its score event. An unstarted/unknown competition returns an empty
  standings list rather than 404 (the read leaks nothing). `…/scoreboard/lag`
  reports the *shared* projection outbox lag (global, not per-competition) and is
  restricted to operators/organizers (`scoreboard:lag`).

- **Submitter attribution is not linked — deferred.** A recorded submission's
  `submitter_email` is left unset by the API this slice (the ledger supports it,
  but linking the authenticated principal to a `User`/`Membership` row is the M10
  identity join); submissions are attributed to the team, not yet the member.

## M9 slice-c (organizer / ops surface) — residual gaps

Slice-c adds the operator surface (instances, builds, publications, jobs, system
probes) on the same foundation. The following are recorded so they are not silent
gaps.

- **Persistent audit-event READ API — DEFERRED-TO-M16.** There is intentionally
  no `GET /api/v1/audit-events` (or similar) in this slice. The `AuditSink` today
  only *logs* audit records (`LoggingAuditSink`); there is **no `AuditEvent`
  table or repository** in the schema. Exposing a queryable audit trail requires
  a new persistent store (table + migration + repository + projection) and is a
  first-class deliverable of **M16 (observability + incident operations)**, not a
  quiet addition here. Building it in slice-c would either invent an unplanned
  schema or serve an in-memory log that vanishes on restart — both worse than the
  explicit deferral. Mutating/ops actions in this slice ARE audited via
  `record_audit` (never carrying a payload/secret); only the *read* surface is
  deferred.

- **Instance operator view exposes public facts only — by design (secret
  boundary).** The instance list/detail DTOs expose the lifecycle `state` /
  `desired_state`, competition/team/challenge refs, the assigned-worker *name*,
  PUBLIC (non-internal) endpoint addresses, the latest health verdict, and
  timestamps. Instance credentials (`secret_ref`), runtime-resource handles
  (`external_ref`), worker credentials, internal endpoint tokens, and the
  `instance_seed` are **never read on this path** and never appear in a response
  — a positive-control test plants each and asserts its absence.

- **Job ops surface redacts payloads — by design (secret boundary).** The job
  DTOs expose only job type, lifecycle state, attempt accounting, timestamps,
  audit linkage, and the structured `error_class` summary. The raw `payload` /
  `result_json` / `error_detail` / refs are **never mapped**, so a flag/seed that
  violated the queue's secret-free convention still cannot leak through the API.

- **Job ops authorization is admin / support only — intentional.** `job:read` /
  `job:operate` are granted to `admin` and the `support` (ops-staff) role only;
  `organizer` is deliberately excluded from the queue-control surface. Instance
  operation, build triggering, and publications are the organizer surface.

- **The control plane never launches / builds — architectural (ADR-001).** Every
  slice-c mutation records DESIRED state or ENQUEUES a durable job a worker claims
  with scoped credentials; no API handler imports Docker/subprocess or executes
  challenge/generator code. The instance launch endpoint maps a DTO to
  `InstanceLifecycleService.request_instance` (reserve + place + enqueue launch);
  the build trigger enqueues a `build_challenge` job.

- **Instance launch scheduling inputs are explicit in the request — this slice.**
  `POST /instances` accepts the architecture, required capabilities, TTL, and
  platform-capacity units to reserve as request fields (defaulted), so the thin
  handler performs only DTO→domain mapping and invents no scheduling policy. A
  later milestone can derive these from challenge/competition policy without a
  wire-contract change (the fields stay optional).

- **List endpoints materialize the full result set in memory — future
  optimization.** All list endpoints (catalog, submissions, scoreboard,
  instances) currently materialize the full ordered result set in memory and
  paginate over it with the opaque cursor; keyset / DB-side pagination is a future
  optimization that will **not** change the opaque-cursor wire contract. Instance
  lists no longer truncate: an earlier 500-row ceiling made instances beyond the
  500 oldest unreachable (`next_cursor` went null while more rows existed); that
  cap is removed, so the cursor now walks every instance.

## M10 slice a (authentication) — landed, and what remains

Slice a of the auth milestone (ADR-007) replaces the M9 `StubAuthenticator` seam
with **real local-password authentication + opaque server-side sessions**. What
this closed and what it explicitly did **not**:

- **The authenticator is real — DONE (M10a).** `DbAuthenticator` (the module-level
  production default) resolves a Bearer *session* token to a `Principal` from
  real data: it hashes the token, looks up a live (not expired, not revoked)
  `sessions` row, and builds the flat-permission principal from the user's system
  roles (`user_system_roles`) + competition memberships. `StubAuthenticator`
  survives only behind the explicit `CTFGEN_API_INSECURE_STUB_AUTH=1` dev flag.
  `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/me` ship.

- **Per-competition authorization — RESOLVED (M10b).** The `Principal`'s
  `system_roles` + `memberships` (`competition_id → (role, team_name)`) are now
  the inputs a COMPETITION-tier authorization decision is resolved over. The flat
  `require_permission` still gates SYSTEM (`user:*` / `job:*`) and AUTHORING
  (`challenge:*` / `build:*`) permissions (deliberately unchanged); COMPETITION
  permissions go through `require_competition_permission`, which consults the
  caller's effective role IN the target competition (its membership there ∪ its
  system roles) — so an `organizer` of A can no longer exercise `competition:write`
  against B. No wire change.

- **Submission tenancy is per-competition — RESOLVED (M10b).** See the slice-b
  residual-gaps section above; `submission_team_scope` now derives the team from
  the membership in the target competition, not `Principal.team`.

- **Federated identity (OIDC/SSO) — DEFERRED to M10c.** Only local password
  credentials exist this slice. SAML is a permanent non-goal (REQ-PLAT-012); OIDC
  is a later slice. The `Authenticator` protocol is the seam it will plug into.

- **Password policy is a length floor only — future hardening.** `AuthService`
  enforces a minimum length; composition rules, breach-list checks, lockout /
  throttling beyond the shared rate-limit middleware, and password-reset flows are
  out of scope for slice a.

## M10 slice b (per-competition tenancy / authorization) — landed, and what remains

Slice b closes the two IDOR-class deferrals above by consuming
`Principal.memberships`. Authorization is now classified into three tiers
(`deps.PERMISSION_SCOPE`, kept total + fail-closed at import):

- **SYSTEM** (`user:*`, `job:*`) — deployment-global; a system role
  (`admin`/`support`). Enforced by the flat `require_permission` (unchanged).
- **AUTHORING** (`challenge:*`, `build:*`) — platform-global challenge authoring,
  independent of any competition. Also enforced by the flat `require_permission`
  (unchanged): an author/organizer authors challenges without a competition
  context.
- **COMPETITION** (`competition:*`, `team:*`, `submission:*`, `scoreboard:*`,
  `publication:*`, `instance:*`) — scoped to the TARGET competition via
  `require_competition_permission` / `assert_competition_permission`, which
  resolve the caller's effective role IN that competition (its membership there ∪
  its system roles). A system role is authorized in every competition; everyone
  else only where it holds a membership.

Design choices worth recording:

- **Create / list of a competition stay flat — by design.** `POST /competitions`
  and `GET /competitions` carry no `{competition_id}` path param (the competition
  does not exist yet / the list spans all), so they remain on the flat
  `require_permission(competition:*)`: creating a NEW competition cannot be scoped
  to a pre-existing membership. Membership assignment (who becomes the organizer of
  a freshly created competition) is the membership surface (M9c/M11).

- **Body/query-scoped routes authorize in the handler.** Where the target
  competition is in the body (`POST /teams`, `POST /instances`) or a query param
  (`GET /teams?competition_id=…`), the thin handler calls the shared
  `assert_competition_permission` on that competition id. Where it is a property of
  a resource addressed by its own id (`GET /submissions/{id}`, the instance-by-id
  actions), the handler loads the resource, resolves its `competition_id`, and
  authorizes BEFORE returning/mutating.

- **Cross-competition operator LIST is filtered, not blanket-allowed — SAFE
  choice.** `GET /instances` (the only cross-competition list) filters its result
  to `deps.authorized_competitions(...)`: a system role sees every instance; anyone
  else sees only the competitions where a membership grants `instance:read`, so no
  other competition's rows leak. A caller with the permission NOWHERE gets `403`
  (not an empty `200`).

- **Denied/errored attempts are audited.** `errors._emit_denied_audit` records one
  `outcome="denied"` `AuditSink` event per 401/403, carrying only
  actor/action(method)/target(path) — never a secret. The persistent audit-event
  READ API remains DEFERRED-TO-M16 (see slice-c above); slice b only emits.

- **Federated identity (OIDC/SSO) — RESOLVED (M10c).** See the slice-c section
  below.

## M10 slice c (OIDC federated login) — landed, and the one credential-blocked path

Slice c adds **OpenID Connect authorization-code + PKCE login** as an alternative
authentication method (ADR-008). It plugs into the M10a session infra: a
successful federated login issues a **normal local session** — OIDC is a login
method, never a new bearer type, and no ID/access token becomes an API bearer.

- **Implemented + verified against a FAKE IdP double — DONE.** The full flow
  (`application/auth/oidc`: discovery, PKCE, token exchange, JWKS ID-token
  validation) + the `/api/v1/auth/oidc/login` (302) and `/auth/oidc/callback`
  endpoints ship, mounted **only when configured** (else a clean `404`, never a
  500; local auth unaffected). The whole security matrix — PKCE S256, state
  one-time-use + expiry (CSRF), nonce (replay), JWKS asymmetric-only signature
  (`alg:none` + HS\* confusion rejected), `iss`/`aud`/`exp`/`iat`, issuer mix-up,
  `email_verified`, domain allow-list, and never-log (REQ-INV-011) — is driven by
  attack tests against an in-test RSA-keypair IdP double
  (`tests/fixtures/fake_idp.py`). See `docs/security/oidc.md`.

- **LIVE verification against a real IdP is CREDENTIAL-BLOCKED — the one
  unverified path.** No IdP (Google / Okta / Keycloak / Entra) is configured on
  this host, so a real discovery/JWKS/token round trip against a production
  provider has not been exercised. Enabling it is operator configuration only (the
  `CTFGEN_OIDC_*` env in `docs/security/oidc.md`), no code change. This is stated
  plainly rather than claimed complete.

- **Provisioning is least-privilege — by design.** An auto-provisioned federated
  user is created with NO system role and NO membership; roles are granted
  afterwards through the membership surface. `auto_provision` off ⇒ an unknown
  email is rejected (401).

- **One IdP per deployment; SAML is a permanent non-goal (REQ-PLAT-012).**
  Multi-IdP selection is a later concern; SAML is never in scope.
