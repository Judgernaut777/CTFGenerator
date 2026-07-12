# M9 slice-a API — known limitations (DEFERRED-TO-M10)

The slice-a control-plane API (`/api/v1`) ships the resource CRUD, the
`ctfgen.error` envelope, cursor pagination, ETag optimistic concurrency,
principal-scoped idempotency, rate limiting, and an audit hook. The following are
**intentionally deferred** and recorded here so they are not silent gaps. None of
them is closed by weakening a design — each is an additive M10 wiring change.

- **Tenancy / resource-ownership authorization (IDOR-class) — deferred to M10.**
  `require_permission` enforces only the coarse role→permission matrix (see
  `deps.ROLE_PERMISSIONS`). Per-org / per-team ownership of a specific resource is
  **not** yet enforced: any principal with `competition:write` can PATCH any
  competition. The `Principal` already carries `org` / `team`; only the
  enforcement wiring (scoping each query/mutation to the caller's tenant) is
  deferred to the M10 auth milestone.

- **Audit of DENIED / errored privileged attempts — deferred to M10.** Only
  successful mutations are audited today (`record_audit(..., outcome="success")`
  on the happy path). The `AuditSink` contract already accepts `"denied"` /
  `"error"` outcomes; emitting an audit event on an authz denial or a failed
  mutation becomes first-class in M10, where authorization denial is a modelled
  event.

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

- **Submission tenancy is team-scope only (name-based) — hardened in M10.**
  `submission_team_scope` confines a `player`/`captain` principal to its own
  `Principal.team` (a team *name*); organizer/admin/staff are unrestricted. A
  team-scoped principal that is not placed on a team is **denied entirely** (fail
  closed): it cannot submit (403), cannot list (403), and cannot read another
  team's submission by id (404) — it is never treated as unrestricted. The
  team name is not yet validated to belong to the competition in the path (the
  `Principal` carries a bare team string, not a `(competition, team)` pair), so a
  player whose `Principal.team` matches a same-named team in a different
  competition could read that competition's team submissions. Full
  `(org, competition, team)` resource-ownership scoping lands in M10; the coarse
  team-name confinement here is what the current `Principal` can express.

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
