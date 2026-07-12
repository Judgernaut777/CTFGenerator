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
