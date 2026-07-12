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
