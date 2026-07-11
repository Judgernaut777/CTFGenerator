# CTFGenerator Control-Plane REST API — Contract (DRAFT)

**Status: DRAFT / NOT YET IMPLEMENTED.** This document specifies the M6/M10
control-plane REST API contract. No routing, handler, or server code exists for
these endpoints yet. Nothing here is wired; the contract is published ahead of
the persistence foundation so that the storage layer, DB schema, and later HTTP
layer share one agreed vocabulary. Field names are aligned with the domain value
types in `src/ctf_generator/domain/challenges/models.py`, and the error/version
envelope reuses the identifiers in `src/ctf_generator/schema.py` — this API MUST
NOT invent a parallel versioning or error scheme.

- **Base path:** `/api/v1`
- **Media type:** `application/json` (UTF-8). All request and response bodies.
- **Scope of this draft:** `competitions`, `teams`, `users`,
  `challenge-definitions`, `challenge-versions`, `submissions`, `scoreboard`,
  `audit-events`. These are exactly the resources the persistence foundation
  needs first. Build/generation orchestration endpoints are deferred.

---

## 1. Shared conventions

These conventions are defined **once** here and apply to every endpoint unless a
resource section states otherwise.

### 1.1 Schema identity and versioning

Every response body — success or error — carries the two-field version stamp
produced by `ctf_generator.schema.stamp()`:

| Field            | Type   | Meaning                                                    |
|------------------|--------|------------------------------------------------------------|
| `schema`         | string | Schema identifier, e.g. `ctfgen.error` (`ERROR_SCHEMA`).   |
| `schema_version` | string | Current SemVer for that schema (`CURRENT_VERSIONS[...]`).  |

Rules (mirroring `schema.py`, do not re-derive):

- Clients apply `check_compatible()` semantics: reject an **unknown major**,
  accept an **equal-or-newer minor** (additive fields ignored if unknown).
- The server stamps every payload with the current version via `stamp()`.
- New API resource bodies that need their own identifier MUST register it in
  `schema.py` (`SPEC_SCHEMA`-style constant + entry in `CURRENT_VERSIONS`)
  rather than hard-coding a string here. This draft references the existing
  `ctfgen.error` identifier and marks per-resource identifiers as **TBD:
  register in `schema.py`** — they are NOT invented in this document.

### 1.2 Error envelope (`ctfgen.error`)

Every non-2xx response returns a single object stamped with `schema` =
`ctfgen.error` (the `ERROR_SCHEMA` constant), `schema_version` from
`CURRENT_VERSIONS[ERROR_SCHEMA]` (currently `"1.0"`). Shape:

```json
{
  "schema": "ctfgen.error",
  "schema_version": "1.0",
  "error": {
    "code": "not_found",
    "message": "competition 'cmp_01H...' does not exist",
    "request_id": "req_01H8XK...",
    "details": [
      { "field": "start_time", "issue": "must be before end_time" }
    ]
  }
}
```

| Field                 | Type              | Notes                                              |
|-----------------------|-------------------|----------------------------------------------------|
| `error.code`          | string (enum)     | Stable machine-readable token (see below).         |
| `error.message`       | string            | Human-readable; not for programmatic branching.    |
| `error.request_id`    | string            | Echo of the request id (see §1.3).                 |
| `error.details`       | array\<object\>   | Optional per-field validation problems.            |
| `error.details[].field` | string          | JSON path of the offending field.                  |
| `error.details[].issue` | string          | What is wrong with it.                             |

Canonical `error.code` values: `invalid_request`, `validation_failed`,
`unauthorized`, `forbidden`, `not_found`, `conflict`,
`precondition_failed`, `idempotency_key_reused`, `rate_limited`,
`unsupported_media_type`, `schema_incompatible`, `internal`.

### 1.3 Request IDs

- Clients MAY send `X-Request-Id`. If absent, the server generates one.
- The server echoes it back in the `X-Request-Id` response header **and** in
  `error.request_id` on failures. It is the correlation key into
  `audit-events`.

### 1.4 Pagination (cursor-based)

List endpoints are cursor-paginated (opaque, forward-only). This matches the
monotonic `seq` cursor already used by `EventStore.since()`.

Query params:

| Param    | Type   | Default | Notes                                             |
|----------|--------|---------|---------------------------------------------------|
| `limit`  | int    | 50      | 1–200. Values above the max are clamped.          |
| `cursor` | string | —       | Opaque token from a prior page's `next_cursor`.   |

List envelope:

```json
{
  "schema": "ctfgen.<resource>-list",
  "schema_version": "1.0",
  "data": [ /* resource objects */ ],
  "page": {
    "limit": 50,
    "next_cursor": "eyJzZXEiOjQyfQ",
    "has_more": true
  }
}
```

- `next_cursor` is `null` and `has_more` is `false` on the final page.
- Cursors are opaque; clients MUST NOT parse or construct them.

### 1.5 Filtering

- Filtering is by explicit, documented query params only (no ad-hoc query DSL).
- Multiple filters combine with AND.
- Repeated params express OR within one field (e.g. `?family=web&family=crypto`).
- Unknown filter params → `400 invalid_request`.

### 1.6 Sorting

- `sort` query param: comma-separated field names; `-` prefix = descending.
  Example: `?sort=-submitted_at,team_id`.
- Only fields documented as sortable per resource are accepted; others →
  `400 invalid_request`.
- Default sort is documented per resource (stable — ties broken by resource id).

### 1.7 Idempotency (`Idempotency-Key` header)

- All non-idempotent creates (`POST`) SHOULD accept an `Idempotency-Key`
  request header (client-generated UUID/ULID).
- First use: the request is processed and its response is stored against the key.
- Replay with the same key **and identical request body**: the stored response
  is returned verbatim (same status, same `request_id` semantics noted in body).
- Replay with the same key but a **different body**: `409 idempotency_key_reused`.
- Keys are scoped per resource collection; retention window is an
  implementation concern (documented at implementation time, not here).

### 1.8 Optimistic concurrency (ETag / version precondition)

Mutable resources are versioned. Each carries an integer `version` field
(monotonic per resource) surfaced two ways:

- Response header `ETag: "<version>"` (weak validator, the integer as a quoted
  string).
- Body field `version`.

Preconditions on mutating requests (`PUT`/`PATCH`/`DELETE`):

- `If-Match: "<version>"` (or the `ETag` value) is **required** on updates to
  versioned resources. Match → apply, bump `version`, return the new `ETag`.
- Stale `If-Match` (resource moved on) → `412 precondition_failed`.
- Missing `If-Match` where required → `428` (Precondition Required) with
  `error.code = precondition_failed`.

### 1.9 Status codes (global)

| Code | When                                                             |
|------|------------------------------------------------------------------|
| 200  | Successful read / update.                                        |
| 201  | Resource created.                                               |
| 202  | Accepted for async processing (reserved; not used in this draft).|
| 204  | Successful delete / no-content.                                 |
| 400  | Malformed request / unknown param (`invalid_request`).          |
| 401  | Missing/invalid credentials (`unauthorized`).                   |
| 403  | Authenticated but not permitted (`forbidden`).                  |
| 404  | Resource not found (`not_found`).                               |
| 409  | State conflict / idempotency-key body mismatch (`conflict`).    |
| 412  | Stale `If-Match` (`precondition_failed`).                       |
| 415  | Non-JSON body (`unsupported_media_type`).                       |
| 422  | Well-formed but semantically invalid (`validation_failed`).     |
| 428  | Required precondition missing (`precondition_failed`).          |
| 429  | Rate limited (`rate_limited`).                                  |
| 500  | Server fault (`internal`).                                      |

### 1.10 Timestamps and identifiers

- All timestamps are ISO-8601 / RFC-3339 UTC strings (matching every
  `.isoformat()` call in `models.py`, e.g. `submitted_at`, `start_time`).
- Resource ids are opaque server-assigned strings. Field names match the domain
  types exactly: `competition_id`, `team_id`, `challenge_id`, `submission_id`.

---

## 2. Resources

> Field names below are taken verbatim from the domain dataclasses so the API
> body and the value type stay one-to-one. Where the domain type has no field
> for an API concern (auth, ownership, timestamps of record creation), the extra
> field is marked **(API-only)**.

### 2.1 `/competitions` — competition configuration

Maps to `CompetitionConfig`.

**Resource shape**

| Field                 | Type              | Source                         |
|-----------------------|-------------------|--------------------------------|
| `competition_id`      | string            | `CompetitionConfig`            |
| `name`                | string            | `CompetitionConfig`            |
| `start_time`          | string (RFC-3339) | `CompetitionConfig`            |
| `end_time`            | string (RFC-3339) | `CompetitionConfig`            |
| `scoring_start_time`  | string \| null    | `CompetitionConfig`            |
| `freeze_time`         | string \| null    | `CompetitionConfig`            |
| `default_scoring`     | object \| null    | `ChallengeScoringConfig` shape |
| `version`             | int               | (API-only) concurrency token   |

| Method | Path                         | Params / Body | Success | Errors |
|--------|------------------------------|---------------|---------|--------|
| GET    | `/competitions`              | query: `limit`, `cursor`, `sort` (default `-start_time`) | 200 list | 400 |
| POST   | `/competitions`              | body: all fields except `competition_id`, `version`; header `Idempotency-Key` | 201 + `ETag` | 400, 409, 415, 422 |
| GET    | `/competitions/{competition_id}` | path | 200 + `ETag` | 404 |
| PATCH  | `/competitions/{competition_id}` | path; header `If-Match`; body: partial | 200 + new `ETag` | 404, 412, 422, 428 |
| DELETE | `/competitions/{competition_id}` | path; header `If-Match` | 204 | 404, 409, 412 |

Validation: `422 validation_failed` if `start_time >= end_time`, or
`freeze_time`/`scoring_start_time` outside `[start_time, end_time]`.

### 2.2 `/teams` — competing teams

No domain dataclass exists; `team_id` is referenced across `Submission`,
`SolveEvent`, `ScoreboardEntry`, and `Event`. Minimal shape defined here.

**Resource shape**

| Field            | Type              | Notes                              |
|------------------|-------------------|------------------------------------|
| `team_id`        | string            | Matches domain `team_id`.          |
| `competition_id` | string            | Owning competition.                |
| `name`           | string            | Display name; unique per comp.     |
| `created_at`     | string (RFC-3339) | (API-only)                         |
| `version`        | int               | (API-only) concurrency token       |

| Method | Path                | Params / Body | Success | Errors |
|--------|---------------------|---------------|---------|--------|
| GET    | `/teams`            | query: `competition_id` (filter), `limit`, `cursor`, `sort` (default `name`) | 200 list | 400 |
| POST   | `/teams`            | body: `competition_id`, `name`; header `Idempotency-Key` | 201 + `ETag` | 400, 409, 422 |
| GET    | `/teams/{team_id}`  | path | 200 + `ETag` | 404 |
| PATCH  | `/teams/{team_id}`  | path; `If-Match`; body: `name` | 200 | 404, 409, 412, 428 |
| DELETE | `/teams/{team_id}`  | path; `If-Match` | 204 | 404, 412 |

`409 conflict` if `name` duplicates an existing team in the same competition.

### 2.3 `/users` — operator / participant accounts

No domain dataclass. Users are people who administer competitions or belong to
teams. Minimal shape.

**Resource shape**

| Field         | Type              | Notes                                        |
|---------------|-------------------|----------------------------------------------|
| `user_id`     | string            | Server-assigned.                             |
| `email`       | string            | Unique.                                      |
| `display_name`| string            |                                              |
| `role`        | string (enum)     | `admin` \| `author` \| `player`.             |
| `team_id`     | string \| null    | For players; matches domain `team_id`.       |
| `created_at`  | string (RFC-3339) | (API-only)                                   |
| `version`     | int               | (API-only) concurrency token                 |

| Method | Path                | Params / Body | Success | Errors |
|--------|---------------------|---------------|---------|--------|
| GET    | `/users`            | query: `role`, `team_id` (filters), `limit`, `cursor`, `sort` (default `email`) | 200 list | 400 |
| POST   | `/users`            | body: `email`, `display_name`, `role`, `team_id?`; `Idempotency-Key` | 201 + `ETag` | 400, 409, 422 |
| GET    | `/users/{user_id}`  | path | 200 + `ETag` | 404 |
| PATCH  | `/users/{user_id}`  | path; `If-Match`; body: partial (`display_name`, `role`, `team_id`) | 200 | 404, 409, 412, 428 |
| DELETE | `/users/{user_id}`  | path; `If-Match` | 204 | 404, 412 |

`409 conflict` on duplicate `email`.

### 2.4 `/challenge-definitions` — logical challenges

A *definition* is the stable logical challenge (its family, category, learning
objectives). Concrete generated content lives in `challenge-versions` (§2.5).
Fields map to the stable parts of `ChallengeSpec`.

**Resource shape**

| Field                 | Type            | Source                     |
|-----------------------|-----------------|----------------------------|
| `challenge_id`        | string          | Matches domain `challenge_id`. |
| `competition_id`      | string \| null  | Null while in a library, set when assigned. |
| `title`               | string          | `ChallengeSpec.title`      |
| `category`            | string          | `ChallengeSpec.category`   |
| `difficulty`          | string          | `ChallengeSpec.difficulty` |
| `family`              | string          | `ChallengeSpec.family` (one of the 8 families) |
| `learning_objectives` | array\<string\> | `ChallengeSpec`            |
| `checkpoints`         | array\<string\> | `ChallengeSpec`            |
| `mode`                | string          | `ChallengeSpec.mode` (`red` default) |
| `current_version_id`  | string \| null  | Latest published challenge-version. |
| `version`             | int             | (API-only) concurrency token |

| Method | Path                                       | Params / Body | Success | Errors |
|--------|--------------------------------------------|---------------|---------|--------|
| GET    | `/challenge-definitions`                   | query: `competition_id`, `family`, `category`, `difficulty` (filters), `limit`, `cursor`, `sort` (default `title`) | 200 list | 400 |
| POST   | `/challenge-definitions`                   | body: title, category, difficulty, family, learning_objectives, checkpoints, mode?, competition_id?; `Idempotency-Key` | 201 + `ETag` | 400, 409, 422 |
| GET    | `/challenge-definitions/{challenge_id}`    | path | 200 + `ETag` | 404 |
| PATCH  | `/challenge-definitions/{challenge_id}`    | path; `If-Match`; body: partial | 200 | 404, 412, 422, 428 |
| DELETE | `/challenge-definitions/{challenge_id}`    | path; `If-Match` | 204 | 404, 409, 412 |

`422 validation_failed` if `family` is not one of the eight known families.
`409 conflict` on delete if published challenge-versions or submissions exist.

### 2.5 `/challenge-versions` — concrete generated instances

A *version* is an immutable, deterministically-generated snapshot of a
definition at a given `seed`. It carries the full serialized `ChallengeSpec`
(via `to_mapping()`), including `ai_resistance`, `dynamic_variation`,
`scenario`, and CVE fields. **Immutable once created** (deterministic
generation guarantee) — hence no PATCH.

**Resource shape**

| Field                 | Type            | Source                              |
|-----------------------|-----------------|-------------------------------------|
| `version_id`          | string          | Server-assigned.                    |
| `challenge_id`        | string          | Parent definition.                  |
| `seed`                | string          | `ChallengeSpec.seed`                |
| `spec`                | object          | Full `ChallengeSpec.to_mapping()` (schema `ctfgen.challenge-spec`, `SPEC_SCHEMA`) |
| `cve_refs`            | array\<string\> | `ChallengeSpec.cve_refs`            |
| `cve_content_hash`    | string \| null  | `ChallengeSpec.cve_content_hash`    |
| `created_at`          | string (RFC-3339) | (API-only)                        |
| `immutable`           | bool            | Always `true`.                      |

Note: `spec` is stamped with `ctfgen.challenge-spec` / its own version — the API
does not re-version challenge content; it embeds the existing stamped artifact.

| Method | Path                                                            | Params / Body | Success | Errors |
|--------|-----------------------------------------------------------------|---------------|---------|--------|
| GET    | `/challenge-versions`                                           | query: `challenge_id` (filter, usually required), `seed` (filter), `limit`, `cursor`, `sort` (default `-created_at`) | 200 list | 400 |
| POST   | `/challenge-versions`                                           | body: `challenge_id`, `seed`; `Idempotency-Key` (re-POST same challenge+seed is idempotent — deterministic output) | 201 | 400, 404, 409, 422 |
| GET    | `/challenge-versions/{version_id}`                              | path | 200 | 404 |
| DELETE | `/challenge-versions/{version_id}`                              | path | 204 | 404, 409 |

No PATCH (immutable). Re-POST of an existing `(challenge_id, seed)` pair returns
the existing version (`200`) rather than duplicating — byte-identical
regeneration is guaranteed by the deterministic generator.

### 2.6 `/submissions` — answer attempts

Maps to `Submission`.

**Resource shape**

| Field           | Type              | Source                    |
|-----------------|-------------------|---------------------------|
| `submission_id` | string            | `Submission`              |
| `team_id`       | string            | `Submission`              |
| `challenge_id`  | string            | `Submission`              |
| `submitted_at`  | string (RFC-3339) | `Submission`              |
| `correct`       | bool              | `Submission` (server-set) |
| `instance_seed` | string \| null    | `Submission`              |

| Method | Path                              | Params / Body | Success | Errors |
|--------|-----------------------------------|---------------|---------|--------|
| GET    | `/submissions`                    | query: `team_id`, `challenge_id`, `correct` (filters), `limit`, `cursor`, `sort` (default `-submitted_at`) | 200 list | 400 |
| POST   | `/submissions`                    | body: `team_id`, `challenge_id`, `answer` (the candidate flag; not stored raw), `instance_seed?`; **`Idempotency-Key` required** | 201 (with `correct` computed) | 400, 404, 409, 422 |
| GET    | `/submissions/{submission_id}`    | path | 200 | 404 |

Submissions are append-only: no PATCH/DELETE. `correct` is computed
server-side; the request carries the raw `answer`, the stored resource does not.
A correct submission causes the server to append a `SolveEvent`-derived
`audit-event` (see §2.8) — via `solve_event_from_submission`. Idempotency-Key
is **required** to make retries safe (duplicate scoring must be impossible).

### 2.7 `/scoreboard` — standings (read-only, derived)

Maps to `ScoreboardSnapshot` / `ScoreboardEntry`. Purely derived from the event
log; not directly writable.

**Snapshot shape**

| Field            | Type              | Source                |
|------------------|-------------------|-----------------------|
| `competition_id` | string            | `ScoreboardSnapshot`  |
| `generated_at`   | string (RFC-3339) | `ScoreboardSnapshot`  |
| `frozen`         | bool              | `ScoreboardSnapshot`  |
| `entries`        | array\<Entry\>    | `ScoreboardSnapshot`  |

**Entry shape** (`ScoreboardEntry`): `team_id`, `score`, `solve_count`,
`last_solve_at` (nullable), `rank`.

| Method | Path                                         | Params / Body | Success | Errors |
|--------|----------------------------------------------|---------------|---------|--------|
| GET    | `/scoreboard`                                | query: `competition_id` (**required**), `at` (RFC-3339, optional point-in-time) | 200 snapshot | 400, 404 |
| GET    | `/scoreboard/challenge-values`               | query: `competition_id` (required), `at?` | 200 list of `ChallengeValueSnapshot` | 400, 404 |

`ChallengeValueSnapshot` entry shape: `challenge_id`, `value`, `solve_count`,
`computed_at`. `entries` are returned pre-sorted by `rank` ascending; the
`sort`/`cursor` conventions do not apply (a scoreboard is a single computed
snapshot, not a paged collection).

### 2.8 `/audit-events` — append-only event log

Maps to `events.Event`. This is the same monotonic-`seq` append-only log backing
`EventStore`; the API is a read window plus a constrained append.

**Resource shape** (`Event`)

| Field          | Type              | Source                                  |
|----------------|-------------------|-----------------------------------------|
| `seq`          | int               | `Event.seq` (monotonic from 1)          |
| `ts`           | string (RFC-3339) | `Event.ts`                              |
| `type`         | string            | `Event.type`                            |
| `team_id`      | string            | `Event.team_id`                         |
| `challenge_id` | string            | `Event.challenge_id`                    |
| `payload`      | object            | `Event.payload`                         |

| Method | Path                         | Params / Body | Success | Errors |
|--------|------------------------------|---------------|---------|--------|
| GET    | `/audit-events`              | query: `since` (int seq; maps to `EventStore.since`), `type`, `team_id`, `challenge_id` (filters), `limit` | 200 list | 400 |
| GET    | `/audit-events/{seq}`        | path (int) | 200 | 404 |
| POST   | `/audit-events`              | body: `type`, `team_id`, `challenge_id`, `payload?`; **`Idempotency-Key` required** | 201 (server assigns `seq`, `ts`) | 400, 422 |

The log is append-only: no PATCH/DELETE, no client-supplied `seq` or `ts`.
Pagination here uses the native `since=<seq>` cursor (an integer) rather than the
opaque token, because `seq` is already a stable monotonic cursor; `next_cursor`
in the list envelope is the last returned `seq` as a string for uniformity.
Most audit events are produced internally (e.g. solve events from
`/submissions`); direct `POST` is reserved for operator/administrative
annotations.

---

## 3. Open questions (to resolve before implementation)

1. **AuthN/AuthZ**: scheme (bearer token / session) and the `role` → operation
   matrix are out of scope for this draft; `401`/`403` are reserved now.
2. **Per-resource list schema identifiers**: `ctfgen.<resource>-list` names are
   placeholders — each must be registered in `schema.py` (`CURRENT_VERSIONS`)
   before use, not minted ad hoc.
3. **`teams`/`users` domain types**: no dataclass exists yet; if these graduate
   to first-class domain value types, this contract's field names are the
   intended target and the dataclasses should match them.
4. **Idempotency-Key retention window** and storage backend: deferred to the
   persistence-foundation implementation.
