# M6 Persistence Design — Core Aggregates

> Design only. No implementation. This document specifies the normalized
> relational schema for the M6 control-plane aggregates and encodes the product
> invariants as concrete DB constraints. It is the schema companion to
> [ADR-002 (PostgreSQL is the durable source of truth)](../adr/002-postgresql-persistence.md)
> and [ADR-006 (persistence schema & immutability)](../adr/006-persistence-schema-and-immutability.md).

## Scope

Nine entities, exactly:

`Competition`, `Team`, `User`, `Membership`, `ChallengeDefinition`,
`ChallengeVersion`, `Submission`, `Solve`, `ScoreEvent`.

Plus two supporting tables named where they are load-bearing for an invariant:
`ChallengeBuild` (content-addressed immutable artifact) and `AuditEvent`
(append-only). Scoreboards are **not** a base table — they are a projection
(see §7).

Target backend: PostgreSQL, schema owned by Alembic (ADR-002). Types below are
PostgreSQL types; `id` columns are `UUID` (application- or `gen_random_uuid()`-
assigned) unless a natural content hash is the key.

Conventions used throughout:

- `created_at timestamptz NOT NULL DEFAULT now()` on every table.
- Soft-archival columns `archived_at timestamptz NULL` (NULL ⇒ live) instead of
  row deletion wherever the row participates in history or scoring (see §6).
- Append-only tables (`ScoreEvent`, `AuditEvent`, `Submission`, `Solve`) carry
  **no** `updated_at` and are protected by immutability triggers (§8).
- `text` (not `varchar(n)`) for free strings; PostgreSQL treats them identically
  and it avoids arbitrary length migrations. Enumerated string domains use
  `text` + `CHECK` rather than native `ENUM` so values can be added by migration
  without a type alteration.

---

## Implementation status

This document began as design-only; aggregates are now landing incrementally in
M6, each following the Competition template (domain aggregate → ORM model →
mapper → repository → Alembic migration → Docker-gated Postgres tests). Status:

| Aggregate(s) | Migration | Status |
|---|---|---|
| `Competition` (§3) | `0002_competitions` | **Implemented** |
| `User`, `Team`, `Membership` (§2) | `0003_identity` | **Implemented** (Epic 1) |
| `ChallengeDefinition`, `ChallengeVersion`, `ChallengeBuild`, `competition_challenges` (§4–5) | `0004_challenges` | **Implemented** (Epic 2) |
| `Submission`, `Solve`, `ScoreEvent` (§6) | `0005_ledger` | **Implemented** (Epic 3) |
| `Job`, `JobTransition` (M7 queue, ADR-003) | `0006_jobs` | **Implemented** (M7) |
| `Worker`, `WorkerCredential` (M7 trust) | `0007_workers` | **Implemented** (M7) |
| `score_projection_outbox`, `scoreboard_projections` (M7, §7's cache realized) | `0008_score_projection` | **Implemented** (M7) |

Decisions made while implementing M7 (queue, worker trust, submission
transaction, gap-safe projection):

- **Deferred issue #1 (seq allocation vs commit order) — RESOLVED by the
  `0008` transactional outbox.** An `AFTER INSERT` trigger on `score_events`
  (`score_events_enqueue_projection`, migration-owned) writes one
  `score_projection_outbox` row *in the same transaction* as every event, so
  the row becomes visible at exactly the instant the event commits — however
  many higher seqs committed first. The projector refolds the full committed
  per-competition event set and deletes outbox rows only in the transaction
  that folded them, so **a committed event can never be skipped, by
  construction**; aborted appends burn a seq but roll back their outbox row
  too, leaving inert gaps. Bare `seq > cursor` consumption and
  xmin-low-water-mark cursors remain **forbidden** (seq order is independent
  of xid order: T1/xid-100 can commit seq 7 while T2/xid-101 still holds
  seq 6; the cursor advances to 7 and 6 is lost on commit). The naive LWM
  `min(visible pending seq) - 1` is additionally *non-monotonic* under that
  exact stall, so lag numbers (`ProjectionLag`) are metrics only, never a
  cursor. `scoreboard_projections` is §7's `scoreboard_cache` realized:
  rebuildable (`ScoreProjector.rebuild()` re-enqueues from the ledger and
  refolds), stamped with `as_of_seq`, written only via a monotonic-guarded
  UPSERT, never a source of truth. The trigger applies to every writer of
  `score_events` automatically — a future writer cannot forget the outbox.
  Since autogenerate cannot see triggers, the integration suite positively
  asserts append→outbox atomicity.
- **Deferred issue #2 (`solve.solved_at == accepted_submission.submitted_at`)
  — RESOLVED by construction in `SubmissionProcessingService`.** The service
  builds the `Solve` from the accepted submission (`solved_at =
  submission.submitted_at`, `submission_id = submission.submission_id`)
  inside the same `Database.session_scope()` transaction that inserted the
  submission and appends the single `solve` ScoreEvent there too — one
  commit, no partial state, stronger than any cross-table CHECK Postgres
  could express.
- **Concurrent submission processing is serialized per competition** by a
  `pg_advisory_xact_lock(hashtextextended(competition_uuid_text, 0))` taken
  as the first write-side statement; the post-lock solve-existence re-check
  is authoritative under READ COMMITTED (asserted by the integration suite),
  and the `uq_solves_*` UNIQUE + `solve_requires_correct_submission` trigger
  remain pure backstops. All ledger writes must go through the application
  service (or take the same lock); the projector shares the same key
  derivation, which only adds harmless serialization.
- **The job queue never uses an allocation-order cursor**: claiming is a
  predicate over `(status='queued', available_at <= now, capabilities)` with
  `FOR UPDATE SKIP LOCKED`, so commit-order gaps cannot skip work. Fencing
  `lease_token` per claim makes duplicate delivery/zombie workers harmless
  (stale tokens are rejected, mutating nothing). `failed` = permanent error;
  `dead_letter` = retryable budget exhausted (operator `retry_dead_letter`
  is the one exit, resetting the budget). The `job_transition_guard` trigger
  mirrors `domain.work.models.LEGAL_JOB_TRANSITIONS` byte-equivalently (an
  integration test asserts DB accept/reject for every (from,to) pair).
- **Worker trust is one 3-state axis + two orthogonal overlays** (drain,
  quarantine); dispatch eligibility is the conjunction. Credentials are
  sha256-at-rest scoped bearer tokens (`ctfw1.` prefix vs 64-hex CHECK makes
  plaintext-at-rest structurally impossible); a partial UNIQUE enforces one
  live credential per worker so rotation is race-proof;
  `worker_credentials_freeze()` (owned by `0007`) permits exactly the
  `revoked_at NULL→value` stamp while `reject_mutation()` (owned by `0004`,
  reused by name) blocks DELETE/TRUNCATE.

Decisions made while implementing §6 (the ledger), consistent with this design:

- **New ledger aggregates bridge the flat scoring domain to the normalized
  schema.** The pre-existing `challenges.models.Submission`/`SolveEvent` use
  opaque `team_id`/`challenge_id` strings with no defined mapping to the identity
  and challenge tables. Epic 3 introduces `domain.ledger` aggregates
  (`LedgerSubmission`, `Solve`, `ScoreEvent`) keyed by full *business* identity
  — competition slug, team name, challenge `(definition_slug, version_no)`, and
  an optional submitter email — which the repositories resolve to surrogate
  uuids (shared `_resolve` helper) and fail loud on any dangling reference.
- **`score_events.seq` is an `Identity(always=True)` PK** — the DB sequence
  supplies the strictly-monotonic ordering the in-process `EventStore` produced
  with a lock; `append` returns the persisted event carrying its assigned `seq`.
  Hardened beyond the original `bigserial`/`GENERATED BY DEFAULT` sketch to
  `GENERATED ALWAYS`, so `seq` is server-assigned and cannot be overridden by a
  client INSERT (it is an authoritative ordinal, never caller-supplied).
  - **Caveat (single-writer ordering).** Identity values are allocated at INSERT
    time, and allocation order is *not* commit order under concurrent writers: a
    later-allocated `seq` can commit before an earlier one, so a projector that
    advances a `since(seq)` cursor could step past a still-uncommitted lower
    `seq` and never re-observe it. The in-process store's `threading.Lock` made
    allocation==commit under its single writer; the DB does not. This is
    acceptable *because M6 processes each submission as one serialized unit of
    work per competition* (the append happens inside the submission transaction),
    which is the only writer of `score_events` — the projector reads committed
    rows in `seq` order with no gaps. If a future milestone introduces concurrent
    ledger writers, the cursor consumer must switch to a gap-tolerant low-water
    mark (or an outbox), not a bare `seq > cursor`.
    **RESOLVED in M7** by the `0008_score_projection` transactional outbox —
    see the M7 decisions block above. Bare `seq > cursor` consumption remains
    forbidden for any component other than the outbox-driven projector.
- **Optional provenance ids are validated non-empty.** `ScoreEvent.submission_id`
  / `solve_id` are either absent (`None`) or a non-empty id — the domain rejects
  `""` at construction, so a malformed provenance link fails as a clean domain
  `ValueError` rather than as a `uuid.UUID("")` crash inside the mapper.
- **Read paths coerce ids at the query boundary.** Repository `get()` methods run
  the caller string through the same `_as_uuid` coercion the write path uses and
  return `None` on a malformed id — a lookup miss is uniform whether the id is
  well-formed-but-absent or syntactically invalid; the persistence layer never
  leaks a driver `DataError` to the caller.
- **At-most-one-solve is a DB guarantee** (`UNIQUE (competition_id, team_id,
  challenge_version_id)`), the submission link is a composite FK on the whole
  identity tuple, and `correct = true` is enforced by the
  `solve_requires_correct_submission` BEFORE INSERT trigger.
- **All three ledger tables are append-only** (BEFORE UPDATE OR DELETE + BEFORE
  TRUNCATE triggers on the shared `reject_mutation` owned by `0004`).
- **`Hint` / `HintUnlock` are deferred** — they are not in this design's scope
  and have no domain representation; out of Epic 3.

Decisions made while implementing §4–5 (Challenge authoring), consistent with
this design except for one deliberate, documented deviation:

- **DEVIATION — version state/timestamp CHECK.** §4 specifies
  `CHECK ((state = 'published') = (published_at IS NOT NULL))`. Implemented
  instead as `CHECK ((state = 'draft') = (published_at IS NULL))`. Rationale: the
  literal spec plus the `freeze_published_version` trigger (§8) make
  `published → archived` *impossible* — archiving would have to null
  `published_at`, but the trigger forbids changing it once published — and it
  would also discard publish provenance. The implemented invariant stamps
  `published_at` when a version leaves `draft` and **retains** it through
  `archived`, so a version carries a publish timestamp iff it is not a draft.
  The domain `ChallengeVersion` enforces the same rule.
- **`spec_sha256` is the authoritative content identity; `spec_json` is a
  queryable `jsonb` copy** that round-trips at the dict level (key order is not
  preserved), never recomputed into a hash.
- **State transitions are explicit repository methods** (`publish`, `archive`),
  not a generic content `update`; the `freeze_published_version` and
  `reject_mutation` triggers are the DB backstops (§8).
- **`reject_mutation()` (generic append-only guard) is created and owned by
  `0004_challenges`** and reused *by name* by the Epic 3 append-only ledger
  triggers — `0005` does **not** re-`CREATE OR REPLACE` it (alembic always runs
  `0004` first, so the function is guaranteed present, and re-defining its body
  in two places would risk a silent divergence). Epic 3 drops only its own
  triggers and its own `solve_requires_correct_submission` function on downgrade,
  leaving the shared guard owned by `0004`.

Decisions made while implementing §2 (Identity), consistent with this design:

- **Domain business keys, not surrogate uuids.** The domain aggregates
  (`ctf_generator.domain.identity`) are keyed by business identity — `User` by
  `email` (the design's case-insensitive login identity), `Team` by
  `(competition_id, name)`, `Membership` by `(user_email, competition_id)`. The
  surrogate `uuid` PKs and the lifecycle columns (`archived_at`, `created_at`)
  live only in the ORM and never surface to the domain; repositories translate
  business keys ↔ surrogate keys and fail loudly (`LookupError`) on a dangling
  reference before any write.
- **Role enum single source of truth.** The eight roles live in
  `domain.identity.models.VALID_ROLES`; the ORM `CHECK` and the migration render
  their SQL list from a sorted copy of that set, so the domain validation and
  the DB constraint cannot silently drift.
- **Cross-competition team integrity is a DB guarantee.** `teams` carries the
  extra `UNIQUE (id, competition_id)` so `memberships (team_id, competition_id)`
  can composite-FK it — a member can never be placed on a team from another
  competition. Because that FK is MATCH SIMPLE (not enforced when `team_id` is
  NULL), `memberships.competition_id` also FKs `competitions` directly so the
  unteamed case stays integrity-checked.
- **No `organizations` table.** Organization is not represented in the domain
  (and is not in the Scope list above); it is intentionally out of Epic 1.

---

## 1. ER diagram (ASCII)

```
                          +------------------+
                          |      User        |
                          |------------------|
                          | id (PK)          |
                          | email  (UQ)      |
                          | display_name     |
                          | archived_at      |
                          +--------+---------+
                                   |
                                   | user_id (FK)
                                   |
                          +--------v---------+        +------------------+
                          |   Membership     |        |    Competition   |
                          |------------------|        |------------------|
                          | id (PK)          |        | id (PK)          |
                          | user_id (FK)     |        | name             |
                          | competition_id(FK)-------->| slug (UQ)        |
                          | team_id (FK) NULL|   +---->| start_time       |
                          | role             |   |    | end_time         |
                          | archived_at      |   |    | scoring_start_at |
                          +--------+---------+   |    | freeze_time      |
                                   |             |    | status           |
                                   | team_id(FK) |    | archived_at      |
                                   |             |    +---------+--------+
                          +--------v---------+   |              |
                          |      Team        |   |              | competition_id (FK)
                          |------------------|   |              |
                          | id (PK)          |   |    +---------v-----------+
                          | competition_id(FK)---+    | CompetitionChallenge |
                          | name             |        | (join, scoring cfg)  |
                          | archived_at      |        |----------------------|
                          | UQ(competition,  |        | id (PK)              |
                          |    name)         |        | competition_id (FK)  |
                          +--------+---------+   +----->| challenge_version_id |
                                   |             |    | initial_value        |
                                   |             |    | minimum_value        |
                                   |             |    | decay_function/decay |
                                   |             |    | UQ(comp, chal_ver)   |
                                   |             |    +----------+-----------+
                                   |             |               |
   +------------------+           |             |               | challenge_version_id (FK)
   | ChallengeDefinition|         |             |               |
   |------------------|           |             |    +----------v-----------+
   | id (PK)          |           |             |    |  ChallengeVersion    |
   | family           |           |             |    |----------------------|
   | slug (UQ)        +-----------------+        |    | id (PK)              |
   | title            |    challenge_def_id (FK) +----+ definition_id (FK)   |
   | archived_at      |                          |    | version_no           |
   +------------------+                          |    | state (draft/pub/    |
                                                 |    |        archived)     |
   +------------------+                          |    | family_version       |
   | ChallengeBuild   |   challenge_version_id   |    | seed                 |
   |------------------|<--(FK, nullable)---------+    | spec_sha256          |
   | build_sha256(PK) |                          |    | spec_json            |
   | challenge_version_id(FK)                     |    | published_at         |
   | family/seed      |                          |    | UQ(def_id,version_no)|
   | spec_sha256      |                          |    +----------+-----------+
   | manifest_json    |                          |               |
   +------------------+                          |               | (scoring/solve target)
                                                 |               |
        +----------------------------------------+---------------+
        |                        |                               |
        | team_id / competition_id / challenge_version_id (FKs)  |
        |                        |                               |
 +------v-----------+   +--------v---------+           +---------v--------+
 |   Submission     |   |      Solve       |           |    ScoreEvent    |
 |------------------|   |------------------|           |------------------|
 | id (PK)          |   | id (PK)          |           | seq (PK, serial) |
 | competition_id FK|   | competition_id FK|           | competition_id FK|
 | team_id (FK)     |   | team_id (FK)     |           | team_id (FK)     |
 | challenge_ver FK |   | challenge_ver FK |           | challenge_ver FK |
 | user_id (FK)     |   | submission_id FK |           | type             |
 | submitted_at     |   | solved_at        |           | ts               |
 | correct (bool)   |   | instance_seed    |           | payload (jsonb)  |
 | instance_seed    |   | UQ(team,         |           | submission_id FK |
 | (append-only)    |   |    challenge_ver,|           | solve_id (FK)    |
 +--------+---------+   |    competition)  |           | (append-only)    |
          |             +--------+---------+           +------------------+
          |                      |
          +---------> submission_id (FK, 1:0..1) <------+
                                                         |
                          +------------------+           |
                          |   AuditEvent     |  (append-only, references any
                          |------------------|   actor/subject by id + type;
                          | id (PK)          |   not FK-constrained to keep
                          | actor_user_id    |   audit rows durable across
                          | action / target |   subject archival)
                          | ts / payload     |
                          +------------------+
```

Cardinality summary:

- `Competition 1—* Team`, `Competition 1—* Membership`, `Competition 1—* CompetitionChallenge`.
- `User 1—* Membership`; a `User` reaches a `Competition`/`Team` **only** through `Membership`.
- `ChallengeDefinition 1—* ChallengeVersion` (the version history).
- `ChallengeVersion 1—* ChallengeBuild` (content-addressed builds of one version).
- `Submission 1—0..1 Solve` (a Solve is caused by exactly one correct Submission; most Submissions have no Solve).
- `ScoreEvent` references the `Submission`/`Solve` that produced it; it is the append-only ledger (§7).

---

## 2. User, Team, Membership

### `users`

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `email` | `text` | login identity |
| `display_name` | `text` | |
| `archived_at` | `timestamptz NULL` | soft archival |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **Unique**: `UNIQUE (lower(email))` via a functional unique index (case-insensitive login). Archived users keep the row; re-registration policy is app-level, not a DB re-use of the address.
- **Indexes**: the unique email index doubles as the lookup index.

No password/credential columns are specified here — authN storage is a separate axis (ADR pending, per 000-template "Authentication" row) and secrets are never stored in loggable columns (ADR-002 invariant).

### `teams`

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `competition_id` | `uuid` | **FK → competitions(id)** |
| `name` | `text` | |
| `archived_at` | `timestamptz NULL` | |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **FK**: `competition_id → competitions(id)` `ON DELETE RESTRICT` (competitions are archived, not deleted — §6). A team belongs to exactly one competition; teams are competition-scoped, matching the domain’s per-competition `team_id`.
- **Unique**: `UNIQUE (competition_id, name)` — team names unique within a competition. (Partial-index variant `WHERE archived_at IS NULL` if archived names may be reused.)
- **Indexes**: `INDEX (competition_id)`.

### `memberships`

Org/competition membership + team placement + role, as one row.

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `user_id` | `uuid` | **FK → users(id)** |
| `competition_id` | `uuid` | **FK → competitions(id)** |
| `team_id` | `uuid NULL` | **FK → teams(id)**; NULL = registered but unteamed / staff |
| `role` | `text` | `CHECK (role IN ('player','captain','author','organizer','admin','observer','judge','support'))` |
| `archived_at` | `timestamptz NULL` | soft removal |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **FKs**: `user_id → users(id)` `ON DELETE RESTRICT`; `competition_id → competitions(id)` `ON DELETE RESTRICT`; `team_id → teams(id)` `ON DELETE RESTRICT`.
- **Unique**: `UNIQUE (user_id, competition_id)` — a user has at most one active membership per competition (role/team are attributes of that one membership; multi-role is out of scope for M6).
- **Cross-table integrity**: `team_id`’s team must belong to `competition_id`. PostgreSQL cannot express this with a plain FK; enforce with a **composite FK**: add `UNIQUE (id, competition_id)` on `teams`, then FK `memberships(team_id, competition_id) → teams(id, competition_id)`. This makes "team belongs to the same competition" a DB guarantee, not app logic.
- **Indexes**: `INDEX (competition_id, team_id)`; `INDEX (user_id)`.

The role enum is a placeholder aligned with the "eight roles" target named in 000-template; the exact set is owned by the Authentication ADR and may be migrated.

---

## 3. Competition

### `competitions`

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `slug` | `text` | human/URL id |
| `name` | `text` | |
| `start_time` | `timestamptz NOT NULL` | |
| `end_time` | `timestamptz NOT NULL` | |
| `scoring_start_at` | `timestamptz NULL` | maps `CompetitionConfig.scoring_start_time` |
| `freeze_time` | `timestamptz NULL` | scoreboard freeze |
| `status` | `text` | `CHECK (status IN ('draft','scheduled','live','frozen','ended','archived'))` |
| `archived_at` | `timestamptz NULL` | |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **Unique**: `UNIQUE (slug)`.
- **CHECK**: `CHECK (end_time > start_time)`; `CHECK (freeze_time IS NULL OR freeze_time BETWEEN start_time AND end_time)`.
- **Indexes**: `INDEX (status)` for the "list live competitions" query.

Maps 1:1 to `domain.CompetitionConfig` (see §9). The per-challenge scoring block (`default_scoring` / `ChallengeScoringConfig`) is normalized out to `competition_challenges` (§5), not embedded.

---

## 4. Challenge authoring: ChallengeDefinition & ChallengeVersion

`ChallengeDefinition` is the stable identity of a challenge across edits.
`ChallengeVersion` is one concrete, individually-scorable revision. Publishing
freezes a version.

### `challenge_definitions`

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `family` | `text` | one of the 8 registered families (`families.family_names()`) |
| `slug` | `text` | stable author-facing id |
| `title` | `text` | current display title (mutable metadata) |
| `archived_at` | `timestamptz NULL` | |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **Unique**: `UNIQUE (slug)`.
- **Indexes**: `INDEX (family)`.

`family` is validated against the process family registry at the application
layer; the DB stores it as `text` (the registry is code, not a table).

### `challenge_versions`

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `definition_id` | `uuid` | **FK → challenge_definitions(id)** |
| `version_no` | `int` | monotonic per definition, from 1 |
| `state` | `text` | `CHECK (state IN ('draft','published','archived'))` |
| `family_version` | `text` | family SDK version at authoring (`Family.version` / `BuildMeta.family_version`) |
| `seed` | `text` | deterministic generation seed (`ChallengeSpec.seed`) |
| `mode` | `text NOT NULL DEFAULT 'red'` | `ChallengeSpec.mode` |
| `spec_sha256` | `text` | content hash of the canonical spec JSON (`BuildMeta.spec_sha256`) |
| `spec_json` | `jsonb` | full `ChallengeSpec.to_mapping()` payload |
| `cve_refs` | `text[] NULL` | `ChallengeSpec.cve_refs` (NULL/empty for non-CVE) |
| `cve_content_hash` | `text NULL` | `ChallengeSpec.cve_content_hash` |
| `spec_version` | `text` | `SPEC_VERSION` stamp carried in the spec meta |
| `published_at` | `timestamptz NULL` | set once, at publish |
| `archived_at` | `timestamptz NULL` | |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **FK**: `definition_id → challenge_definitions(id)` `ON DELETE RESTRICT`.
- **Unique**: `UNIQUE (definition_id, version_no)`; and `UNIQUE (definition_id, spec_sha256)` so re-generating the identical spec does not create a duplicate version row (dedup by content, upholds determinism).
- **CHECK**: originally specified `CHECK ((state = 'published') = (published_at IS NOT NULL))`. **Implemented instead** as `CHECK ((state = 'draft') = (published_at IS NULL))` so `published → archived` is possible and publish provenance is retained — see the deviation note under "Implementation status" above. `published_at` is set once the version leaves `draft` and kept through `archived`.
- **Immutability**: once `state = 'published'`, the content columns (`spec_sha256`, `spec_json`, `seed`, `family_version`, `mode`, `cve_*`, `spec_version`, `version_no`, `definition_id`) are frozen. `draft` rows are freely mutable. Only two forward transitions of `state` are allowed: `draft → published` and `published → archived`. Enforced by a trigger (§8).
- **Indexes**: `INDEX (definition_id, state)`; `INDEX (spec_sha256)`.

### `challenge_builds` (content-addressed, immutable)

Materialized artifact of a published version — the byte-identical bundle
produced by `build.py`. Keyed by its own content hash so identical inputs
(family, seed, family_version, spec) collapse to one row (upholds "identical
(generator version, spec, family version, seed) ⇒ identical artifacts").

| column | type | notes |
|---|---|---|
| `build_sha256` | `text` | **PK** — content address of the built bundle |
| `challenge_version_id` | `uuid` | **FK → challenge_versions(id)** |
| `family` | `text` | `BuildMeta.family` |
| `seed` | `text` | `BuildMeta.seed` |
| `family_version` | `text NULL` | `BuildMeta.family_version` |
| `spec_sha256` | `text` | `BuildMeta.spec_sha256` (must equal the version’s) |
| `generator_version` | `text` | `__version__` at build time |
| `manifest_json` | `jsonb` | file manifest / provenance marker |
| `storage_uri` | `text NULL` | pointer to the bundle in artifact storage (Artifact-storage axis) |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `build_sha256` (content-addressed; no surrogate).
- **FK**: `challenge_version_id → challenge_versions(id)` `ON DELETE RESTRICT`.
- **Unique**: PK already dedups; add `UNIQUE (challenge_version_id, family_version, generator_version, seed)` as a human-legible cross-check that one (version, toolchain, seed) yields one build.
- **Immutability**: the entire row is insert-only — no `UPDATE` permitted (§8). Builds are never edited; a new build is a new hash.
- Row bytes are never deleted while any competition references the version (§6).

---

## 5. Competition ↔ Challenge join + per-challenge scoring config

A challenge version is scored **per competition**; scoring config
(`ChallengeScoringConfig`) lives on the join, not on the version.

### `competition_challenges`

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `competition_id` | `uuid` | **FK → competitions(id)** |
| `challenge_version_id` | `uuid` | **FK → challenge_versions(id)** |
| `initial_value` | `int NOT NULL DEFAULT 500` | `ChallengeScoringConfig.initial_value` |
| `minimum_value` | `int NOT NULL DEFAULT 100` | |
| `decay_function` | `text NOT NULL DEFAULT 'static'` | `CHECK (decay_function IN ('static','linear','logarithmic'))` |
| `decay` | `int NOT NULL DEFAULT 0` | |
| `first_blood_enabled` | `bool NOT NULL DEFAULT true` | `FirstBloodBonusConfig` |
| `first_blood_bonus_points` | `int NOT NULL DEFAULT 0` | |
| `first_blood_bonus_percent` | `double precision NOT NULL DEFAULT 0` | |
| `archived_at` | `timestamptz NULL` | remove challenge from comp without deleting solves |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **FKs**: both `ON DELETE RESTRICT`.
- **Unique**: `UNIQUE (competition_id, challenge_version_id)` — a version appears at most once in a competition.
- **CHECK**: `CHECK (minimum_value <= initial_value)`; `CHECK (initial_value >= 0)`.
- Only **published** versions may be attached — enforced at app level (the DB cannot cheaply join-check version state on insert; a trigger is optional if hard enforcement is wanted).

This is the normalization of `CompetitionConfig.default_scoring` /
`ChallengeScoringConfig`, which the dataclasses inline. See §9 divergence note.

---

## 6. Submission, Solve, ScoreEvent (the competition ledger)

**Submission and Solve are separate tables** — a Submission is every answer
attempt (correct or not); a Solve is the at-most-once accepted result. This
mirrors the domain split `Submission` vs `SolveEvent` and the helper
`solve_event_from_submission`.

### `submissions` (append-only)

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** (domain `submission_id`) |
| `competition_id` | `uuid` | **FK → competitions(id)** |
| `team_id` | `uuid` | **FK → teams(id)** |
| `challenge_version_id` | `uuid` | **FK → challenge_versions(id)** (domain `challenge_id`) |
| `user_id` | `uuid NULL` | **FK → users(id)** — submitting member, if tracked |
| `submitted_at` | `timestamptz NOT NULL` | |
| `correct` | `bool NOT NULL` | |
| `instance_seed` | `text NULL` | per-user/per-instance seed |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **FKs**: all `ON DELETE RESTRICT`.
- **Composite FK**: `(team_id, competition_id) → teams(id, competition_id)` so a submission’s team is guaranteed to be in the submission’s competition.
- **Append-only**: no `UPDATE`/`DELETE` (§8). Correctness is decided at insert; a retraction is a new compensating row/event, never an edit.
- **Indexes**: `INDEX (competition_id, team_id, submitted_at)` (per-team feed); `INDEX (challenge_version_id)`; partial `INDEX (competition_id, challenge_version_id) WHERE correct` for solve derivation.

### `solves` (append-only, at-most-one guarantee)

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `competition_id` | `uuid` | **FK → competitions(id)** |
| `team_id` | `uuid` | **FK → teams(id)** |
| `challenge_version_id` | `uuid` | **FK → challenge_versions(id)** |
| `submission_id` | `uuid` | **FK → submissions(id)** — the accepted attempt |
| `solved_at` | `timestamptz NOT NULL` | |
| `instance_seed` | `text NULL` | |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `id`.
- **FKs**: `competition_id`, `team_id`, `challenge_version_id` `ON DELETE RESTRICT`; `submission_id → submissions(id)` `ON DELETE RESTRICT`.
- **THE core invariant** — *a correct submission creates at most one Solve per (team, challenge, competition)*:
  `UNIQUE (competition_id, team_id, challenge_version_id)`.
  This is the schema encoding of the product rule; a second correct submission by the same team for the same challenge in the same competition cannot insert a second solve.
- **Unique** (integrity of the link): `UNIQUE (submission_id)` — a given submission produces at most one solve.
- **CHECK**: `solved_at` should equal the source submission’s `submitted_at` (domain sets them equal). Enforced app-side (cross-row), not by CHECK. **Not enforced at the M6 persistence layer** — `SqlAlchemySolveRepository.add` does not re-read the submission to assert equality, and there is no trigger. The invariant is the responsibility of the *submission-processing service* (next milestone), which constructs the `Solve` from the accepted submission and therefore sets `solved_at = submission.submitted_at` by construction. Until that service lands, a hand-built `Solve` with a divergent `solved_at` would persist; this is a known, documented gap, not a silent one.
- **Consistency**: `solves.submission_id` must reference a submission with `correct = true` and matching `(competition_id, team_id, challenge_version_id)`. A composite FK `(submission_id, competition_id, team_id, challenge_version_id) → submissions(id, competition_id, team_id, challenge_version_id)` (backed by a `UNIQUE` on those submission columns) makes the tuple match a DB guarantee; the `correct = true` part is a trigger/app check.
- **Append-only**: no `UPDATE`/`DELETE` (§8).
- **Indexes**: the two UNIQUE constraints cover the hot lookups; add `INDEX (competition_id, challenge_version_id, solved_at)` for first-blood / solve-count queries.

### `score_events` (append-only event ledger — source of truth)

The durable, event-sourced ledger. This is the relational form of
`events.Event` and the "ScoreEvent" of the invariant set. Scoreboards are folds
over this table (§7). Preserves the monotonic `seq` contract from `events.py`.

| column | type | notes |
|---|---|---|
| `seq` | `bigint GENERATED ALWAYS AS IDENTITY` | **PK** — DB-assigned monotonic sequence (replaces the in-process `threading.Lock` seq from `events.py`); `ALWAYS` so it cannot be client-overridden. See the single-writer ordering caveat in §1. |
| `competition_id` | `uuid` | **FK → competitions(id)** |
| `team_id` | `uuid` | **FK → teams(id)** |
| `challenge_version_id` | `uuid` | **FK → challenge_versions(id)** (domain `challenge_id`) |
| `type` | `text NOT NULL` | e.g. `submission`, `solve`, `first_blood`, `freeze`, `revalue` |
| `ts` | `text NOT NULL` | ISO-8601 UTC string, byte-compatible with `events.Event.ts` |
| `payload` | `jsonb NOT NULL DEFAULT '{}'` | matches `events.Event.payload` |
| `submission_id` | `uuid NULL` | **FK → submissions(id)** — provenance |
| `solve_id` | `uuid NULL` | **FK → solves(id)** — provenance |
| `created_at` | `timestamptz NOT NULL DEFAULT now()` | |

- **PK**: `seq` (`bigint GENERATED ALWAYS AS IDENTITY`) — a database sequence provides the strictly-monotonic ordering that `InMemoryEventStore`/`JsonlEventStore` produced via a lock. `since(seq)` becomes `WHERE seq > $1 ORDER BY seq`; `latest_seq()` becomes `SELECT COALESCE(MAX(seq),0)`. `ALWAYS` (not `BY DEFAULT`) makes `seq` server-authoritative; see the single-writer ordering caveat in §1 for why `since`-cursor projection is safe only under the serialized M6 write path.
- **FKs**: `competition_id`, `team_id`, `challenge_version_id` `ON DELETE RESTRICT`; `submission_id`, `solve_id` `ON DELETE RESTRICT`.
- **Append-only**: `INSERT` only; no `UPDATE`/`DELETE` (§8). A correction is a new compensating event.
- **Indexes**: PK covers `since`/`latest_seq`; add `INDEX (competition_id, seq)` for per-competition replay and `INDEX (type)` for typed folds.

This table supersedes `postgres_events.py`’s `competition_events` (which is
keyed identically: `seq serial PK, ts, type, team_id, challenge_id, payload
jsonb`). The M6 form adds real FKs (`team_id`, `challenge_version_id`,
`competition_id`) and provenance links, but keeps `postgres_events.py` a valid
narrower adapter behind the same `EventStore` protocol.

---

## 7. Scoreboards are projections, not tables

There is **no authoritative `scoreboards` table.** A scoreboard is the result
of folding `score_events` (and/or `solves`) through the existing pure functions
in `scoreboard.py` (`compute_scoreboard`, `compute_challenge_values`) with a
`scoring_engine.py` strategy. This is unchanged by M6 — only the event *source*
becomes a durable table.

- `domain.ScoreboardEntry` / `ScoreboardSnapshot` / `ChallengeValueSnapshot`
  remain **value objects**, not rows.
- If a cached/materialized scoreboard is ever persisted for performance, it is a
  `scoreboard_cache` table stamped with `as_of_seq` (the max `score_events.seq`
  folded in) and is **rebuildable and discardable** — never a source of truth.
  A frozen scoreboard (`ScoreboardSnapshot.frozen`) may be persisted as such a
  cache row pinned at the competition’s `freeze_time` seq, but it is still a
  projection of the ledger, reproducible by replaying events up to that seq.

Invariant upheld: *scoreboards are reconstructable from ScoreEvents.*

---

## 8. Immutability enforcement: triggers vs app-level

Two immutability regimes, enforced with **defense in depth** (DB is the backstop
so a buggy or malicious app path cannot violate the invariant):

| Target | Rule | Primary enforcement | Backstop |
|---|---|---|---|
| `score_events`, `submissions`, `solves`, `audit_events` | insert-only (no UPDATE/DELETE) | app repository never issues UPDATE/DELETE | **`BEFORE UPDATE OR DELETE` trigger** `RAISE EXCEPTION` |
| `challenge_versions` where `state='published'` | content columns frozen; only `draft→published`, `published→archived` state moves | app publish path | **`BEFORE UPDATE` trigger** rejecting content-column changes and illegal state transitions once published |
| `challenge_builds` | whole row insert-only | app writes builds once | **`BEFORE UPDATE OR DELETE` trigger** |

Why DB triggers (not app-only): the at-most-one-solve and append-only ledger
invariants are correctness- and audit-critical; ADR-002 explicitly moves the
solve uniqueness from an in-process lock to a DB constraint. Triggers are the
matching move for the "no rewriting history" half. App-level checks stay as the
first line (clear errors, no round-trip surprises) but are **not** the guarantee.

Concrete trigger sketch (illustrative, not migration code):

```sql
-- append-only ledger
CREATE FUNCTION reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER score_events_immutable
  BEFORE UPDATE OR DELETE ON score_events
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- published challenge_version content freeze
CREATE FUNCTION freeze_published_version() RETURNS trigger AS $$
BEGIN
  IF OLD.state = 'published' THEN
    IF NEW.spec_sha256 <> OLD.spec_sha256
       OR NEW.spec_json IS DISTINCT FROM OLD.spec_json
       OR NEW.seed <> OLD.seed
       OR NEW.version_no <> OLD.version_no THEN
      RAISE EXCEPTION 'published challenge_version content is immutable';
    END IF;
    IF NEW.state NOT IN ('published','archived') THEN
      RAISE EXCEPTION 'published version may only move to archived';
    END IF;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
```

The `UNIQUE (definition_id, spec_sha256)` and content-addressed
`challenge_builds.build_sha256` PK provide the *content-identity* half of
immutability (identical content can’t fork into two rows); the triggers provide
the *no-mutation* half.

**As implemented (`0004_challenges`), refining the sketch above:**

- The freeze also lists **`published_at`** among the frozen columns — this is the
  load-bearing detail behind the state/timestamp deviation (§4): `published_at`
  is stamped once and never changes, so `published → archived` keeps it.
- The freeze guards **`OLD.state IN ('published','archived')`**, not just
  `'published'` — otherwise an archived row would be fully mutable and could be
  moved back to `draft`/`published`. `'archived'` is enforced **terminal**.
- The insert-only ledgers also get a **`BEFORE TRUNCATE … FOR EACH STATEMENT`**
  trigger, because `FOR EACH ROW` triggers do not fire on `TRUNCATE` (so the
  append-only/insert-only guarantee would otherwise be bypassable).

---

## 9. Deletion & archival strategy

**Destructive `DELETE` is prohibited on any table that carries history, scoring,
or audit meaning.** The default is **soft archival**: set `archived_at = now()`;
`archived_at IS NULL` means live. Rationale: solves, submissions, and score
events form an auditable competition record; deleting a team or challenge would
orphan or silently rewrite that record.

Per-table policy:

| Table | Delete policy |
|---|---|
| `score_events`, `submissions`, `solves`, `audit_events` | **Never deleted, never updated.** Append-only; corrections are compensating rows/events. |
| `challenge_builds` | **Never deleted** while any `challenge_version` referencing it is non-archived. Content-addressed, immutable. |
| `challenge_versions` (published) | **Archived only** (`state='archived'`, `archived_at` set). Content stays for reproducibility of past competitions. |
| `challenge_versions` (draft) | Hard-deletable **only if never published and never attached** to a `competition_challenge` (no dependent rows). This is the one place a true `DELETE` is allowed. |
| `challenge_definitions` | Soft archival (`archived_at`). Kept because versions reference it. |
| `competitions` | Soft archival (`status='archived'`, `archived_at`). Ledger rows reference it. |
| `teams`, `users`, `memberships` | Soft archival (`archived_at`). Referenced by submissions/solves/score events. |
| `competition_challenges` | Soft archival (`archived_at`) — detaches a challenge from a running competition without deleting the solves already recorded against that version. |

All FKs into history tables are `ON DELETE RESTRICT` (never `CASCADE`), so an
accidental delete of a parent cannot silently erase ledger children — the
database refuses it. Read queries filter `WHERE archived_at IS NULL` for "live"
views; audit/history views ignore the filter.

GDPR/erasure (future): satisfied by **pseudonymization** of `users` (null out
`email`/`display_name`, keep the `id` and its FKs) rather than row deletion, so
the competition ledger stays intact and reconstructable. Out of M6 scope; noted
so the schema (nullable PII columns, stable `id`) does not preclude it.

---

## 10. AuditEvent (append-only)

`audit_events` records who did what (publish, archive, role change, score
override, config edit). It is **append-only** exactly like `score_events`, with
the same insert-only trigger (§8).

| column | type | notes |
|---|---|---|
| `id` | `uuid` | **PK** |
| `actor_user_id` | `uuid NULL` | **FK → users(id)** `ON DELETE RESTRICT` (nullable for system actions) |
| `action` | `text NOT NULL` | e.g. `challenge.publish`, `membership.role_change` |
| `target_type` | `text NOT NULL` | e.g. `challenge_version`, `competition` |
| `target_id` | `text NOT NULL` | id of the subject; **not** FK-constrained so audit rows survive subject archival/pseudonymization |
| `ts` | `timestamptz NOT NULL DEFAULT now()` | |
| `payload` | `jsonb NOT NULL DEFAULT '{}'` | before/after or context; **never** flags, session tokens, or provider keys (ADR-002 invariant) |

- **PK**: `id`. **Index**: `INDEX (target_type, target_id, ts)`, `INDEX (actor_user_id, ts)`.
- Deliberately **not** FK-linked on `target_id` (heterogeneous subjects; must outlive them). `actor_user_id` *is* an FK because users are only archived, never deleted.

---

## 11. Reconciliation with the domain dataclasses

`domain/challenges/models.py` are pure value types; the schema is their durable
projection. Where they agree and diverge:

| Domain dataclass | Table | Agreement / divergence |
|---|---|---|
| `Submission(submission_id, team_id, challenge_id, submitted_at, correct, instance_seed)` | `submissions` | **Agree** field-for-field. `submission_id → id`, `challenge_id → challenge_version_id` (the DB is explicit that the referent is a *version*). Schema adds `competition_id` and optional `user_id` the dataclass lacks (the dataclass is competition-agnostic; the row is not). |
| `SolveEvent(team_id, challenge_id, solved_at, submission_id, instance_seed)` | `solves` | **Agree** on all fields. Schema adds surrogate `id`, `competition_id`, and the `UNIQUE(competition,team,challenge)` the dataclass can only imply. `solve_event_from_submission()` is the app-level factory that becomes a `solves` INSERT. |
| `CompetitionConfig(competition_id, name, start_time, end_time, scoring_start_time, freeze_time, default_scoring)` | `competitions` (+ `competition_challenges`) | **Diverge by normalization.** Scalar timing fields map 1:1 (`scoring_start_time → scoring_start_at`). `default_scoring` (an embedded `ChallengeScoringConfig`) is **not** a column — it is normalized into `competition_challenges` rows. Schema adds `slug`, `status`, `archived_at`. |
| `ChallengeScoringConfig(challenge_id, initial_value, minimum_value, decay_function, decay, first_blood_bonus)` | `competition_challenges` | **Diverge:** the dataclass keys by `challenge_id` alone; the table keys by `(competition_id, challenge_version_id)` because scoring is per-competition. `FirstBloodBonusConfig` is **flattened** into three columns rather than a nested object. |
| `FirstBloodBonusConfig(enabled, bonus_points, bonus_percent)` | (flattened into `competition_challenges`) | **Diverge:** no own table; flattened columns `first_blood_enabled/_bonus_points/_bonus_percent`. |
| `ScoreboardEntry`, `ScoreboardSnapshot`, `ChallengeValueSnapshot` | **none** (projection) | **Agree that these are derived.** No base table — computed by `scoreboard.py` folds over `score_events` (§7). `ScoreboardSnapshot.frozen` may be persisted only as a rebuildable cache row. |
| `ChallengeSpec(title, category, difficulty, family, seed, learning_objectives, checkpoints, ai_resistance, dynamic_variation, cve_refs, cve_content_hash, mode, scenario)` | `challenge_versions` (+ `challenge_definitions`) | **Diverge by split.** Stable identity (`family`, title/`slug`) → `challenge_definitions`; the versioned content (`seed`, `mode`, `cve_refs`, `cve_content_hash`, `spec_version`) → `challenge_versions` scalar columns; the **entire** `to_mapping()` blob → `spec_json jsonb` (so nested `ai_resistance`/`dynamic_variation`/`scenario` are preserved without a column explosion). `spec_sha256` is the content hash of that blob. |
| `events.Event(seq, ts, type, team_id, challenge_id, payload)` | `score_events` | **Agree** on `seq/ts/type/payload` (byte-compatible `ts`, monotonic `seq`). **Diverge:** `team_id`/`challenge_id` become real UUID FKs (`team_id`, `challenge_version_id`) + explicit `competition_id`, and gain `submission_id`/`solve_id` provenance links. `postgres_events.py.competition_events` is the narrower, FK-less precursor of this table. |
| `build.BuildMeta(family, seed, spec_sha256, family_version)` | `challenge_builds` | **Agree**; the table adds `build_sha256` (content-address PK), `generator_version`, `manifest_json`, `storage_uri`. |

Fields **not invented**: every column above traces to a domain dataclass field,
`events.Event`, `BuildMeta`, `Family.version`, or `SPEC_VERSION`/`__version__`.
`User`/`Team`/`Membership`/`role` have no domain dataclass today (only `team_id`
strings appear); they are introduced here as the minimal identity model the
product invariants (per-team solves, membership) require, kept deliberately thin
(no credential/PII beyond `email`/`display_name`) and flagged as owned by the
future Authentication ADR.

---

## 12. Mapping onto the event-sourced prototype

- `events.EventStore` protocol (`append`/`since`/`all`/`latest_seq`) is preserved
  verbatim; `score_events` is a new implementation behind it (ADR-002 already
  states this). `seq` moves from a `threading.Lock`-guarded counter to a
  `bigserial`/DB sequence — same monotonicity contract, now transactional.
- `InMemoryEventStore` stays for tests/offline; `JsonlEventStore` demoted to
  dev/export; `postgres_events.py` is the seed adapter, widened by M6 into
  `score_events` with FKs and provenance.
- `scoreboard.py` / `scoring_engine.py` folds are **unchanged** — they keep
  folding events into `ScoreboardEntry`/`Snapshot` value objects; only the event
  source is now a durable, indexed, append-only table.
- `scoring_engine.py`’s transitive coupling to `events.py` (the M5.5 refactor
  target) is orthogonal to this schema: the schema depends on the pure
  `EventStore` *protocol*, not the infra impl, so breaking that coupling does
  not change any table here.

---

## 13. Open items (out of M6 design scope, noted so schema doesn’t preclude them)

- Exact role set / permission model → Authentication ADR (the `role` CHECK is a placeholder).
- Enforcing "only published versions attach to competitions" as a hard DB rule (currently app-level + optional trigger).
- `scoreboard_cache` materialization shape (`as_of_seq`) if fold performance ever needs it.
- User PII pseudonymization workflow for erasure requests (nullable PII columns already allow it).
