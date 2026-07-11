# Title: ADR-006 — Normalized persistence schema with append-only ledger and enforced immutability

> One line: Adopt a normalized relational schema for the M6 core aggregates in
> which Submission and Solve are separate tables, ScoreEvent/AuditEvent are
> append-only, published challenge content and builds are immutable, scoreboards
> are projections, and destructive delete is replaced with soft archival.

## Status

**Proposed**

## Date

`2026-07-11`

## Context

This decision refines the **Database strategy** axis (000-template), building on
[ADR-002](002-postgresql-persistence.md) (PostgreSQL is the durable source of
truth). ADR-002 chose the backbone; this ADR fixes the *shape* of the core
control-plane schema and the invariants the shape must encode. Full column-level
detail lives in [`docs/architecture/persistence-design.md`](../architecture/persistence-design.md).

Current-state facts (grounded in the codebase):

- The domain already splits `Submission` from `SolveEvent`
  (`domain/challenges/models.py`), with `solve_event_from_submission()` refusing
  to build a solve from an incorrect submission. There is no persistence for
  either today.
- The event log (`events.py`) is an append-only sequence with monotonic `seq`;
  `postgres_events.py` is a seed Postgres adapter keyed `seq serial PK, ts, type,
  team_id, challenge_id, payload jsonb`.
- Scoreboards are computed by pure folds (`scoreboard.py`, `scoring_engine.py`)
  over events; `ScoreboardEntry`/`Snapshot` are value objects, not stored rows.
- Challenge generation is deterministic: identical (generator version, spec,
  family version, seed) ⇒ byte-identical artifacts; `build.BuildMeta` carries
  `spec_sha256` + `family_version`, and `ChallengeSpec` carries `cve_content_hash`
  to lock CVE content. No `User`/`Team`/`Membership`/`ChallengeVersion` types
  exist yet.

Product invariants this schema must uphold:

- A correct submission creates **at most one** Solve per (team, challenge,
  competition).
- The score-event log is the source of truth; scoreboards are rebuildable.
- Published challenge content and content-addressed builds are immutable; drafts
  are mutable.
- History (submissions, solves, score/audit events) is auditable and must not be
  silently rewritten or deleted.
- ADR-002 invariants: no secrets (flags, session tokens, provider keys) in
  loggable/persisted columns; Alembic owns the schema.

## Decision

We will define the M6 core schema as nine normalized entities — `Competition`,
`Team`, `User`, `Membership`, `ChallengeDefinition`, `ChallengeVersion`,
`Submission`, `Solve`, `ScoreEvent` — plus supporting `ChallengeBuild`
(content-addressed) and `AuditEvent`, with these binding rules:

1. **Submission and Solve are separate tables.** Every attempt is a
   `submissions` row; an accepted attempt yields at most one `solves` row.
2. **At-most-one-solve is a DB unique constraint:**
   `UNIQUE (competition_id, team_id, challenge_version_id)` on `solves`, plus
   `UNIQUE (submission_id)`. The domain rule becomes a database guarantee, not
   app logic (matching ADR-002’s move of this invariant off the in-process lock).
3. **ScoreEvent and AuditEvent are append-only.** `bigserial`/serial-keyed,
   INSERT-only, protected by `BEFORE UPDATE OR DELETE` triggers that raise. The
   monotonic `seq` from `events.py` is preserved via a DB sequence. Corrections
   are compensating events, never edits.
4. **Scoreboards are projections, not base tables.** They are folds over
   `score_events` via the existing pure functions; any materialization is a
   rebuildable cache stamped with `as_of_seq`, never authoritative.
5. **Challenge authoring is versioned and immutable-on-publish.**
   `ChallengeDefinition` holds stable identity; `ChallengeVersion` holds one
   revision. `draft` rows are mutable; on `published` the content columns freeze
   and only `published → archived` is allowed thereafter — enforced by trigger
   and by `UNIQUE (definition_id, spec_sha256)` content dedup. `ChallengeBuild`
   is keyed by its own `build_sha256` (content-addressed) and is whole-row
   insert-only.
6. **Destructive delete is replaced with soft archival.** History-bearing tables
   are never `DELETE`d; they carry `archived_at` (or `status`), and all FKs into
   history are `ON DELETE RESTRICT` (never `CASCADE`). The sole hard-delete
   allowed is a never-published, unattached draft version.
7. **Immutability is enforced defense-in-depth:** app repositories are the first
   line; DB triggers + unique/content-address constraints are the backstop, so a
   buggy or hostile app path cannot rewrite history or mutate published content.

The schema reconciles with the existing dataclasses: `submissions`/`solves` agree
field-for-field with `Submission`/`SolveEvent` (adding `competition_id` +
surrogate ids); `CompetitionConfig.default_scoring`/`ChallengeScoringConfig` are
**normalized out** onto a `competition_challenges` join keyed
`(competition_id, challenge_version_id)`; `ChallengeSpec` is **split** across
`challenge_definitions` (identity) and `challenge_versions` (versioned content +
full `spec_json` blob + `spec_sha256`). No fields are invented beyond the minimal
`User`/`Team`/`Membership` identity model the per-team/membership invariants
require (deferred in detail to the future Authentication ADR).

## Consequences

### Positive

- The at-most-one-solve invariant and the append-only history become database
  guarantees, immune to app bugs and concurrent writers.
- Full auditability and reproducibility: past competitions replay from an
  immutable ledger; published challenges and builds are content-addressed and
  cannot drift, upholding deterministic generation.
- Clean separation of concerns: identity/versioning/scoring/ledger each
  normalized, so a challenge can evolve (new versions) without rewriting past
  competition records.
- `events.py`/`postgres_events.py`/`scoreboard.py` semantics are preserved — the
  `EventStore` protocol and the pure folds are unchanged; only durability and
  constraints are added.

### Negative

- More tables and cross-table (composite-FK) integrity than an embedded design;
  more Alembic migrations and trigger DDL to author and test.
- Triggers put correctness logic in the database (harder to unit-test than pure
  Python; must be covered by DB-level tests). Chosen deliberately as the backstop.
- Soft archival means queries must consistently filter `archived_at IS NULL`;
  forgetting the filter leaks archived rows into live views.
- Introduces `User`/`Team`/`Membership` ahead of the Authentication ADR; the
  `role` set is a placeholder subject to later migration.

### Neutral

- Scoreboard computation and the `EventStore` protocol shape are untouched.
- `postgres_events.py` remains a valid narrower adapter; `score_events` is its
  widened M6 form (real FKs + provenance).
- The M5.5 decoupling of `scoring_engine.py` from `events.py` is orthogonal: the
  schema depends on the pure `EventStore` protocol, not the infra impl.
- Future ADRs must respect: the ledger (not any scoreboard/cache) is
  authoritative; published version content and builds are immutable; history
  tables are append-only and never `CASCADE`-deleted.

## Alternatives considered

| Alternative | Why not chosen |
|---|---|
| **One `submissions` table with a `correct` flag and no separate `solves`** | Cannot express "at most one solve per (team, challenge, competition)" as a clean unique constraint (correct submissions can legitimately repeat), and conflates "attempt" with "accepted result" — diverging from the existing domain split and `solve_event_from_submission()`. |
| **Store scoreboards as authoritative rows** | Violates the ADR-002 invariant that scoreboards are reconstructable projections of the score-event ledger; risks divergence between stored standings and the ledger. |
| **App-level immutability only (no triggers)** | A buggy or malicious code path could rewrite history or edit a published challenge; the audit/scoring invariants are too load-bearing to leave without a DB backstop. |
| **Embed scoring config on the version (as the `ChallengeScoringConfig` dataclass does)** | Scoring is per-competition, not per-version; embedding would force a new version per competition and duplicate content. Normalizing onto `competition_challenges` keeps versions reusable across competitions. |
| **Hard `DELETE` with `ON DELETE CASCADE`** | Silently erases auditable competition history and orphans ledger meaning; rejected in favor of soft archival + `RESTRICT`. |
| **Mutable challenges, no versioning** | Editing a challenge mid- or post-competition would retroactively change what teams solved; breaks reproducibility and the deterministic-generation guarantee. |
