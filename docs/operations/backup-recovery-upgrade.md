# Backup, Recovery, Upgrade & Retention

Operational runbook for the M6+ control-plane platform (PostgreSQL source of truth
+ a content-addressed artifact store + isolated workers). Grounded in the M17
tooling (`scripts/backup.sh`, `scripts/restore.sh`, the
`ctf_generator.application.backup.verify` harness) and the M16 readiness gate.

The invariants that shape every procedure here:

- **Append-only / tamper-evident** tables — `audit_events`, the ledger
  (`submissions`/`solves`/`score_events`), `job_transitions`, `instance_events`,
  `quota_reservation_items`, published challenge content — reject UPDATE/DELETE/
  TRUNCATE at the DB (`reject_mutation()`). A restore must **load** rows, never
  mutate them; a downgrade must never destroy them.
- **Content-addressed artifacts** — the artifact store is immutable and
  deterministically rebuildable from `(generator version, spec, family version,
  seed)` (REQ-NFR-009), so artifact loss is hash-verifiable and recoverable.
- **Secret-free** — the DSN, artifact root, and flags live in env; worker creds are
  sha256-at-rest; there is **no separate secret store to back up**, and backups /
  the verifier never capture or emit a secret.

Targets: **RPO ≤ 5 min** (REQ-NFR-006), **RTO ≤ 30 min** (REQ-NFR-007).

---

## 1. Backup

```
CTFGEN_DATABASE_URL=postgresql://user:pw@host/ctf \
CTFGEN_ARTIFACT_ROOT=/var/lib/ctfgen/artifacts \
  scripts/backup.sh /backups/ctfgen/$(date -u +%Y%m%dT%H%M%SZ)
```

Produces `db.dump` (a `pg_dump --format=custom` logical dump — restorable, INSERT-
ordered, so `pg_restore` recreates schema+triggers then COPY-loads rows without
mutating the append-only tables), `artifacts.tar`, and a secret-free `MANIFEST`
(revision, ledger + audit row counts, artifact count/checksum). The script is
read-only on the source and refuses to overwrite an existing backup.

**Cadence / RPO.** The logical dump is a point-in-time **baseline**. Meeting
RPO ≤ 5 min in production is **continuous WAL archiving / PITR** layered on top
(e.g. `pgBackRest`/`barman` streaming WAL to object storage) — a deployment-infra
concern outside these scripts. The logical dump's row-count provenance assumes a
**quiescent** backup (no concurrent scoring/audit writes); take scheduled logical
dumps in a maintenance window or with the control plane drained, and rely on
PITR/WAL for hot, sub-5-min-RPO recovery (a PITR restore is inherently
snapshot-consistent, so the quiescence caveat does not apply to it).

**Artifacts.** `artifacts.tar` of `CTFGEN_ARTIFACT_ROOT`; because artifacts are
content-addressed and rebuildable, their RPO is relaxed — a lost artifact is
regenerated deterministically. Replicate the artifact volume/bucket per your
storage SLA (an S3-compatible backend is the same `ArtifactStore` protocol, not yet
implemented — credential-blocked).

---

## 2. Restore + verify (recovery drill)

```
scripts/restore.sh /backups/ctfgen/<TS> postgresql://user:pw@newhost/ctf_restored [--force]
```

Creates the target DB, `pg_restore`s the dump (INSERT-only; the append-only triggers
are recreated and never tripped), extracts the artifacts, and runs the verifier —
exiting nonzero if verification fails. It refuses a non-empty target without
`--force`.

The **verifier** (`python -m ctf_generator.application.backup.verify --manifest
<SRC>/MANIFEST`, run automatically by restore.sh) proves the restore is a
consistent, usable state — the prerequisite for a valid recovery drill:

| Check | Fails when |
|---|---|
| `migration_head` | `alembic_version` ≠ the code head (`CODE_MIGRATION_HEAD`) — an unusable/wrong-schema restore |
| `ledger_seq_monotonic` | `score_events.seq` non-monotonic / duplicate (identity not restored) — burned seqs are legal and NOT flagged |
| `ledger_rowcount` / `audit_rowcount` | restored count ≠ the manifest count — a dropped ledger/audit row (quiescent-backup assumption) |
| `scoreboard_parity` | a re-fold of the restored ledger doesn't reproduce the stored projection, or a projection is orphaned over a lost/empty ledger |
| `artifact_integrity` | a build's stored tar is missing or doesn't hash back to the content address its key encodes |

The harness is READ-ONLY and its output is secret-free (counts/seqs/revisions/
hashes only). It verifies restore **integrity**, not the RPO/RTO SLOs themselves —
time the restore (`restore.sh` wall clock) to validate RTO ≤ 30 min, and derive RPO
from your backup/WAL cadence.

**Recovery drill (the v1.0 gate, validates REQ-NFR-006/007):** on a cadence,
restore the latest backup into a scratch target, run the verifier, record the
wall-clock restore time and the backup's data-loss window, and confirm both meet the
SLOs. Log the drill in the audit trail.

Post-DB-recovery, the scoreboard is reconstructable from the ledger regardless — the
projection is a pure fold of `score_events` (see incident-response §2.4).

---

## 3. Schema upgrade & rollback

Migrations are Alembic (chain `0001..<head>`); **every migration has a real,
drift-tested `downgrade()`** (proven by `tests/test_migration_drift_integration.py`:
`upgrade head` has zero ORM drift, and `downgrade base` leaves no leftover objects).

**Upgrade:**
```
CTFGEN_DATABASE_URL=... alembic -c alembic.ini upgrade head
```
Then confirm the deploy: `GET /system/version` (running version) and
`GET /system/ready` — whose `migrations` check compares the DB `alembic_version` to
the code `CODE_MIGRATION_HEAD` and returns **503** until they match. `/system/ready`
is the deploy gate; do not route traffic to an app whose migrations are behind.

**Rollback policy (see incident-response §2.11).** Prefer a **forward fix**.
Downgrade only if the new migration is the cause AND no data depends on it. The
**append-only tables (`audit_events`, the ledger, `score_events`) are never
downgraded destructively** — a downgrade that would drop or truncate them is
forbidden; roll the app back and forward-fix the schema instead. App rollback is
safe independently: artifacts are immutable/content-addressed and instance launch is
idempotent, so a control-plane rollback doesn't disturb running instances.

---

## 4. Retention & archival

- **Append-only, never purged (by design):** `audit_events`, the ledger
  (`submissions`/`solves`/`score_events`), `job_transitions`, `instance_events`.
  These are the tamper-evident / integrity record and are retained indefinitely;
  they are backed up but never destructively pruned (the `reject_mutation` triggers
  enforce it). Cold-storage archival of very old competitions is a future option
  (they remain queryable in place today).
- **Soft archival, not deletion:** competitions (`status='archived'`, `archived_at`)
  and challenge versions (`published → archived`) are archived, never hard-deleted;
  FKs are `ON DELETE RESTRICT`, never `CASCADE` (ADR-006).
- **Transient tables (safe to prune):** `oidc_login_transactions` (one-time-use +
  expiring — `prune_expired()`), expired `auth_sessions`, released
  `quota_reservations`, and dead-letter/expired jobs (`reap_expired`,
  `retry_dead_letter`). Wire `prune_expired()` / the reaper into a scheduled
  maintenance loop per your operational cadence (housekeeping only — never touches
  the append-only record).

Because the ledger and audit trail are append-only and fully backed up, and
artifacts are rebuildable, the durable state has a single authoritative recovery
path: restore PostgreSQL (PITR for RPO ≤ 5 min) + the artifact volume, then run the
verifier before returning to service.

---

## 5. Recovery drill results (RPO/RTO evidence — M20)

`scripts/recovery_drill.sh` is the **executed** disaster-recovery drill behind
RELEASE_CRITERIA gate **S8** and REQ-NFR-007. `verify.py` proves a restore is
*integrity*-correct; the drill answers the *time* question: it seeds a known state
into a throwaway source DB, takes a logical `pg_dump -Fc` backup + artifact tar +
MANIFEST, **drops the source** (simulated loss), restores into a fresh target, and
wraps the **whole recovery-to-verified-usable path** (`pg_restore` → extract
artifacts → `verify.py`) in an explicit `perf_counter` clock. It prints MEASURED vs
TARGET for both RTO and RPO, asserts **RTO ≤ SLO** (parameter, default 1800 s =
30 min), asserts the restore is not a no-op (target actually holds the seeded ledger
rows, parity vs MANIFEST), and **exits nonzero on any breach**.

```
CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \
  scripts/recovery_drill.sh [--rto-slo-seconds N] [--rpo-target-seconds N]
```

**Measured (representative slice — 1 competition, 3 ledger events, 1 audit row, 1
content-addressed build blob), live `ctfgen_pg_epic1` PostgreSQL 16:**

| Metric | Measured | Target | Result |
|--------|----------|--------|--------|
| **RTO** (restore → verified-usable, wall clock) | **≈ 1.7 s** | ≤ 1800 s (30 min) | **PASS** |
| **RPO** (baseline snapshot staleness) | ≈ 0 s | ≤ 300 s | baseline-only (not a gate) |

The gate is live, not a tautology: `--rto-slo-seconds 0` breaches and exits nonzero,
and `--empty-target` (verify an un-restored empty target) is caught as a NO-OP
restore and exits nonzero. Regression-guarded by
`tests/test_recovery_drill_integration.py` (PG+docker gated; skips cleanly when
PostgreSQL is unreachable).

**RTO scope.** The measured RTO is the restore + verify wall clock on a small
representative dataset; it does **not** include human detection/decision latency or
production-scale data volume. It validates the *mechanism* is well within SLO with
large headroom; production-scale RTO on a full dataset is **UNVERIFIED here**
(no production-scale corpus on this host) — re-run the drill against a
production-sized restore to close that.

**RPO — honest status (charter §5).** A logical `pg_dump` is a point-in-time
**baseline**: at the instant of backup everything committed is captured, so the
drill reports only "baseline snapshot staleness" (backup age vs the newest datum),
which is **not a gate**. The continuous **RPO ≤ 5 min (REQ-NFR-006)** posture
requires **WAL archiving / PITR**, which is **NOT configured on this host** →
**UNVERIFIED**. The drill deliberately does **not** fake a 5-minute RPO; it
validates RTO end-to-end and documents the PITR requirement as the remaining RPO
work (configure `archive_mode`/`archive_command` + base backups, then drill a
point-in-time restore to a target recovery timestamp and assert the recoverable
window ≤ 5 min).

**Host caveat.** On an operator host with the `postgresql-client` binaries,
`scripts/backup.sh` + `restore.sh` run verbatim. This rootful arm64 CI host has no
pg client binaries and the postgres container shares no host path, so a docker-exec
`pg_dump --file=` would write inside the container. The drill therefore reuses the
**same** logical `pg_dump -Fc`/`pg_restore` semantics and the **same** `verify.py`
harness + MANIFEST format, but streams the dump/restore over `docker exec`
stdin/stdout (the proven pattern in `tests/test_restore_verify_integration.py`). The
RTO methodology is identical when the scripts run directly.
