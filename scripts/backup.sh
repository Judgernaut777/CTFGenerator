#!/usr/bin/env bash
#
# backup.sh DEST_DIR  --  capture a restorable point-in-time backup (M17 17a).
#
# Captures, into DEST_DIR:
#   * db.dump      -- pg_dump --format=custom of the platform DB named by
#                     $CTFGEN_DATABASE_URL. A logical, restorable, INSERT-ordered
#                     dump: pg_restore into a fresh DB recreates the schema +
#                     append-only triggers and COPY-loads rows (INSERT path --
#                     it NEVER issues UPDATE/DELETE/TRUNCATE, so the tamper-
#                     evident ledger/audit tables are loaded without mutation).
#   * artifacts.tar-- a tar of the content-addressed artifact store rooted at
#                     $CTFGEN_ARTIFACT_ROOT (immutable, deterministically
#                     rebuildable content -- REQ-NFR-009).
#   * MANIFEST     -- secret-free provenance: timestamp, DB revision, artifact
#                     count + checksum, ledger counters (for restore row-count
#                     parity), and tool versions.
#
# RPO NOTE: this logical dump is the point-in-time BASELINE. The true RPO<=5min
# (REQ-NFR-006) posture for production is continuous WAL archiving / PITR on top
# of this baseline; that is a deployment-infra concern (not in this script).
#
# SECRET-FREE: the DSN is parsed into libpq PG* env vars (never echoed, never on
# argv); the MANIFEST records only counts/hashes/revisions -- never a DSN, flag,
# token, or password. NON-DESTRUCTIVE: only pg_dump + read-only SELECTs + a tar
# of the store touch the source; nothing is written to the source DB or store.

set -euo pipefail

_here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/_lib.sh
. "$_here/_lib.sh"

[ "$#" -ge 1 ] || die "usage: backup.sh DEST_DIR"
dest="$1"

[ -n "${CTFGEN_DATABASE_URL:-}" ] || die "CTFGEN_DATABASE_URL is not set"
[ -n "${CTFGEN_ARTIFACT_ROOT:-}" ] || die "CTFGEN_ARTIFACT_ROOT is not set"
[ -d "$CTFGEN_ARTIFACT_ROOT" ] || die "artifact root does not exist: $CTFGEN_ARTIFACT_ROOT"

require_cmd tar
require_cmd sha256sum

mkdir -p "$dest"
[ ! -e "$dest/db.dump" ] || die "refusing to overwrite existing backup at $dest/db.dump"

dsn_parse "$CTFGEN_DATABASE_URL"
[ -n "${PGDATABASE:-}" ] || die "CTFGEN_DATABASE_URL has no database name (postgresql://host/DBNAME)"

# QUIESCENT-BACKUP NOTE: the provenance row counts below are read just after the
# dump, so this baseline logical backup assumes the DB is QUIESCENT (no concurrent
# scoring/audit appends -- take it in a maintenance window / with the control plane
# drained). For a HOT backup during active scoring, use continuous WAL/PITR (whose
# restore is inherently snapshot-consistent); the manifest row-count checks are a
# quiescent-backup convenience, not the authoritative integrity guarantee (that is
# scoreboard parity + artifact hash + immutability + migration head on restore).

# 1) Logical custom-format dump (restorable, INSERT-ordered). Read-only.
$CTFGEN_PG_DUMP --format=custom --file="$dest/db.dump"

# 2) Archive the content-addressed artifact store (read-only; -C so paths are
#    store-root-relative and extract cleanly on restore).
tar -cf "$dest/artifacts.tar" -C "$CTFGEN_ARTIFACT_ROOT" .

# 3) Provenance queries (read-only SELECTs).
db_revision="$($CTFGEN_PSQL -tAqc 'SELECT version_num FROM alembic_version')"
score_count="$($CTFGEN_PSQL -tAqc 'SELECT count(*) FROM score_events')"
score_max_seq="$($CTFGEN_PSQL -tAqc 'SELECT coalesce(max(seq), 0) FROM score_events')"
audit_count="$($CTFGEN_PSQL -tAqc 'SELECT count(*) FROM audit_events')"

artifact_count="$(tar -tf "$dest/artifacts.tar" | grep -vc '/$' || true)"
artifacts_sha256="$(sha256sum "$dest/artifacts.tar" | cut -d' ' -f1)"
pg_dump_version="$($CTFGEN_PG_DUMP --version | head -n1)"

# 4) Secret-free MANIFEST (KEY=VALUE; consumed by the restore verifier).
{
    printf 'backup_created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'db_revision=%s\n' "$db_revision"
    printf 'score_events_count=%s\n' "$score_count"
    printf 'score_events_max_seq=%s\n' "$score_max_seq"
    printf 'audit_events_count=%s\n' "$audit_count"
    printf 'artifact_count=%s\n' "$artifact_count"
    printf 'artifacts_sha256=%s\n' "$artifacts_sha256"
    printf 'pg_dump_version=%s\n' "$pg_dump_version"
} >"$dest/MANIFEST"

printf 'backup complete: %s (revision %s, %s ledger events, %s artifacts)\n' \
    "$dest" "$db_revision" "$score_count" "$artifact_count"
