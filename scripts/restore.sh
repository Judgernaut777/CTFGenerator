#!/usr/bin/env bash
#
# restore.sh SRC_DIR TARGET_DSN [--force]  --  restore + verify (M17 17a).
#
# Restores a backup produced by backup.sh into a TARGET database and artifact
# root, then runs the read-only restore verifier and exits nonzero if it fails
# (a restore is not "done" until it is proven usable -- the recovery drill).
#
#   * Creates the TARGET database (named by TARGET_DSN) if absent.
#   * pg_restore of SRC/db.dump into it: recreates the schema INCLUDING the
#     append-only reject_mutation triggers, then COPY-loads rows. COPY is the
#     INSERT path -- it never issues UPDATE/DELETE/TRUNCATE, so the tamper-
#     evident ledger/audit tables are loaded WITHOUT mutation and their
#     immutability triggers are back in force after restore. No --clean is used.
#   * Extracts SRC/artifacts.tar into $CTFGEN_ARTIFACT_ROOT.
#   * Runs `python -m ctf_generator.application.backup.verify` against the
#     TARGET (migration head, ledger, scoreboard parity, artifact hashes).
#
# CLOBBER GUARD: refuses to restore over a NON-EMPTY target database (one that
# already has public tables) unless --force is given (which DROPs + recreates
# it). This protects live data from an accidental restore.
#
# SECRET-FREE: TARGET_DSN is parsed into libpq PG* env vars (never echoed, never
# on argv); nothing prints a password.

set -euo pipefail

_here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/_lib.sh
. "$_here/_lib.sh"

force=0
positional=()
for arg in "$@"; do
    case "$arg" in
        --force) force=1 ;;
        -*) die "unknown option: $arg" ;;
        *) positional+=("$arg") ;;
    esac
done

[ "${#positional[@]}" -ge 2 ] || die "usage: restore.sh SRC_DIR TARGET_DSN [--force]"
src="${positional[0]}"
target_dsn="${positional[1]}"

[ -f "$src/db.dump" ] || die "missing $src/db.dump"
[ -f "$src/artifacts.tar" ] || die "missing $src/artifacts.tar"
[ -n "${CTFGEN_ARTIFACT_ROOT:-}" ] || die "CTFGEN_ARTIFACT_ROOT (restore target) is not set"

require_cmd tar

dsn_parse "$target_dsn"
target_db="$PGDATABASE"
[ -n "$target_db" ] || die "TARGET_DSN has no database name"

# Admin ops connect to the maintenance database, never to $target_db itself.
psql_admin() { PGDATABASE=postgres $CTFGEN_PSQL "$@"; }

exists="$(psql_admin -tAqc "SELECT 1 FROM pg_database WHERE datname='$target_db'")"
if [ "$exists" = "1" ]; then
    tables="$($CTFGEN_PSQL -d "$target_db" -tAqc \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
    if [ "${tables:-0}" -gt 0 ]; then
        if [ "$force" -ne 1 ]; then
            die "refusing to clobber non-empty target '$target_db' ($tables tables); pass --force"
        fi
        printf 'warning: --force: dropping and recreating non-empty target %s\n' "$target_db" >&2
        psql_admin -c "DROP DATABASE \"$target_db\" WITH (FORCE)"
        psql_admin -c "CREATE DATABASE \"$target_db\""
    fi
else
    psql_admin -c "CREATE DATABASE \"$target_db\""
fi

# Recreate schema + triggers and COPY-load rows (INSERT-only; no --clean).
$CTFGEN_PG_RESTORE --no-owner --no-privileges --dbname="$target_db" "$src/db.dump"

# Restore the content-addressed artifact store.
mkdir -p "$CTFGEN_ARTIFACT_ROOT"
tar -xf "$src/artifacts.tar" -C "$CTFGEN_ARTIFACT_ROOT"

# Verify the restored state (read-only). Exits nonzero on any failed check.
py="${CTFGEN_PYTHON:-python3}"
if ! CTFGEN_DATABASE_URL="$target_dsn" \
    CTFGEN_ARTIFACT_ROOT="$CTFGEN_ARTIFACT_ROOT" \
    "$py" -m ctf_generator.application.backup.verify --manifest "$src/MANIFEST"; then
    die "restore verification FAILED for target '$target_db'"
fi

printf 'restore complete and verified: target %s\n' "$target_db"
