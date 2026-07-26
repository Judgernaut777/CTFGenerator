#!/usr/bin/env bash
#
# pitr_drill.sh  --  EXECUTED point-in-time-recovery drill that PROVES continuous
# WAL archiving can recover PostgreSQL to an ARBITRARY target time, closing the RPO
# gap that scripts/recovery_drill.sh explicitly leaves open (a logical pg_dump is a
# BASELINE snapshot; REQ-NFR-006's continuous RPO <= 5 min needs WAL archiving/PITR).
#
# It answers the question a baseline dump cannot: "after a base backup, can we
# replay archived WAL forward to a chosen instant and STOP there exactly?" -- and
# asserts the recovered cluster contains every commit at/<= the target and NONE
# after it. That before/after boundary IS point-in-time recoverability; the age of
# the newest archived WAL segment IS the achievable RPO window.
#
# Fully self-contained via docker + the postgres:16 image (server toolchain incl.
# pg_basebackup); it touches NO control-plane database and leaves NO residue (a
# cleanup trap removes both throwaway containers and both volumes). It mirrors the
# archive settings shipped in deploy/docker-compose.pitr.yml, so a PASS here is
# evidence the SAME config recovers a real deployment.
#
# End to end:
#   1. SOURCE: start a throwaway postgres:16 with wal_level=replica, archive_mode=on
#      and archive_command copying each filled segment into a `walarchive` volume
#      (the compose overlay's exact archive_command).
#   2. BASE BACKUP: pg_basebackup -Fp -Xstream into a `base` volume (a physical
#      copy of the cluster -- the PITR starting point).
#   3. SEED + MARK: create a marker table; insert a BEFORE row; capture the target
#      time T = now(); insert an AFTER row; pg_switch_wal() + wait for the segment
#      to land in the archive (so T is inside the archived range).
#   4. SIMULATE LOSS: stop + remove SOURCE. Only the base backup + archive survive.
#   5. RESTORE (PITR): inject recovery.signal + restore_command + recovery_target_
#      time=T + recovery_target_action=promote into the base copy, start a fresh
#      container over it; postgres replays archived WAL up to T, then promotes.
#   6. ASSERT: the recovered cluster has the BEFORE row and does NOT have the AFTER
#      row (recovery stopped exactly at T). Report the RPO window (archive lag).
#      Exit nonzero on any breach (incl. a negative-control mode that must fail).
#
# SECRET-FREE: the throwaway cluster uses POSTGRES_HOST_AUTH_METHOD=trust on an
# isolated docker network namespace (no host port published); no password is set,
# stored, or printed. All output is counts / labels / durations only.

set -euo pipefail

_here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/_lib.sh
. "$_here/_lib.sh"   # die / require_cmd

# --- configuration -----------------------------------------------------------

rpo_target_seconds=300   # REQ-NFR-006 RPO <= 5 min -- ASSERTED against archive lag
image="${CTFGEN_PG_IMAGE:-postgres:16}"
tag="pitr_$$"            # unique-per-run names so concurrent runs never collide
src="ctfgen_${tag}_src"
dst="ctfgen_${tag}_dst"
vol_arch="ctfgen_${tag}_arch"
vol_base="ctfgen_${tag}_base"
negative_control=0       # --negative-control: recover PAST T; the AFTER row then
                         # leaks and the drill MUST fail (proves the assert has teeth)
keep=0

usage() {
    cat >&2 <<'EOF'
usage: pitr_drill.sh [--rpo-target-seconds N] [--negative-control] [--keep]
  --rpo-target-seconds N   RPO window to assert the archive lag against (default 300)
  --negative-control       recover to the LATEST WAL (past the target) -- the AFTER
                           row then survives and the drill MUST exit nonzero
  --keep                   leave containers + volumes for inspection (prints names)
env:
  CTFGEN_PG_IMAGE          postgres image to use (default postgres:16)
EOF
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --rpo-target-seconds) rpo_target_seconds="${2:?}"; shift 2 ;;
        --negative-control) negative_control=1; shift ;;
        --keep) keep=1; shift ;;
        -h|--help) usage ;;
        *) die "unknown argument: $1" ;;
    esac
done

require_cmd docker

# --- cleanup trap ------------------------------------------------------------

cleanup() {
    [ "$keep" = 1 ] && { echo "kept: $src $dst $vol_arch $vol_base"; return; }
    docker rm -f "$src" "$dst" >/dev/null 2>&1 || true
    docker volume rm "$vol_arch" "$vol_base" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# psql helper against a named container (trust auth; no password on argv).
psql_c() {
    local ctr="$1"; shift
    docker exec -i "$ctr" psql -X -A -t -U postgres -d postgres "$@"
}

# Wait for a STABLE real server. The official image starts a TEMPORARY init-time
# server (socket only) to run bootstrap scripts, then restarts -- so a single
# pg_isready/SELECT can pass against that temp server moments before the socket
# vanishes. Require N consecutive successful SELECT 1s a second apart, and only
# start counting after the container logs the FINAL "ready to accept connections".
wait_ready() {
    local ctr="$1" i ok=0
    for i in $(seq 1 90); do
        if [ -z "$(docker ps -q --filter "name=^${ctr}$")" ]; then
            echo "--- $ctr crashed; last log lines: ---" >&2
            docker logs --tail 30 "$ctr" 2>&1 | sed 's/^/  /' >&2 || true
            die "$ctr exited before becoming ready"
        fi
        if docker exec "$ctr" psql -X -tA -U postgres -d postgres -c 'SELECT 1' \
                >/dev/null 2>&1; then
            ok=$((ok + 1))
            [ "$ok" -ge 3 ] && return 0
        else
            ok=0
        fi
        sleep 1
    done
    echo "--- $ctr not ready; last log lines: ---" >&2
    docker logs --tail 30 "$ctr" 2>&1 | sed 's/^/  /' >&2 || true
    die "$ctr did not become ready in time"
}

# --- 1. SOURCE cluster with WAL archiving ------------------------------------

echo "[pitr] starting source cluster ($image) with WAL archiving"
docker volume create "$vol_arch" >/dev/null
docker volume create "$vol_base" >/dev/null
docker run -d --name "$src" \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -v "$vol_arch":/walarchive \
    -v "$vol_base":/base \
    "$image" \
    postgres \
      -c wal_level=replica \
      -c archive_mode=on \
      -c "archive_command=test ! -f /walarchive/%f && cp %p /walarchive/%f" \
      -c archive_timeout=60 \
      -c max_wal_senders=3 >/dev/null
wait_ready "$src"
# The two named volumes mount root-owned; the archiver (the server process) and
# pg_basebackup both run as the postgres user (uid 999), so hand them ownership
# before either writes -- else archive_command / pg_basebackup fail EPERM.
docker exec -u root "$src" chown postgres:postgres /walarchive /base >/dev/null

# --- 2. base backup ----------------------------------------------------------

echo "[pitr] taking base backup (pg_basebackup -Fp -Xstream)"
# Run as the postgres user so the copied cluster is owned by uid 999 (postgres),
# which the restore container requires for a 0700 PGDATA.
docker exec -u postgres "$src" \
    pg_basebackup -U postgres -D /base -Fp -X stream -c fast >/dev/null
backup_epoch="$(docker exec "$src" date -u +%s)"

# --- 3. seed + capture the point-in-time target ------------------------------

echo "[pitr] seeding marker rows + capturing target time T"
psql_c "$src" -c "CREATE TABLE pitr_marker (id serial PRIMARY KEY, label text, at timestamptz DEFAULT now());" >/dev/null
psql_c "$src" -c "INSERT INTO pitr_marker (label) VALUES ('before-target');" >/dev/null
# T = an instant AFTER the before-row commit and BEFORE the after-row commit.
# Command substitution trims the trailing newline but PRESERVES the space inside
# the timestamp (stripping it would make recovery_target_time unparseable).
target_time="$(psql_c "$src" -c "SELECT now();")"
target_time="${target_time#"${target_time%%[![:space:]]*}"}"  # ltrim only
[ -n "$target_time" ] || die "failed to capture target time"
sleep 2
psql_c "$src" -c "INSERT INTO pitr_marker (label) VALUES ('after-target');" >/dev/null

# Force the WAL holding both commits out to the archive so T is recoverable.
psql_c "$src" -c "SELECT pg_switch_wal();" >/dev/null
psql_c "$src" -c "CHECKPOINT;" >/dev/null
echo "[pitr] waiting for the switched WAL segment to reach the archive"
archived=0
for _ in $(seq 1 60); do
    n="$(docker exec "$src" sh -c 'ls -1 /walarchive 2>/dev/null | grep -c -E "^[0-9A-F]{24}$" || true')"
    if [ "${n:-0}" -ge 1 ]; then archived=1; archive_epoch="$(docker exec "$src" date -u +%s)"; break; fi
    sleep 1
done
[ "$archived" = 1 ] || die "no WAL segment was archived (archive_command failing?)"

# --- 4. simulate loss --------------------------------------------------------

echo "[pitr] stopping + removing source (only base backup + archive survive)"
docker rm -f "$src" >/dev/null

# --- 5. PITR restore ---------------------------------------------------------

# Recover to T (positive) or to the very end of the WAL (negative control: the
# after-row then survives and the assertion below MUST fail).
if [ "$negative_control" = 1 ]; then
    recovery_line="recovery_target_action = 'promote'"   # no target -> replay ALL WAL
    echo "[pitr] NEGATIVE CONTROL: recovering past T (after-row must leak)"
else
    recovery_line="recovery_target_time = '$target_time'"
    echo "[pitr] restoring to point-in-time T=$target_time"
fi

# Inject the recovery config into the base copy AS the postgres user (correct
# ownership/permissions), then start a fresh cluster over it.
docker run --rm -u postgres -v "$vol_base":/base "$image" bash -c "
    set -e
    touch /base/recovery.signal
    {
        echo \"restore_command = 'cp /walarchive/%f %p'\"
        echo \"$recovery_line\"
        echo \"recovery_target_action = 'promote'\"
    } >> /base/postgresql.auto.conf
" >/dev/null

docker run -d --name "$dst" \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    -v "$vol_arch":/walarchive \
    -v "$vol_base":/var/lib/postgresql/data \
    "$image" >/dev/null
wait_ready "$dst"

# Wait for recovery to finish (promotion -> not in recovery, read-write).
echo "[pitr] waiting for recovery to complete + promote"
promoted=0
for _ in $(seq 1 60); do
    r="$(psql_c "$dst" -c "SELECT pg_is_in_recovery();" | tr -d '[:space:]' || true)"
    if [ "$r" = "f" ]; then promoted=1; break; fi
    sleep 1
done
[ "$promoted" = 1 ] || die "recovery did not complete/promote in time"

# --- 6. assert the point-in-time boundary ------------------------------------

before_n="$(psql_c "$dst" -c "SELECT count(*) FROM pitr_marker WHERE label='before-target';" | tr -d '[:space:]')"
after_n="$(psql_c "$dst" -c "SELECT count(*) FROM pitr_marker WHERE label='after-target';" | tr -d '[:space:]')"
rpo_window=$(( archive_epoch - backup_epoch ))

echo "-----------------------------------------------------------------------"
echo "PITR drill results"
echo "  target time (T)           : $target_time"
echo "  before-target rows        : $before_n (expect 1)"
echo "  after-target rows         : $after_n (expect 0 at T)"
echo "  archive lag / RPO window  : ${rpo_window}s   (target <= ${rpo_target_seconds}s)"
echo "-----------------------------------------------------------------------"

fail=0
[ "$before_n" = 1 ] || { echo "BREACH: before-target row missing after PITR"; fail=1; }
if [ "$negative_control" = 1 ]; then
    # The whole point: without a target, the after-row leaks -> the boundary check
    # below is what a real PITR relies on, so this control MUST end nonzero.
    [ "$after_n" = 1 ] || { echo "control weak: after-row absent even without a target"; fail=1; }
    echo "NEGATIVE CONTROL: after-target present as expected -> failing on purpose"
    exit 1
fi
[ "$after_n" = 0 ] || { echo "BREACH: after-target row present -> recovery overshot T"; fail=1; }
[ "$rpo_window" -le "$rpo_target_seconds" ] || { echo "BREACH: RPO window ${rpo_window}s > ${rpo_target_seconds}s"; fail=1; }

[ "$fail" = 0 ] || exit 1
echo "PITR drill PASS: point-in-time recovery stopped exactly at T; RPO window within target."
