#!/usr/bin/env bash
#
# recovery_drill.sh  --  EXECUTED disaster-recovery drill that MEASURES the RTO
# wall-clock against its SLO (M20 validation program). Unlike verify.py (which
# proves a restore is INTEGRITY-correct) this drill answers the *time* question
# REQ-NFR-007 asks: "how long, on the wall clock, to recover to a verified-usable
# state?" -- and asserts that measured RTO <= the SLO (default 30min), exiting
# NONZERO on breach. It is real evidence for RELEASE_CRITERIA gate S8, not a claim.
#
# What it does, end to end, against the live control-plane PostgreSQL:
#   1. SEED a known state into a throwaway SOURCE database + a real content-
#      addressed artifact store (a competition, ledger events, an audit row, a
#      materialized build blob) -- the same representative slice verify.py checks.
#   2. BACKUP: a logical pg_dump(--format=custom) of SOURCE + a tar of the store +
#      a secret-free MANIFEST (the same KEY=VALUE format scripts/backup.sh writes,
#      recording backup_created_at + ledger/audit counters). The backup timestamp
#      is recorded.
#   3. SIMULATE LOSS: DROP the source database. From here only the backup survives.
#   4. RESTORE (TIMED): create a fresh empty TARGET database, pg_restore the dump
#      into it, extract the artifact tar, then run the verify.py harness against
#      TARGET -- the WHOLE recovery-to-usable path wrapped in an explicit
#      perf_counter clock (via python). RTO = that wall-clock.
#   5. MEASURE + ASSERT: print MEASURED vs TARGET for both RTO and RPO; assert
#      RTO <= SLO; assert the restore is NOT a no-op (TARGET actually holds the
#      seeded ledger rows -- parity vs the backup MANIFEST). Exit nonzero on any
#      breach.
#
# ---------------------------------------------------------------------------
# RPO HONESTY (charter section 5 -- no faked SLO). A logical pg_dump is a
# point-in-time BASELINE: at the instant of backup everything committed is
# captured, so the drill reports "baseline snapshot staleness" = backup_created_at
# minus the newest recoverable datum's timestamp. That is NOT the continuous
# RPO<=5min posture REQ-NFR-006 requires -- that needs WAL archiving / PITR, which
# is NOT configured on this host. So RPO here is reported as BASELINE-ONLY and is
# NOT a gate; the continuous-RPO requirement is documented UNVERIFIED. This drill
# VALIDATES RTO end-to-end and does NOT pretend to validate a 5-minute RPO.
#
# HOST NOTE (why this drill streams instead of shelling out to backup.sh/
# restore.sh verbatim). scripts/backup.sh and restore.sh drive `pg_dump --file=`
# and `pg_restore <file>`; on an OPERATOR host that has the postgresql-client
# binaries they run as-is. THIS rootful arm64 CI host has NO pg client binaries and
# the postgres container shares NO host path, so a docker-exec `pg_dump --file=`
# would write the dump INSIDE the container while the tar/MANIFEST land on the
# host -- they cannot round-trip here. The drill therefore reuses the *same*
# logical pg_dump(-Fc)/pg_restore semantics and the *same* verify.py harness +
# MANIFEST, but streams the dump/restore over `docker exec` stdin/stdout (the
# proven pattern in tests/test_restore_verify_integration.py). The RTO methodology
# is identical on an operator host running the scripts directly.
#
# SECRET-FREE: the DSN's password is passed to the pg tools only via PGPASSWORD
# (docker exec -e), never on argv or in output; the MANIFEST and all drill output
# carry only counts / revisions / slugs / durations -- never a DSN, password,
# flag, or challenge payload.

set -euo pipefail

_here="$(cd "$(dirname "$0")" && pwd)"
_repo="$(cd "$_here/.." && pwd)"
# shellcheck source=scripts/_lib.sh
. "$_here/_lib.sh"   # die / require_cmd (dsn_parse unused: we derive DSNs in python)

# --- configuration -----------------------------------------------------------

rto_slo_seconds=1800   # REQ-NFR-007 RTO <= 30 min (parameter; --rto-slo-seconds)
rpo_target_seconds=300 # REQ-NFR-006 RPO <= 5 min (REPORTED ONLY -- see RPO HONESTY)
keep_target=0          # --keep: leave the recovered TARGET db for inspection
empty_target=0         # --empty-target: negative control (no-op restore must BREACH)

usage() {
    cat >&2 <<'EOF'
usage: recovery_drill.sh [--rto-slo-seconds N] [--rpo-target-seconds N]
                         [--keep] [--empty-target]
  --rto-slo-seconds N     RTO SLO to assert against (default 1800 = 30min)
  --rpo-target-seconds N  RPO target to REPORT against (default 300; not a gate)
  --keep                  keep the recovered TARGET database (prints its name)
  --empty-target          NEGATIVE CONTROL: skip the restore and verify an EMPTY
                          target -- proves a no-op restore is caught (exits nonzero)
env:
  CTFGEN_TEST_DATABASE_URL / CTFGEN_DATABASE_URL  base DSN (db name is replaced)
  CTFGEN_PG_DOCKER_CONTAINER                      postgres container (default ctfgen_pg_epic1)
  CTFGEN_PYTHON                                   python to use (default <repo>/.venv/bin/python3)
EOF
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --rto-slo-seconds) rto_slo_seconds="${2:?}"; shift 2 ;;
        --rpo-target-seconds) rpo_target_seconds="${2:?}"; shift 2 ;;
        --keep) keep_target=1; shift ;;
        --empty-target) empty_target=1; shift ;;
        -h|--help) usage ;;
        *) die "unknown argument: $1" ;;
    esac
done

base_dsn="${CTFGEN_TEST_DATABASE_URL:-${CTFGEN_DATABASE_URL:-}}"
[ -n "$base_dsn" ] || die "set CTFGEN_TEST_DATABASE_URL (or CTFGEN_DATABASE_URL) to a reachable PostgreSQL"
container="${CTFGEN_PG_DOCKER_CONTAINER:-ctfgen_pg_epic1}"

pybin="${CTFGEN_PYTHON:-$_repo/.venv/bin/python3}"
[ -x "$pybin" ] || pybin="python3"
export PYTHONPATH="$_repo/src${PYTHONPATH:+:$PYTHONPATH}"

require_cmd docker
require_cmd tar
require_cmd sha256sum

# The pg tools run INSIDE the container; forward the connection as PG* env so no
# credential is ever on argv (secret-free), and connect to 127.0.0.1 in-container.
docker exec "$container" pg_dump --version >/dev/null 2>&1 \
    || die "postgres container '$container' unreachable (docker exec pg_dump failed)"

# Derive PG* connection parts from the base DSN, secret-free, via python.
eval "$("$pybin" - "$base_dsn" <<'PY'
import sys
from sqlalchemy.engine import make_url
u = make_url(sys.argv[1])
print(f"PG_USER={u.username or ''}")
print(f"PG_PASSWORD={u.password or ''}")
print(f"PG_HOST={u.host or '127.0.0.1'}")
print(f"PG_PORT={u.port or 5432}")
PY
)"

suffix="$("$pybin" -c 'import uuid;print(uuid.uuid4().hex[:12])')"
source_db="ctfgen_drill_src_${suffix}"
target_db="ctfgen_drill_tgt_${suffix}"

derive_dsn() {  # derive_dsn DBNAME -> a full DSN for that db (password included)
    "$pybin" - "$base_dsn" "$1" <<'PY'
import sys
from sqlalchemy.engine import make_url
print(make_url(sys.argv[1]).set(database=sys.argv[2]).render_as_string(hide_password=False))
PY
}
source_dsn="$(derive_dsn "$source_db")"
target_dsn="$(derive_dsn "$target_db")"

work="$(mktemp -d -t ctfgen-drill-XXXXXX)"
src_store="$(mktemp -d -t ctfgen-drill-src-store-XXXXXX)"
tgt_store="$(mktemp -d -t ctfgen-drill-tgt-store-XXXXXX)"

# Admin op against the maintenance database (CREATE/DROP a throwaway db).
admin_sql() {
    "$pybin" - "$base_dsn" "$1" <<'PY'
import sys
import sqlalchemy as sa
from sqlalchemy.engine import make_url
base = make_url(sys.argv[1])
eng = sa.create_engine(base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True)
try:
    with eng.connect() as c:
        c.execute(sa.text(sys.argv[2]))
finally:
    eng.dispose()
PY
}

cleanup() {
    set +e
    admin_sql "DROP DATABASE IF EXISTS \"$source_db\" WITH (FORCE)" 2>/dev/null
    if [ "$keep_target" -ne 1 ]; then
        admin_sql "DROP DATABASE IF EXISTS \"$target_db\" WITH (FORCE)" 2>/dev/null
    fi
    rm -rf "$work" "$src_store" "$tgt_store"
}
trap cleanup EXIT

printf '== CTFGenerator recovery drill ==\n'
printf 'source=%s  target=%s  container=%s\n' "$source_db" "$target_db" "$container"
printf 'RTO SLO=%ss (gate)   RPO target=%ss (baseline-only, NOT a gate)\n\n' \
    "$rto_slo_seconds" "$rpo_target_seconds"

# --- 1) SEED a known state into SOURCE --------------------------------------

printf '[1/5] seeding known state into %s ...\n' "$source_db"
newest_ts="$(
    SRC_DSN="$source_dsn" SRC_STORE="$src_store" REPO_ROOT="$_repo" \
    "$pybin" - <<'PY'
import os, hashlib
from datetime import datetime, timedelta, UTC
import sqlalchemy as sa
from sqlalchemy.engine import make_url
from alembic import command
from alembic.config import Config as AlembicConfig
from ctf_generator.infrastructure.database.config import DatabaseConfig
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.artifacts.local_store import LocalFilesystemArtifactStore
from ctf_generator.application.scoring.projector import ScoreProjector
from ctf_generator.domain.audit.models import AuditEvent
from ctf_generator.domain.authoring.models import (
    ChallengeBuild, ChallengeDefinition, ChallengePublication, ChallengeVersion,
)
from ctf_generator.domain.challenges.models import CompetitionConfig
from ctf_generator.domain.identity.models import Team
from ctf_generator.domain.ledger.models import ScoreEvent
from ctf_generator.infrastructure.database.audit_repository import SqlAlchemyAuditRepository
from ctf_generator.infrastructure.database.challenge_build_repository import SqlAlchemyChallengeBuildRepository
from ctf_generator.infrastructure.database.challenge_definition_repository import SqlAlchemyChallengeDefinitionRepository
from ctf_generator.infrastructure.database.challenge_publication_repository import SqlAlchemyChallengePublicationRepository
from ctf_generator.infrastructure.database.challenge_version_repository import SqlAlchemyChallengeVersionRepository
from ctf_generator.infrastructure.database.competition_repository import SqlAlchemyCompetitionRepository
from ctf_generator.infrastructure.database.score_ledger_repository import SqlAlchemyScoreLedger
from ctf_generator.infrastructure.database.team_repository import SqlAlchemyTeamRepository

dsn = os.environ["SRC_DSN"]; store_root = os.environ["SRC_STORE"]; repo = os.environ["REPO_ROOT"]
base = make_url(dsn)

# create + migrate the throwaway source database
admin = sa.create_engine(base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True)
with admin.connect() as c:
    c.execute(sa.text(f'CREATE DATABASE "{base.database}"'))
admin.dispose()
cfg = AlembicConfig(os.path.join(repo, "alembic.ini"))
cfg.set_main_option("script_location", os.path.join(repo, "alembic"))
cfg.set_main_option("sqlalchemy.url", dsn)
command.upgrade(cfg, "head")

# Real "now"-relative timestamps so the reported RPO (backup age minus newest
# datum) is a genuine fresh-backup staleness of a few seconds, not an artifact of
# a hardcoded date.
t0 = datetime.now(UTC).replace(microsecond=0)
slug = "cup"
spec_sha = "spec-sha-" + "0" * 55
db = Database(DatabaseConfig(url=dsn))
with db.session_scope() as s:
    SqlAlchemyCompetitionRepository(s).add(CompetitionConfig(
        competition_id=slug, name="Cup",
        start_time=t0 - timedelta(minutes=1), end_time=t0 + timedelta(hours=48)))
    for team in ("Red", "Blue"):
        SqlAlchemyTeamRepository(s).add(Team(slug, team))
    SqlAlchemyChallengeDefinitionRepository(s).add(
        ChallengeDefinition(family="web", slug="sql", title="SQL"))
    SqlAlchemyChallengeVersionRepository(s).add(ChallengeVersion(
        definition_slug="sql", version_no=1, state="draft", family_version="1.0",
        seed="s", spec_sha256=spec_sha, spec={"t": 1}, spec_version="1.0"))
with db.session_scope() as s:
    SqlAlchemyChallengeVersionRepository(s).publish("sql", 1, t0)
with db.session_scope() as s:
    SqlAlchemyChallengePublicationRepository(s).add(ChallengePublication(
        competition_id=slug, definition_slug="sql", version_no=1,
        initial_value=500, minimum_value=500, decay_function="static",
        first_blood_enabled=False))

tar_bytes = b"PK\x00\x00 pretend challenge build tarball " + os.urandom(16)
content_hash = hashlib.sha256(tar_bytes).hexdigest()
storage_uri = f"builds/{content_hash[:2]}/{content_hash}.tar"
build_sha256 = hashlib.sha256(f"{spec_sha}:{content_hash}".encode()).hexdigest()
LocalFilesystemArtifactStore(store_root).put(storage_uri, tar_bytes)
with db.session_scope() as s:
    SqlAlchemyChallengeBuildRepository(s).add(ChallengeBuild(
        build_sha256=build_sha256, definition_slug="sql", version_no=1, family="web",
        seed="s", spec_sha256=spec_sha, generator_version="gen-1",
        manifest={"files": ["public/readme.txt"]}, family_version="1.0",
        storage_uri=storage_uri))

def ev(team, type_, ts):
    return ScoreEvent(competition_id=slug, team_name=team, definition_slug="sql",
                      version_no=1, type=type_, ts=ts.isoformat())
# The newest recoverable datum is timestamped at t0 (seed start); the backup runs
# a few seconds later, so the reported baseline staleness = backup_created_at - t0
# is a genuine, non-negative few-seconds number for this fresh snapshot.
newest = t0
with db.session_scope() as s:
    ledger = SqlAlchemyScoreLedger(s)
    ledger.append(ev("Red", "submission", t0 - timedelta(seconds=2)))
    ledger.append(ev("Red", "solve", t0 - timedelta(seconds=1)))
    ledger.append(ev("Blue", "solve", newest))
with db.session_scope() as s:
    import uuid
    SqlAlchemyAuditRepository(s).add(AuditEvent(
        audit_event_id=str(uuid.uuid4()), actor="organizer:alice",
        action="publication.create", target="cup/sql/v1", outcome="success",
        request_id="req-drill", occurred_at=t0))
ScoreProjector(db).run_until_drained()
db.dispose()
# The single value bash captures: the newest recoverable datum's timestamp.
print(newest.isoformat())
PY
)"
[ -n "$newest_ts" ] || die "seed step produced no newest-timestamp (seeding failed)"
printf '      seeded; newest recoverable datum at %s\n\n' "$newest_ts"

# --- 2) BACKUP (dump + tar + MANIFEST) --------------------------------------

printf '[2/5] backing up %s (logical pg_dump -Fc + artifact tar + MANIFEST) ...\n' "$source_db"
backup_created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Streaming logical custom-format dump over docker exec (see HOST NOTE). The dump
# bytes cross the container boundary via stdout to a HOST file.
docker exec -e "PGPASSWORD=${PG_PASSWORD}" "$container" \
    pg_dump --format=custom -h 127.0.0.1 -U "$PG_USER" "$source_db" >"$work/db.dump"
[ -s "$work/db.dump" ] || die "pg_dump produced an empty dump"

tar -cf "$work/artifacts.tar" -C "$src_store" .

# MANIFEST in the exact KEY=VALUE format scripts/backup.sh writes + verify.py reads.
SRC_DSN="$source_dsn" WORK="$work" BACKUP_TS="$backup_created_at" \
    "$pybin" - <<'PY'
import os
import sqlalchemy as sa
from ctf_generator.infrastructure.database.config import DatabaseConfig
from ctf_generator.infrastructure.database.session import Database
db = Database(DatabaseConfig(url=os.environ["SRC_DSN"]))
with db.session_scope() as s:
    rev = s.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one()
    n = s.execute(sa.text("SELECT count(*) FROM score_events")).scalar_one()
    mx = s.execute(sa.text("SELECT coalesce(max(seq),0) FROM score_events")).scalar_one()
    au = s.execute(sa.text("SELECT count(*) FROM audit_events")).scalar_one()
db.dispose()
with open(os.path.join(os.environ["WORK"], "MANIFEST"), "w", encoding="utf-8") as h:
    h.write(f"backup_created_at={os.environ['BACKUP_TS']}\n")
    h.write(f"db_revision={rev}\n")
    h.write(f"score_events_count={n}\n")
    h.write(f"score_events_max_seq={mx}\n")
    h.write(f"audit_events_count={au}\n")
PY
expected_score_count="$(sed -n 's/^score_events_count=//p' "$work/MANIFEST")"
printf '      backup at %s; %s ledger events captured\n\n' "$backup_created_at" "$expected_score_count"

# --- 3) SIMULATE LOSS -------------------------------------------------------

printf '[3/5] simulating loss: dropping source %s (only the backup survives) ...\n\n' "$source_db"
admin_sql "DROP DATABASE IF EXISTS \"$source_db\" WITH (FORCE)"

# --- 4) RESTORE (TIMED) -----------------------------------------------------

# Fresh empty target. In --empty-target mode we deliberately DO NOT restore into
# it, to prove the drill's verification catches a no-op recovery.
admin_sql "CREATE DATABASE \"$target_db\""

if [ "$empty_target" -eq 1 ]; then
    printf '[4/5] NEGATIVE CONTROL (--empty-target): verifying an EMPTY target (no restore) ...\n'
    restore_block="CTFGEN_DATABASE_URL='$target_dsn' '$pybin' -m ctf_generator.application.backup.verify --manifest '$work/MANIFEST'"
else
    printf '[4/5] restoring into fresh target %s and TIMING to verified-usable ...\n' "$target_db"
    # The FULL recovery path, timed as one wall-clock: pg_restore -> extract
    # artifacts -> verify.py (migration head, ledger, scoreboard parity, artifact
    # hashes). Recovery is not "done" until verify passes, so verify is inside the
    # clock. verify exits nonzero on any failed check -> propagates as the block rc.
    restore_block="set -e
docker exec -i -e 'PGPASSWORD=${PG_PASSWORD}' '$container' pg_restore --no-owner --no-privileges -h 127.0.0.1 -U '$PG_USER' -d '$target_db' <'$work/db.dump'
mkdir -p '$tgt_store'
tar -xf '$work/artifacts.tar' -C '$tgt_store'
CTFGEN_DATABASE_URL='$target_dsn' CTFGEN_ARTIFACT_ROOT='$tgt_store' '$pybin' -m ctf_generator.application.backup.verify --manifest '$work/MANIFEST' --artifact-root '$tgt_store'"
fi

# Explicit perf_counter clock around the restore block (via python, per spec).
rto_file="$work/rto_seconds"
set +e
"$pybin" - "$rto_file" bash -c "$restore_block" <<'PY'
import subprocess, sys, time
out, cmd = sys.argv[1], sys.argv[2:]
t = time.perf_counter()
rc = subprocess.run(cmd).returncode
with open(out, "w", encoding="utf-8") as h:
    h.write("%.4f" % (time.perf_counter() - t))
sys.exit(rc)
PY
restore_rc=$?
set -e
rto_seconds="$(cat "$rto_file" 2>/dev/null || echo 0)"

if [ "$empty_target" -eq 1 ]; then
    printf '\n[5/5] result (NEGATIVE CONTROL):\n'
    if [ "$restore_rc" -eq 0 ]; then
        die "FALSE GREEN: verify PASSED against an EMPTY target -- the drill would not catch a no-op restore"
    fi
    printf '  NO-OP RESTORE correctly BREACHED: verify.py FAILED against the empty target\n'
    printf '  (a restore that loaded no rows is caught -- the check asserts real data, not a tautology)\n'
    exit 1
fi

if [ "$restore_rc" -ne 0 ]; then
    die "restore/verify FAILED (rc=$restore_rc) -- recovery did not reach a verified-usable state"
fi

# --- 5) MEASURE + ASSERT ----------------------------------------------------

printf '\n[5/5] measurement:\n'
BACKUP_TS="$backup_created_at" NEWEST_TS="$newest_ts" \
RTO_SECONDS="$rto_seconds" RTO_SLO="$rto_slo_seconds" \
RPO_TARGET="$rpo_target_seconds" TGT_DSN="$target_dsn" \
EXPECT_SCORE_COUNT="$expected_score_count" \
    "$pybin" - <<'PY'
import os, sys
from datetime import datetime
import sqlalchemy as sa
from ctf_generator.infrastructure.database.config import DatabaseConfig
from ctf_generator.infrastructure.database.session import Database

rto = float(os.environ["RTO_SECONDS"])
rto_slo = float(os.environ["RTO_SLO"])
rpo_target = float(os.environ["RPO_TARGET"])
backup = datetime.fromisoformat(os.environ["BACKUP_TS"].replace("Z", "+00:00"))
newest = datetime.fromisoformat(os.environ["NEWEST_TS"])
rpo = (backup - newest).total_seconds()  # baseline snapshot staleness
expect = int(os.environ["EXPECT_SCORE_COUNT"])

# NO-OP GUARD: assert the recovered target actually holds the seeded ledger rows.
# A restore that silently loaded nothing (0 rows) is a no-op; MANIFEST parity in
# verify.py already caught it, but we re-assert here on real row counts so the
# drill's success is anchored to observed data, never a tautology.
db = Database(DatabaseConfig(url=os.environ["TGT_DSN"]))
with db.session_scope() as s:
    got = int(s.execute(sa.text("SELECT count(*) FROM score_events")).scalar_one())
db.dispose()

print(f"  restore row parity : target has {got} score_events (backup had {expect})")
print(f"  RPO (baseline snapshot staleness): MEASURED={rpo:.1f}s  TARGET<={rpo_target:.0f}s  [BASELINE-ONLY, NOT A GATE]")
print(f"  RTO (restore -> verified-usable) : MEASURED={rto:.3f}s  TARGET<={rto_slo:.0f}s  {'PASS' if rto <= rto_slo else 'BREACH'}")
print("  NOTE: continuous RPO<=5min (REQ-NFR-006) needs WAL/PITR (NOT configured here)")
print("        -> UNVERIFIED (charter section 5); this drill VALIDATES RTO (REQ-NFR-007) end to end.")
print("  NOTE: RTO measured on a small representative slice; production-data-volume RTO")
print("        is UNVERIFIED here (charter section 5) -- the gate proves the recovery")
print("        mechanism + wall-clock, not the restore time at production scale.")

breach = False
if got == 0 or got != expect:
    print(f"  BREACH: recovered target ledger row count {got} != backup {expect} (restore was a no-op / lossy)")
    breach = True
if rto > rto_slo:
    print(f"  BREACH: measured RTO {rto:.3f}s exceeds SLO {rto_slo:.0f}s")
    breach = True
sys.exit(1 if breach else 0)
PY

printf '\nrecovery drill PASSED: RTO within SLO and restore verified against the backup.\n'
if [ "$keep_target" -eq 1 ]; then
    printf 'RECOVERED_TARGET_DB=%s\n' "$target_db"
fi
printf 'MEASURED_RTO_SECONDS=%s\n' "$rto_seconds"
