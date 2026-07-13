"""Restore-verification harness (M17 slice 17a) -- the recovery-drill core.

``verify_restore(database, artifact_store=None, ...)`` runs a battery of
READ-ONLY checks against a *restored* control-plane database (and, optionally,
its content-addressed artifact store) and returns a structured
:class:`VerificationReport`. A restore that recreated the wrong schema, lost or
corrupted ledger/audit rows, restored a scoreboard projection that no longer
matches its ledger, or dropped/corrupted an artifact blob FAILS -- so a green
report is evidence the backup is genuinely RESTORABLE (recoverability /
usability).

SCOPE (honest, per REQ framing): this harness verifies restore INTEGRITY, not the
DR time/loss SLOs. It does NOT measure RPO (REQ-NFR-006, <=5min -- a function of
backup cadence + continuous WAL/PITR, a deployment concern deferred here) nor RTO
(REQ-NFR-007, <=30min -- the wall-clock restore duration, which restore.sh can
time). A green report says "this backup restores to a consistent, usable state",
which is the prerequisite for a valid recovery drill against those SLOs -- not a
measurement of the SLOs themselves.

Design notes (why each check catches corruption without false greens):

* **MIGRATION HEAD** -- ``alembic_version`` must equal
  :data:`CODE_MIGRATION_HEAD`. A restore at the wrong schema revision is
  unusable; a tampered/half-applied ``alembic_version`` fails here.
* **LEDGER SEQ** -- ``score_events.seq`` is a Postgres identity column and the
  ledger is append-only, but seqs are NOT guaranteed contiguous: an aborted
  append *burns* a seq (and rolls back its outbox row too -- see
  ``application/scoring/projector``), so permanent identity gaps are a LEGAL,
  inert state. This check therefore asserts the false-positive-free invariant --
  seqs are strictly monotonic, unique, and >= 1 (a duplicate or non-monotonic
  seq means the PK / identity was not restored) -- and delegates *lost-row*
  detection to ROW-COUNT parity (when a manifest is supplied) and to SCOREBOARD
  PARITY (a lost solve diverges the projection). This deliberately does not
  assert bare contiguity, which would flag a healthy burned-seq ledger.
* **LEDGER / AUDIT ROW-COUNT** (only with a manifest) -- the manifest records the
  source ``score_events`` (count + max seq) and ``audit_events`` counts; a restore
  that silently dropped rows shows a lower count here. A burned-seq gap is
  identical in source and restore, so it is not a false positive. NOTE: the
  manifest counts assume a QUIESCENT backup (no concurrent scoring/audit writes
  during the dump -- take the backup in a maintenance window / with the control
  plane drained; for a HOT backup use continuous WAL/PITR, whose restore is
  inherently snapshot-consistent). Under a quiescent backup the counts equal the
  dump exactly; the race-free authoritative checks (scoreboard parity, artifact
  hash, immutability, migration head) hold regardless.
* **SCOREBOARD PARITY** -- for every competition the stored projection must be
  DERIVABLE from the restored ledger: re-folding the committed ``score_events``
  through the pure ``compute_scoreboard`` (via ``ScoreProjector.dry_project``,
  read-only) must reproduce the stored projection's entries when both fold the
  same event set. A stored projection that is *ahead* of the ledger (references
  events that no longer exist) is a hard fail; a projection merely *behind* the
  ledger is projection lag (rebuildable), not corruption. This is what catches a
  lost/altered solve even with no manifest.
* **ARTIFACT INTEGRITY** (only with an artifact store) -- every
  ``challenge_builds`` row with a ``storage_uri`` is content-addressed: the key
  is ``builds/<sha>/<sha>.tar`` where ``<sha> == sha256(tar_bytes)``
  (materialization keys the blob by its own content hash). The bytes must exist
  in the store AND hash back to the ``<sha>`` the key encodes -- a missing or
  corrupted blob fails.

The harness is strictly READ-ONLY (it opens transactional sessions but only ever
SELECTs; it never writes, and the append-only triggers would reject it if it
tried). Its output is SECRET-FREE by construction: it emits row counts, seqs,
revision ids, competition slugs and sha256 hex -- never a flag, token, password,
DSN, or challenge payload.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import sqlalchemy as sa

from ctf_generator.application.scoring.projector import ScoreProjector
from ctf_generator.infrastructure.database.competition_repository import (
    SqlAlchemyCompetitionRepository,
)
from ctf_generator.infrastructure.database.migrations import CODE_MIGRATION_HEAD
from ctf_generator.infrastructure.database.score_ledger_repository import (
    SqlAlchemyScoreLedger,
)
from ctf_generator.infrastructure.database.score_projection_repository import (
    SqlAlchemyScoreboardProjectionRepository,
)

# The default scoring engine used by the production projector. Parity must fold
# with the SAME engine the persisted projection was computed with, or a healthy
# restore would diverge; this mirrors ``ScoreProjector``'s default.
_DEFAULT_ENGINE = "dynamic_decay"

_SHA256_HEX_LEN = 64


class RestoreVerificationError(RuntimeError):
    """Raised by :meth:`VerificationReport.raise_for_status` when one or more
    restore-verification checks FAILED. Carries the failing report so an
    operator / caller sees exactly which checks failed (secret-free)."""

    def __init__(self, report: VerificationReport) -> None:
        super().__init__(report.summary())
        self.report = report


@dataclass(frozen=True)
class CheckResult:
    """The pass/fail outcome of a single named verification check, with a
    secret-free human detail line."""

    name: str
    passed: bool
    detail: str

    def render(self) -> str:
        return f"[{'PASS' if self.passed else 'FAIL'}] {self.name}: {self.detail}"


@dataclass(frozen=True)
class VerificationReport:
    """The structured result of a restore verification: one
    :class:`CheckResult` per check. ``passed`` is True iff every check passed."""

    checks: tuple[CheckResult, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if not check.passed)

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [f"restore verification: {status} ({len(self.checks)} checks)"]
        lines.extend(check.render() for check in self.checks)
        return "\n".join(lines)

    def raise_for_status(self) -> None:
        """Raise :class:`RestoreVerificationError` iff any check failed."""
        if not self.passed:
            raise RestoreVerificationError(self)


# --- individual checks -------------------------------------------------------
#
# Each check is defensive: any unexpected error becomes a FAIL result (a check
# that cannot complete is not a pass), so a broken restore can never masquerade
# as green by making a check crash.


def _check_migration_head(database) -> CheckResult:
    try:
        with database.session_scope() as session:
            revision = session.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar_one_or_none()
    except Exception as exc:  # noqa: BLE001 - a check that cannot read fails
        return CheckResult(
            "migration_head", False, f"could not read alembic_version: {type(exc).__name__}"
        )
    if revision == CODE_MIGRATION_HEAD:
        return CheckResult("migration_head", True, f"at head {revision}")
    return CheckResult(
        "migration_head",
        False,
        f"restored revision {revision!r} != code head {CODE_MIGRATION_HEAD!r}",
    )


def _read_ledger_seqs(session) -> list[int]:
    rows = session.execute(
        sa.text("SELECT seq FROM score_events ORDER BY seq")
    ).all()
    return [int(seq) for (seq,) in rows]


def _check_ledger_seq(database) -> CheckResult:
    try:
        with database.session_scope() as session:
            seqs = _read_ledger_seqs(session)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "ledger_seq_monotonic", False, f"could not read score_events: {type(exc).__name__}"
        )
    if not seqs:
        return CheckResult("ledger_seq_monotonic", True, "ledger is empty")
    previous = 0
    for seq in seqs:
        if seq < 1:
            return CheckResult(
                "ledger_seq_monotonic", False, f"non-positive seq {seq}"
            )
        if seq <= previous:
            return CheckResult(
                "ledger_seq_monotonic",
                False,
                f"seq not strictly monotonic/unique at {seq} (prev {previous})",
            )
        previous = seq
    return CheckResult(
        "ledger_seq_monotonic",
        True,
        f"{len(seqs)} events, strictly monotonic, max seq {seqs[-1]}",
    )


def _check_ledger_rowcount(database, manifest: Mapping[str, object]) -> CheckResult | None:
    """Row-count / max-seq parity against a source manifest (optional). Returns
    ``None`` when the manifest carries no ledger counters (nothing to check)."""
    expected_count = manifest.get("score_events_count")
    expected_max = manifest.get("score_events_max_seq")
    if expected_count is None and expected_max is None:
        return None
    try:
        with database.session_scope() as session:
            count = session.execute(
                sa.text("SELECT count(*) FROM score_events")
            ).scalar_one()
            max_seq = session.execute(
                sa.text("SELECT coalesce(max(seq), 0) FROM score_events")
            ).scalar_one()
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "ledger_rowcount", False, f"could not read score_events: {type(exc).__name__}"
        )
    if expected_count is not None and int(count) != int(expected_count):
        return CheckResult(
            "ledger_rowcount",
            False,
            f"row count {count} != manifest {int(expected_count)} (rows lost/added)",
        )
    if expected_max is not None and int(max_seq) != int(expected_max):
        return CheckResult(
            "ledger_rowcount",
            False,
            f"max seq {max_seq} != manifest {int(expected_max)}",
        )
    return CheckResult(
        "ledger_rowcount", True, f"row count {count} + max seq {max_seq} match manifest"
    )


def _check_audit_rowcount(database, manifest: Mapping[str, object]) -> CheckResult | None:
    """Completeness of the append-only, tamper-evident audit trail against the
    manifest count (optional; None when the manifest carries no audit counter).
    audit_events has no projection to cross-check, so a dropped audit row is
    detectable ONLY by this count (same quiescent-backup assumption as the ledger
    row-count check)."""
    expected = manifest.get("audit_events_count")
    if expected is None:
        return None
    try:
        with database.session_scope() as session:
            count = session.execute(
                sa.text("SELECT count(*) FROM audit_events")
            ).scalar_one()
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "audit_rowcount", False, f"could not read audit_events: {type(exc).__name__}"
        )
    if int(count) != int(expected):
        return CheckResult(
            "audit_rowcount",
            False,
            f"audit row count {count} != manifest {int(expected)} (audit rows lost)",
        )
    return CheckResult("audit_rowcount", True, f"audit row count {count} matches manifest")


def _canonical(entries: Mapping[str, object]) -> str:
    # JSONB round-trips at the value level; normalize both sides through
    # canonical JSON so key order / tuple-vs-list can't cause a false mismatch.
    return json.dumps(entries, sort_keys=True, default=str)


def _check_scoreboard_parity(database, engine_name: str) -> CheckResult:
    projector = ScoreProjector(database, engine_name=engine_name)
    try:
        with database.session_scope() as session:
            competitions = [c.competition_id for c in SqlAlchemyCompetitionRepository(session).list()]
            ledger = SqlAlchemyScoreLedger(session)
            projections = SqlAlchemyScoreboardProjectionRepository(session)
            checked = 0
            for slug in competitions:
                events = ledger.list_for_competition(slug)
                stored = projections.get(slug)
                if not events:
                    # A projection with NO ledger events is an ORPHAN -- the
                    # restore lost that competition's entire ledger while keeping
                    # its projection (as_of_seq references vanished events). Must
                    # fail; skipping it (the old behaviour) was a false green.
                    if stored is not None and stored.as_of_seq > 0:
                        return CheckResult(
                            "scoreboard_parity",
                            False,
                            f"competition {slug!r} has a projection "
                            f"(as_of_seq {stored.as_of_seq}) but ZERO ledger "
                            "events -- ledger rows lost",
                        )
                    continue
                checked += 1
                if stored is None:
                    return CheckResult(
                        "scoreboard_parity",
                        False,
                        f"competition {slug!r} has {len(events)} ledger events "
                        "but no restored projection",
                    )
                refold = projector.dry_project(session, slug)
                if stored.as_of_seq > refold.as_of_seq:
                    return CheckResult(
                        "scoreboard_parity",
                        False,
                        f"competition {slug!r} projection as_of_seq "
                        f"{stored.as_of_seq} is AHEAD of ledger max "
                        f"{refold.as_of_seq} (ledger rows lost)",
                    )
                if stored.as_of_seq < refold.as_of_seq:
                    # Projection legitimately lags the ledger (pending events at
                    # backup time); rebuildable, not corruption. Do not strictly
                    # compare entries (we do not bound-fold here).
                    continue
                if _canonical(stored.entries) != _canonical(refold.entries):
                    return CheckResult(
                        "scoreboard_parity",
                        False,
                        f"competition {slug!r} restored projection does not match "
                        f"a re-fold of its ledger at seq {stored.as_of_seq}",
                    )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "scoreboard_parity", False, f"parity check errored: {type(exc).__name__}: {exc}"
        )
    return CheckResult(
        "scoreboard_parity",
        True,
        f"{checked} competition projection(s) derivable from the restored ledger",
    )


def _content_hash_from_key(storage_uri: str) -> str | None:
    """The content address a build key encodes: ``builds/<sha>/<sha>.tar`` ->
    ``<sha>``. Returns ``None`` if the key is not the expected shape (so the
    caller fails loud rather than silently passing an unrecognizable key)."""
    name = PurePosixPath(storage_uri).name
    if not name.endswith(".tar"):
        return None
    stem = name[: -len(".tar")]
    if len(stem) != _SHA256_HEX_LEN:
        return None
    try:
        int(stem, 16)
    except ValueError:
        return None
    return stem.lower()


def _check_artifact_integrity(database, artifact_store) -> CheckResult:
    try:
        return _artifact_integrity(database, artifact_store)
    except Exception as exc:  # noqa: BLE001 - any store/DB error is a FAIL, not a crash
        return CheckResult(
            "artifact_integrity", False, f"artifact check errored: {type(exc).__name__}"
        )


def _artifact_integrity(database, artifact_store) -> CheckResult:
    with database.session_scope() as session:
        rows = session.execute(
            sa.text(
                "SELECT build_sha256, storage_uri FROM challenge_builds "
                "WHERE storage_uri IS NOT NULL"
            )
        ).all()
    checked = 0
    for build_sha256, storage_uri in rows:
        expected = _content_hash_from_key(storage_uri)
        if expected is None:
            return CheckResult(
                "artifact_integrity",
                False,
                f"build {build_sha256[:12]} has an unrecognizable storage key",
            )
        data = artifact_store.get(storage_uri)
        if data is None:
            return CheckResult(
                "artifact_integrity",
                False,
                f"artifact for build {build_sha256[:12]} is MISSING from the store",
            )
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            return CheckResult(
                "artifact_integrity",
                False,
                f"artifact for build {build_sha256[:12]} is CORRUPTED "
                f"(content hash {actual[:12]} != key {expected[:12]})",
            )
        checked += 1
    return CheckResult(
        "artifact_integrity", True, f"{checked} artifact blob(s) present and content-verified"
    )


def verify_restore(
    database,
    artifact_store=None,
    *,
    manifest: Mapping[str, object] | None = None,
    engine_name: str = _DEFAULT_ENGINE,
) -> VerificationReport:
    """Run the full read-only restore-verification battery and return a
    structured report (call :meth:`VerificationReport.raise_for_status` to turn a
    failure into an exception).

    ``database`` is a restored :class:`Database`. ``artifact_store`` (optional)
    enables the artifact-integrity check. ``manifest`` (optional, e.g. the
    ``MANIFEST`` a backup wrote) enables ledger row-count parity. ``engine_name``
    must match the scoring engine the persisted projections were computed with.
    """
    checks: list[CheckResult] = [
        _check_migration_head(database),
        _check_ledger_seq(database),
    ]
    if manifest is not None:
        rowcount = _check_ledger_rowcount(database, manifest)
        if rowcount is not None:
            checks.append(rowcount)
        audit_rowcount = _check_audit_rowcount(database, manifest)
        if audit_rowcount is not None:
            checks.append(audit_rowcount)
    checks.append(_check_scoreboard_parity(database, engine_name))
    if artifact_store is not None:
        checks.append(_check_artifact_integrity(database, artifact_store))
    return VerificationReport(tuple(checks))


# --- operator CLI ------------------------------------------------------------


def _load_manifest(path: str | None) -> Mapping[str, object] | None:
    if not path:
        return None
    import os

    if not os.path.exists(path):
        return None
    ledger: dict[str, object] = {}
    # The backup MANIFEST is a simple ``KEY=VALUE`` text file (secret-free); read
    # only the ledger counters this harness understands, ignore the rest.
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key in {"score_events_count", "score_events_max_seq"}:
                try:
                    ledger[key] = int(value)
                except ValueError:
                    continue
    return ledger or None


def main(argv: list[str] | None = None) -> int:
    """Standalone operator entry: verify the restored DB named by
    ``CTFGEN_DATABASE_URL`` (and the artifact store at ``CTFGEN_ARTIFACT_ROOT``
    if set). Prints a secret-free report; exits 0 on PASS, 1 on FAIL, 2 on a
    configuration error. ``restore.sh`` invokes this."""
    import argparse
    import os

    from ctf_generator.infrastructure.database.config import (
        DatabaseConfig,
        DatabaseConfigError,
    )
    from ctf_generator.infrastructure.database.session import Database

    parser = argparse.ArgumentParser(
        prog="python -m ctf_generator.application.backup.verify",
        description="Verify a restored CTFGenerator database (read-only).",
    )
    parser.add_argument(
        "--manifest",
        default=os.environ.get("CTFGEN_BACKUP_MANIFEST"),
        help="optional backup MANIFEST for ledger row-count parity",
    )
    parser.add_argument(
        "--artifact-root",
        default=os.environ.get("CTFGEN_ARTIFACT_ROOT"),
        help="artifact store root (enables artifact-integrity check)",
    )
    parser.add_argument(
        "--engine",
        default=_DEFAULT_ENGINE,
        help=f"scoring engine the projections were computed with (default {_DEFAULT_ENGINE})",
    )
    args = parser.parse_args(argv)

    try:
        config = DatabaseConfig.from_env()
    except DatabaseConfigError as exc:
        # Never echoes the DSN; only the missing-var message.
        print(f"configuration error: {exc}")
        return 2
    database = Database(config)

    artifact_store = None
    if args.artifact_root:
        from ctf_generator.infrastructure.artifacts.local_store import (
            LocalFilesystemArtifactStore,
        )

        artifact_store = LocalFilesystemArtifactStore(args.artifact_root)

    try:
        report = verify_restore(
            database,
            artifact_store=artifact_store,
            manifest=_load_manifest(args.manifest),
            engine_name=args.engine,
        )
    finally:
        database.dispose()

    print(report.summary())
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover - exercised via the CLI
    raise SystemExit(main())
