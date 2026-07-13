"""Real backup -> restore -> verify round-trip for M17 slice 17a.

Docker-gated. Seeds a representative slice into a SOURCE database + a real
on-disk artifact store, performs a GENUINE pg_dump(--format=custom)/pg_restore
into a FRESH TARGET database (a real logical dump + restore, NOT a SQLAlchemy
ORM clone) plus a real tar round-trip of the artifact store, then drives
``verify_restore`` against the TARGET.

Positive: every check (migration head, ledger seq, ledger row-count parity,
scoreboard parity, artifact integrity) PASSES, and the restore PRESERVED the
append-only immutability triggers (an UPDATE on a restored audit / ledger row is
still rejected).

Negative controls (each must make the verifier FAIL -- no false green):
  (a) a wrong ``alembic_version``            -> migration-head check fails
  (b) a deleted ``score_events`` row (gap)   -> ledger row-count + scoreboard fail
  (c) a deleted artifact blob                -> artifact-integrity check fails

pg_dump / pg_restore run on the host if present, else via ``docker exec`` into
the postgres:16 container (default ``ctfgen_pg_epic1``, overridable with
``CTFGEN_PG_DOCKER_CONTAINER``). This is why the round-trip is real: the rows
travel through Postgres's own dump/restore, not through Python objects.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_restore_verify_integration
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ProgrammingError

    from ctf_generator.application.backup.verify import (
        RestoreVerificationError,
        verify_restore,
    )
    from ctf_generator.application.scoring.projector import ScoreProjector
    from ctf_generator.domain.audit.models import AuditEvent
    from ctf_generator.domain.authoring.models import (
        ChallengeBuild,
        ChallengeDefinition,
        ChallengePublication,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.ledger.models import ScoreEvent
    from ctf_generator.infrastructure.artifacts.local_store import (
        LocalFilesystemArtifactStore,
    )
    from ctf_generator.infrastructure.database.audit_repository import (
        SqlAlchemyAuditRepository,
    )
    from ctf_generator.infrastructure.database.challenge_build_repository import (
        SqlAlchemyChallengeBuildRepository,
    )
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_publication_repository import (
        SqlAlchemyChallengePublicationRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.competition_repository import (
        SqlAlchemyCompetitionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.score_ledger_repository import (
        SqlAlchemyScoreLedger,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_CONTAINER = os.environ.get("CTFGEN_PG_DOCKER_CONTAINER", "ctfgen_pg_epic1")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SPEC_SHA = "spec-sha-" + "0" * 55  # 64-ish; only equality vs the version matters
_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _host_pg() -> bool:
    return bool(shutil.which("pg_dump")) and bool(shutil.which("pg_restore"))


def _docker_pg() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(
            ["docker", "exec", _CONTAINER, "pg_dump", "--version"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return True
    except Exception:
        return False


_TOOLING = _host_pg() or (_TEST_URL is not None and _docker_pg())
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL) and _TOOLING
if _IMPORT_ERROR is not None:
    _SKIP_REASON = f"db extra not importable ({_IMPORT_ERROR})"
elif not _TEST_URL:
    _SKIP_REASON = "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
elif not _TOOLING:
    _SKIP_REASON = (
        f"no pg_dump/pg_restore on host and container {_CONTAINER!r} unreachable"
    )
else:
    _SKIP_REASON = ""


def _conn_params():
    u = make_url(_TEST_URL)
    return u.username or "", u.password or "", u.host or "localhost", str(u.port or 5432)


def _pg_dump(dbname: str) -> bytes:
    user, password, host, port = _conn_params()
    if _host_pg():
        env = {**os.environ, "PGPASSWORD": password}
        cmd = ["pg_dump", "-h", host, "-p", port, "-U", user, "-Fc", dbname]
        return subprocess.run(cmd, env=env, check=True, stdout=subprocess.PIPE).stdout
    cmd = [
        "docker", "exec", "-e", f"PGPASSWORD={password}", _CONTAINER,
        "pg_dump", "-h", "127.0.0.1", "-U", user, "-Fc", dbname,
    ]
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE).stdout


def _pg_restore(dbname: str, dump: bytes) -> None:
    user, password, host, port = _conn_params()
    if _host_pg():
        env = {**os.environ, "PGPASSWORD": password}
        cmd = [
            "pg_restore", "--no-owner", "--no-privileges",
            "-h", host, "-p", port, "-U", user, "-d", dbname,
        ]
        subprocess.run(cmd, env=env, input=dump, check=True)
        return
    cmd = [
        "docker", "exec", "-i", "-e", f"PGPASSWORD={password}", _CONTAINER,
        "pg_restore", "--no-owner", "--no-privileges",
        "-h", "127.0.0.1", "-U", user, "-d", dbname,
    ]
    subprocess.run(cmd, input=dump, check=True)


@contextmanager
def _admin_engine():
    base = make_url(_TEST_URL)
    engine = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        yield engine, base
    finally:
        engine.dispose()


def _alembic_config(url: str) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


def _tar_dir(root: str) -> bytes:
    """A real tar of the artifact store (mirrors backup.sh's artifacts.tar)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(root, arcname=".")
    return buf.getvalue()


def _untar_into(data: bytes, root: str) -> None:
    os.makedirs(root, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
        tar.extractall(root)  # noqa: S202 - trusted, self-produced archive


def _seed(db: Database, artifact_root: str) -> dict:
    """Seed a representative slice; return provenance the tests assert on."""
    slug = "cup"
    with db.session_scope() as s:
        SqlAlchemyCompetitionRepository(s).add(
            CompetitionConfig(
                competition_id=slug,
                name="Cup",
                start_time=_NOW,
                end_time=_NOW + timedelta(hours=48),
            )
        )
        for team in ("Red", "Blue"):
            SqlAlchemyTeamRepository(s).add(Team(slug, team))
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family="web", slug="sql", title="SQL")
        )
        SqlAlchemyChallengeVersionRepository(s).add(
            ChallengeVersion(
                definition_slug="sql",
                version_no=1,
                state="draft",
                family_version="1.0",
                seed="s",
                spec_sha256=_SPEC_SHA,
                spec={"t": 1},
                spec_version="1.0",
            )
        )
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish("sql", 1, _NOW)
    with db.session_scope() as s:
        SqlAlchemyChallengePublicationRepository(s).add(
            ChallengePublication(
                competition_id=slug,
                definition_slug="sql",
                version_no=1,
                initial_value=500,
                minimum_value=500,
                decay_function="static",
                first_blood_enabled=False,
            )
        )

    # A materialized build backed by real bytes in a real content-addressed store.
    tar_bytes = b"PK\x00\x00 pretend challenge build tarball " + os.urandom(16)
    content_hash = hashlib.sha256(tar_bytes).hexdigest()
    storage_uri = f"builds/{content_hash[:2]}/{content_hash}.tar"
    build_sha256 = hashlib.sha256(f"{_SPEC_SHA}:{content_hash}".encode()).hexdigest()
    store = LocalFilesystemArtifactStore(artifact_root)
    store.put(storage_uri, tar_bytes)
    with db.session_scope() as s:
        SqlAlchemyChallengeBuildRepository(s).add(
            ChallengeBuild(
                build_sha256=build_sha256,
                definition_slug="sql",
                version_no=1,
                family="web",
                seed="s",
                spec_sha256=_SPEC_SHA,
                generator_version="gen-1",
                manifest={"files": ["public/readme.txt"]},
                family_version="1.0",
                storage_uri=storage_uri,
            )
        )

    # Ledger: a submission (provenance) + two solves drive the scoreboard.
    with db.session_scope() as s:
        ledger = SqlAlchemyScoreLedger(s)
        ledger.append(_score_event("Red", "submission"))
        ledger.append(_score_event("Red", "solve", _NOW + timedelta(minutes=5)))
        ledger.append(_score_event("Blue", "solve", _NOW + timedelta(minutes=9)))

    audit_id = str(uuid.uuid4())
    with db.session_scope() as s:
        SqlAlchemyAuditRepository(s).add(
            AuditEvent(
                audit_event_id=audit_id,
                actor="organizer:alice",
                action="publication.create",
                target="cup/sql/v1",
                outcome="success",
                request_id="req-123",
                occurred_at=_NOW,
            )
        )

    # Drain the projector so scoreboard_projections is at head before backup.
    ScoreProjector(db).run_until_drained()
    return {
        "slug": slug,
        "audit_id": audit_id,
        "storage_uri": storage_uri,
        "content_hash": content_hash,
    }


def _score_event(team: str, type_: str, ts: datetime = _NOW) -> ScoreEvent:
    return ScoreEvent(
        competition_id="cup",
        team_name=team,
        definition_slug="sql",
        version_no=1,
        type=type_,
        ts=ts.isoformat(),
    )


def _manifest_from_source(db: Database) -> dict:
    with db.session_scope() as s:
        count = s.execute(sa.text("SELECT count(*) FROM score_events")).scalar_one()
        max_seq = s.execute(
            sa.text("SELECT coalesce(max(seq), 0) FROM score_events")
        ).scalar_one()
        audit = s.execute(sa.text("SELECT count(*) FROM audit_events")).scalar_one()
    return {
        "score_events_count": int(count),
        "score_events_max_seq": int(max_seq),
        "audit_events_count": int(audit),
    }


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class RestoreRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self._names: list[str] = []
        self._dirs: list[str] = []
        self._databases: list[Database] = []

    def tearDown(self) -> None:
        for db in self._databases:
            db.dispose()
        with _admin_engine() as (engine, _base):
            with engine.connect() as conn:
                for name in self._names:
                    conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        for d in self._dirs:
            shutil.rmtree(d, ignore_errors=True)

    def _new_db_name(self) -> str:
        name = f"ctfgen_dr_{uuid.uuid4().hex[:12]}"
        self._names.append(name)
        return name

    def _url_for(self, name: str) -> str:
        return make_url(_TEST_URL).set(database=name).render_as_string(hide_password=False)

    def _database(self, name: str) -> Database:
        db = Database(DatabaseConfig(url=self._url_for(name)))
        self._databases.append(db)
        return db

    def _tmpdir(self) -> str:
        d = tempfile.mkdtemp(prefix="ctfgen-dr-")
        self._dirs.append(d)
        return d

    def _build_source(self) -> tuple[str, str, dict]:
        """Create + migrate + seed a source DB and its artifact store."""
        source = self._new_db_name()
        with _admin_engine() as (engine, _base):
            with engine.connect() as conn:
                conn.execute(sa.text(f'CREATE DATABASE "{source}"'))
        command.upgrade(_alembic_config(self._url_for(source)), "head")
        src_artifacts = self._tmpdir()
        prov = _seed(self._database(source), src_artifacts)
        prov["src_artifacts"] = src_artifacts
        return source, src_artifacts, prov

    def _restore_into_fresh_target(self, source: str, src_artifacts: str) -> tuple[str, str]:
        """A REAL dump+restore into a brand-new empty target DB + artifact root."""
        dump = _pg_dump(source)
        self.assertGreater(len(dump), 0)
        target = self._new_db_name()
        with _admin_engine() as (engine, _base):
            with engine.connect() as conn:
                conn.execute(sa.text(f'CREATE DATABASE "{target}"'))  # empty
        _pg_restore(target, dump)
        tgt_artifacts = self._tmpdir()
        _untar_into(_tar_dir(src_artifacts), tgt_artifacts)
        return target, tgt_artifacts

    # -- the happy path -------------------------------------------------------

    def test_backup_restore_verify_round_trip_passes(self) -> None:
        source, src_artifacts, prov = self._build_source()
        manifest = _manifest_from_source(self._database(source))
        target, tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)

        target_db = self._database(target)
        report = verify_restore(
            target_db,
            artifact_store=LocalFilesystemArtifactStore(tgt_artifacts),
            manifest=manifest,
        )
        self.assertTrue(report.passed, report.summary())
        names = {c.name for c in report.checks}
        self.assertEqual(
            names,
            {
                "migration_head",
                "ledger_seq_monotonic",
                "ledger_rowcount",
                "audit_rowcount",
                "scoreboard_parity",
                "artifact_integrity",
            },
        )
        report.raise_for_status()  # does not raise

    def test_restore_preserves_append_only_immutability(self) -> None:
        source, src_artifacts, prov = self._build_source()
        target, _tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)
        target_db = self._database(target)

        # The reject_mutation triggers came across with the schema: an UPDATE on a
        # restored audit / ledger row is still rejected.
        with self.assertRaises(ProgrammingError):
            with target_db.session_scope() as s:
                s.execute(
                    sa.text("UPDATE audit_events SET outcome='denied' WHERE id=:i"),
                    {"i": prov["audit_id"]},
                )
        with self.assertRaises(ProgrammingError):
            with target_db.session_scope() as s:
                s.execute(sa.text("UPDATE score_events SET type='freeze' WHERE seq=1"))
        with self.assertRaises(ProgrammingError):
            with target_db.session_scope() as s:
                s.execute(sa.text("DELETE FROM audit_events WHERE id=:i"), {"i": prov["audit_id"]})

    # -- negative controls (verifier must FAIL) -------------------------------

    def test_negative_wrong_migration_head_fails(self) -> None:
        source, src_artifacts, _prov = self._build_source()
        target, tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)
        target_db = self._database(target)

        with target_db.session_scope() as s:
            s.execute(sa.text("UPDATE alembic_version SET version_num='0000_wrong'"))
        report = verify_restore(
            target_db, artifact_store=LocalFilesystemArtifactStore(tgt_artifacts)
        )
        self.assertFalse(report.passed)
        self.assertIn("migration_head", {c.name for c in report.failures()})
        with self.assertRaises(RestoreVerificationError):
            report.raise_for_status()

    def test_negative_ledger_seq_gap_fails(self) -> None:
        source, src_artifacts, _prov = self._build_source()
        manifest = _manifest_from_source(self._database(source))
        target, tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)
        target_db = self._database(target)

        # Inject a ledger gap by DELETING the highest-seq solve row. The
        # append-only trigger forbids DELETE, so bypass it exactly as only a
        # corruption/attacker could -- proving the verifier catches the result.
        with target_db.session_scope() as s:
            s.execute(sa.text("SET session_replication_role = replica"))
            s.execute(
                sa.text(
                    "DELETE FROM score_events WHERE seq = "
                    "(SELECT max(seq) FROM score_events)"
                )
            )
        report = verify_restore(
            target_db,
            artifact_store=LocalFilesystemArtifactStore(tgt_artifacts),
            manifest=manifest,
        )
        self.assertFalse(report.passed)
        failed = {c.name for c in report.failures()}
        # Both the manifest row-count parity and the scoreboard parity notice the
        # lost solve (the projection is now ahead of the ledger).
        self.assertIn("ledger_rowcount", failed)
        self.assertIn("scoreboard_parity", failed)

    def test_negative_audit_row_dropped_fails(self) -> None:
        # audit_events has no projection to cross-check, so a dropped audit row is
        # caught ONLY by the manifest audit-row-count check. Delete one (bypassing
        # the append-only trigger, as only corruption could) -> audit_rowcount FAILS.
        source, src_artifacts, _prov = self._build_source()
        manifest = _manifest_from_source(self._database(source))
        target, tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)
        target_db = self._database(target)
        with target_db.session_scope() as s:
            s.execute(sa.text("SET session_replication_role = replica"))
            s.execute(sa.text("DELETE FROM audit_events WHERE ctid IN "
                              "(SELECT ctid FROM audit_events LIMIT 1)"))
        report = verify_restore(target_db, manifest=manifest)
        self.assertFalse(report.passed)
        self.assertIn("audit_rowcount", {c.name for c in report.failures()})

    def test_negative_projection_entries_tampered_fails(self) -> None:
        # The scoreboard_parity ENTRIES-equality branch (as_of_seq matches the
        # ledger but the rendered entries differ) needs its own control -- the
        # seq-gap test only trips the as_of_seq-ahead branch. Tamper the restored
        # projection's entries while leaving as_of_seq == the ledger max.
        source, src_artifacts, _prov = self._build_source()
        target, tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)
        target_db = self._database(target)
        with target_db.session_scope() as s:
            # scoreboard_projections is a materialized fold (not append-only) --
            # a direct UPDATE simulates a corrupted/altered projection row.
            s.execute(sa.text(
                "UPDATE scoreboard_projections "
                "SET entries = '{\"tampered\": true}'::jsonb"
            ))
        report = verify_restore(target_db, artifact_store=None)
        self.assertFalse(report.passed)
        self.assertIn("scoreboard_parity", {c.name for c in report.failures()})

    def test_negative_orphan_projection_empty_ledger_fails(self) -> None:
        # A restore that lost a competition's ENTIRE ledger but kept its projection
        # (as_of_seq references vanished events) must FAIL scoreboard_parity -- the
        # old code skipped an empty-ledger competition before the projection check.
        source, src_artifacts, _prov = self._build_source()
        target, tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)
        target_db = self._database(target)
        with target_db.session_scope() as s:
            s.execute(sa.text("SET session_replication_role = replica"))
            s.execute(sa.text("DELETE FROM score_events"))  # keep the projection
        report = verify_restore(target_db, artifact_store=None)
        self.assertFalse(report.passed)
        self.assertIn("scoreboard_parity", {c.name for c in report.failures()})

    def test_negative_missing_artifact_fails(self) -> None:
        source, src_artifacts, prov = self._build_source()
        target, tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)
        target_db = self._database(target)

        # Corrupt the restored store: remove the blob the build row points at.
        blob = os.path.join(tgt_artifacts, prov["storage_uri"])
        self.assertTrue(os.path.exists(blob))
        os.remove(blob)
        report = verify_restore(
            target_db, artifact_store=LocalFilesystemArtifactStore(tgt_artifacts)
        )
        self.assertFalse(report.passed)
        self.assertIn("artifact_integrity", {c.name for c in report.failures()})

    def test_negative_corrupted_artifact_bytes_fail(self) -> None:
        source, src_artifacts, prov = self._build_source()
        target, tgt_artifacts = self._restore_into_fresh_target(source, src_artifacts)
        target_db = self._database(target)

        # Overwrite the blob with different bytes (content hash no longer matches
        # the key). Write directly (bypassing the immutable store) as corruption
        # would.
        blob = os.path.join(tgt_artifacts, prov["storage_uri"])
        with open(blob, "wb") as handle:
            handle.write(b"tampered-bytes")
        report = verify_restore(
            target_db, artifact_store=LocalFilesystemArtifactStore(tgt_artifacts)
        )
        self.assertFalse(report.passed)
        self.assertIn("artifact_integrity", {c.name for c in report.failures()})


if __name__ == "__main__":
    unittest.main()
