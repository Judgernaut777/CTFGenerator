"""PostgreSQL integration tests for the gap-safe scoreboard projection (M7).

Proves the transactional outbox resolves the design doc's deferred issue #1:
the two-phase stalled-writer test first *documents the legacy bare-cursor
skip* (``since(seq_b)`` misses the later-committed lower ``seq_a`` forever)
and then shows the projector picks BOTH events up. Docker-gated; skips
cleanly off-Docker.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_score_projection_integration
"""

from __future__ import annotations

import os
import random
import threading
import time
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from unittest import mock

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import IntegrityError, OperationalError
    from sqlalchemy.orm import Session

    from ctf_generator.application.scoring.projector import ScoreProjector
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengePublication,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.ledger.models import ScoreEvent
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
    from ctf_generator.infrastructure.database.score_projection_repository import (
        SqlAlchemyScoreboardProjectionRepository,
        SqlAlchemyScoreProjectionQueue,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"db extra not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_it_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _alembic_config(url) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


@contextmanager
def _migrated_database():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield db, url
        finally:
            db.dispose()


def _seed(db, competition_id: str = "cup", teams: tuple[str, ...] = ("Red", "Blue")):
    with db.session_scope() as s:
        SqlAlchemyCompetitionRepository(s).add(
            CompetitionConfig(
                competition_id=competition_id,
                name=f"Comp {competition_id}",
                start_time=_NOW,
                end_time=_NOW + timedelta(hours=48),
            )
        )
        for team in teams:
            SqlAlchemyTeamRepository(s).add(Team(competition_id, team))
        definitions = SqlAlchemyChallengeDefinitionRepository(s)
        if definitions.get("sql") is None:
            definitions.add(ChallengeDefinition(family="web", slug="sql", title="SQL"))
            SqlAlchemyChallengeVersionRepository(s).add(
                ChallengeVersion(
                    definition_slug="sql",
                    version_no=1,
                    state="draft",
                    family_version="1.0",
                    seed="s",
                    spec_sha256="h1",
                    spec={"t": 1},
                    spec_version="1.0",
                )
            )
    with db.session_scope() as s:
        versions = SqlAlchemyChallengeVersionRepository(s)
        if versions.get("sql", 1).state == "draft":
            versions.publish("sql", 1, _NOW)
    with db.session_scope() as s:
        SqlAlchemyChallengePublicationRepository(s).add(
            ChallengePublication(
                competition_id=competition_id,
                definition_slug="sql",
                version_no=1,
                initial_value=500,
                minimum_value=500,
                decay_function="static",
                first_blood_enabled=False,
            )
        )


def _event(
    competition_id: str = "cup",
    team_name: str = "Red",
    type_: str = "solve",
    ts: datetime = _NOW,
) -> ScoreEvent:
    return ScoreEvent(
        competition_id=competition_id,
        team_name=team_name,
        definition_slug="sql",
        version_no=1,
        type=type_,
        ts=ts.isoformat(),
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class OutboxTriggerTests(unittest.TestCase):
    def test_append_enqueues_outbox_row_atomically(self) -> None:
        # Positively asserts the migration-owned trigger exists and fires --
        # autogenerate drift checks cannot see triggers, so a silently
        # dropped trigger MUST fail here.
        with _migrated_database() as (db, _url):
            _seed(db)
            with db.session_scope() as s:
                appended = SqlAlchemyScoreLedger(s).append(_event())
            with db.session_scope() as s:
                rows = s.execute(
                    sa.text("SELECT seq, status FROM score_projection_outbox")
                ).all()
        self.assertEqual(rows, [(appended.seq, "pending")])

    def test_aborted_append_burns_seq_but_leaves_no_outbox_row(self) -> None:
        with _migrated_database() as (db, url):
            _seed(db)
            session = Session(db.engine)
            try:
                SqlAlchemyScoreLedger(session).append(_event())  # flush, no commit
                session.rollback()
            finally:
                session.close()
            with db.session_scope() as s:
                outbox_count = s.execute(
                    sa.text("SELECT count(*) FROM score_projection_outbox")
                ).scalar()
                event_count = s.execute(
                    sa.text("SELECT count(*) FROM score_events")
                ).scalar()
        self.assertEqual(outbox_count, 0)
        self.assertEqual(event_count, 0)

    def test_dangling_outbox_seq_is_an_fk_violation(self) -> None:
        # The outbox is mutable (no immutability trigger), so its integrity
        # failures surface as IntegrityError, never ProgrammingError.
        with _migrated_database() as (db, _url):
            _seed(db)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    comp = s.execute(
                        sa.text("SELECT id FROM competitions WHERE slug='cup'")
                    ).scalar_one()
                    s.execute(
                        sa.text(
                            "INSERT INTO score_projection_outbox "
                            "(seq, competition_id) VALUES (999999, :c)"
                        ),
                        {"c": comp},
                    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class StalledWriterTests(unittest.TestCase):
    def test_stalled_writer_is_never_skipped(self) -> None:
        """THE deferred-issue-#1 scenario, two-phase.

        Session A allocates seq_a but stalls before commit; session B
        allocates seq_b > seq_a and commits. A bare cursor advanced to seq_b
        misses seq_a FOREVER (documented below); the outbox projector
        catches it on the pass after A finally commits.
        """
        with _migrated_database() as (db, _url):
            _seed(db)
            projector = ScoreProjector(db)

            session_a = Session(db.engine)
            try:
                ledger_a = SqlAlchemyScoreLedger(session_a)
                stalled = ledger_a.append(_event(team_name="Red"))  # flush only
                seq_a = stalled.seq

                with db.session_scope() as s:
                    committed = SqlAlchemyScoreLedger(s).append(
                        _event(team_name="Blue")
                    )
                seq_b = committed.seq
                self.assertGreater(seq_b, seq_a)

                # Legacy failure, documented: after B commits, a cursor at
                # seq_b sees nothing -- and never will see seq_a.
                with db.session_scope() as s:
                    self.assertEqual(SqlAlchemyScoreLedger(s).since(seq_b), [])

                # Projector pass 1: only B's committed event is visible.
                projector.run_until_drained()
                with db.session_scope() as s:
                    projection = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
                self.assertEqual(projection.as_of_seq, seq_b)
                self.assertEqual(len(projection.entries["entries"]), 1)

                # A finally commits: the bare cursor STILL skips seq_a...
                session_a.commit()
                with db.session_scope() as s:
                    self.assertEqual(SqlAlchemyScoreLedger(s).since(seq_b), [])
            finally:
                session_a.close()

            # ...but A's outbox row became visible with its commit, so pass 2
            # folds BOTH events. No committed event is ever skipped.
            projector.run_until_drained()
            with db.session_scope() as s:
                projection = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
                latest = SqlAlchemyScoreLedger(s).latest_seq()
                pending = s.execute(
                    sa.text(
                        "SELECT count(*) FROM score_projection_outbox "
                        "WHERE status = 'pending'"
                    )
                ).scalar()
        self.assertEqual(projection.as_of_seq, latest)
        self.assertEqual(pending, 0)
        self.assertEqual(len(projection.entries["entries"]), 2)  # both teams

    def test_high_concurrency_drain_never_loses_an_event(self) -> None:
        writers = 8
        events_per_writer = 25
        with _migrated_database() as (db, _url):
            teams = tuple(f"T{i}" for i in range(writers))
            _seed(db, teams=teams)
            projector = ScoreProjector(db)
            errors: list[BaseException] = []
            barrier = threading.Barrier(writers + 1)
            writers_done = threading.Event()

            def write(index: int) -> None:
                # Random flush-to-commit jitter forces seq-allocation /
                # commit-order inversions between writers.
                rng = random.Random(index)  # noqa: S311 - test jitter only
                try:
                    barrier.wait(timeout=30)
                    for n in range(events_per_writer):
                        session = Session(db.engine)
                        try:
                            SqlAlchemyScoreLedger(session).append(
                                _event(
                                    team_name=f"T{index}",
                                    ts=_NOW + timedelta(seconds=n),
                                )
                            )
                            time.sleep(rng.uniform(0, 0.01))
                            session.commit()
                        finally:
                            session.close()
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            def project() -> None:
                try:
                    barrier.wait(timeout=30)
                    while not writers_done.is_set():
                        projector.run_once(batch_size=17)
                        time.sleep(0.005)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [
                threading.Thread(target=write, args=(i,)) for i in range(writers)
            ]
            threads.append(threading.Thread(target=project))
            for t in threads:
                t.start()
            for t in threads[:-1]:
                t.join(timeout=300)
            writers_done.set()
            threads[-1].join(timeout=300)

            self.assertEqual(errors, [])
            projector.run_until_drained()

            with db.session_scope() as s:
                pending = s.execute(
                    sa.text(
                        "SELECT count(*) FROM score_projection_outbox "
                        "WHERE status = 'pending'"
                    )
                ).scalar()
                failed = s.execute(
                    sa.text(
                        "SELECT count(*) FROM score_projection_outbox "
                        "WHERE status = 'failed'"
                    )
                ).scalar()
                total_events = s.execute(
                    sa.text("SELECT count(*) FROM score_events")
                ).scalar()
                latest = SqlAlchemyScoreLedger(s).latest_seq()
                stored = SqlAlchemyScoreboardProjectionRepository(s).get("cup")

            self.assertEqual(total_events, writers * events_per_writer)
            self.assertEqual(pending, 0)
            self.assertEqual(failed, 0)
            self.assertEqual(stored.as_of_seq, latest)

            # The stored projection equals a from-scratch refold.
            rebuilt_total = projector.rebuild()
            self.assertEqual(rebuilt_total, writers * events_per_writer)
            with db.session_scope() as s:
                fresh = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
        self.assertEqual(stored.as_of_seq, fresh.as_of_seq)
        self.assertEqual(stored.entries["entries"], fresh.entries["entries"])


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ProjectorBehaviorTests(unittest.TestCase):
    def test_duplicate_delivery_is_idempotent(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            projector = ScoreProjector(db)
            with db.session_scope() as s:
                SqlAlchemyScoreLedger(s).append(_event())
            projector.run_until_drained()
            with db.session_scope() as s:
                first = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
            # Re-deliver every event (what a crash between apply and complete
            # amounts to) and re-drain: identical state, no double counting.
            with db.session_scope() as s:
                SqlAlchemyScoreProjectionQueue(s).requeue_all()
            projector.run_until_drained()
            with db.session_scope() as s:
                second = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
        self.assertEqual(first.as_of_seq, second.as_of_seq)
        self.assertEqual(first.entries["entries"], second.entries["entries"])

    def test_poison_event_blocks_only_its_competition(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db, competition_id="cup")
            _seed(db, competition_id="other", teams=("Green",))
            with db.session_scope() as s:
                ledger = SqlAlchemyScoreLedger(s)
                ledger.append(_event(competition_id="cup"))
                # 'revalue' is ledger-legal but the fold cannot represent it
                # yet -- the projector must fail LOUD, not drop it.
                ledger.append(
                    _event(competition_id="other", team_name="Green", type_="revalue")
                )
            projector = ScoreProjector(db)
            projector.run_until_drained()
            with db.session_scope() as s:
                healthy = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
                poisoned = SqlAlchemyScoreboardProjectionRepository(s).get("other")
                failed = SqlAlchemyScoreProjectionQueue(s).list_failed()
                lag = SqlAlchemyScoreProjectionQueue(s).pending_stats()
        self.assertIsNotNone(healthy)  # the sibling still projected
        self.assertIsNone(poisoned)
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].status, "failed")
        self.assertEqual(failed[0].attempts, 1)
        self.assertIn("ProjectionUnsupportedEventError", failed[0].last_error)
        self.assertEqual(lag.pending_count, 0)

    def test_failed_error_is_sanitized_class_and_message_only(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            with db.session_scope() as s:
                SqlAlchemyScoreLedger(s).append(
                    ScoreEvent(
                        competition_id="cup",
                        team_name="Red",
                        definition_slug="sql",
                        version_no=1,
                        type="freeze",
                        ts=_NOW.isoformat(),
                        payload={"secret_looking": "ctf{never_logged}"},
                    )
                )
            ScoreProjector(db).run_until_drained()
            with db.session_scope() as s:
                failed = SqlAlchemyScoreProjectionQueue(s).list_failed()
        self.assertEqual(len(failed), 1)
        # The sanitized error names the exception class, never the payload.
        self.assertIn("ProjectionUnsupportedEventError", failed[0].last_error)
        self.assertNotIn("ctf{", failed[0].last_error)
        self.assertNotIn("secret_looking", failed[0].last_error)
        # A sanitized error never carries SQLAlchemy's raw statement echo.
        self.assertNotIn("[SQL", failed[0].last_error)

    def test_requeue_all_resets_a_genuinely_failed_row_to_pending(self) -> None:
        # Actually exercise the failed->pending UPDATE branch: append a poison
        # event, drain to produce a real status='failed' row, THEN requeue_all
        # and assert the row is pending with last_error cleared and attempts
        # preserved (before any second drain re-fails it).
        with _migrated_database() as (db, _url):
            _seed(db)
            with db.session_scope() as s:
                SqlAlchemyScoreLedger(s).append(_event(type_="freeze"))  # poison
            projector = ScoreProjector(db)
            projector.run_until_drained()
            with db.session_scope() as s:
                failed = SqlAlchemyScoreProjectionQueue(s).list_failed()
            self.assertEqual(len(failed), 1)
            self.assertEqual(failed[0].attempts, 1)
            seq = failed[0].seq
            with db.session_scope() as s:
                reset = SqlAlchemyScoreProjectionQueue(s).requeue_all()
            self.assertGreaterEqual(reset, 1)
            with db.session_scope() as s:
                row = s.execute(
                    sa.text(
                        "SELECT status, last_error, attempts FROM "
                        "score_projection_outbox WHERE seq = :seq"
                    ),
                    {"seq": seq},
                ).one()
        self.assertEqual(row.status, "pending")
        self.assertIsNone(row.last_error)  # cleared on requeue
        self.assertEqual(row.attempts, 1)  # preserved across the reset

    def test_transient_error_leaves_rows_pending_and_later_drain_succeeds(
        self,
    ) -> None:
        # A non-deterministic failure (here an OperationalError) must NOT poison
        # the competition: the outbox rows stay pending (re-claimable) and a
        # subsequent drain succeeds once the transient condition clears.
        with _migrated_database() as (db, _url):
            _seed(db)
            with db.session_scope() as s:
                SqlAlchemyScoreLedger(s).append(_event())
            projector = ScoreProjector(db)
            boom = OperationalError("SELECT 1", {}, Exception("connection reset"))
            with mock.patch.object(
                ScoreProjector, "_refold", side_effect=boom
            ):
                projector.run_once()
            with db.session_scope() as s:
                queue = SqlAlchemyScoreProjectionQueue(s)
                lag = queue.pending_stats()
                projection = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
            self.assertEqual(lag.pending_count, 1)  # still pending, not failed
            self.assertEqual(lag.failed_count, 0)
            self.assertIsNone(projection)  # nothing projected yet
            # The transient condition clears; a normal drain now succeeds.
            projector.run_until_drained()
            with db.session_scope() as s:
                lag = SqlAlchemyScoreProjectionQueue(s).pending_stats()
                projection = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
        self.assertEqual(lag.pending_count, 0)
        self.assertEqual(lag.failed_count, 0)
        self.assertIsNotNone(projection)

    def test_lag_reports_failed_count(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            with db.session_scope() as s:
                SqlAlchemyScoreLedger(s).append(_event(type_="freeze"))  # poison
            ScoreProjector(db).run_until_drained()
            with db.session_scope() as s:
                lag = SqlAlchemyScoreProjectionQueue(s).pending_stats()
        self.assertEqual(lag.pending_count, 0)
        self.assertEqual(lag.failed_count, 1)

    def test_naive_ts_is_rejected_at_append(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            naive = ScoreEvent(
                competition_id="cup",
                team_name="Red",
                definition_slug="sql",
                version_no=1,
                type="solve",
                ts="2026-06-01T12:00:00",  # no offset -> ambiguous
            )
            with self.assertRaises(ValueError):
                with db.session_scope() as s:
                    SqlAlchemyScoreLedger(s).append(naive)
            with db.session_scope() as s:
                count = s.execute(
                    sa.text("SELECT count(*) FROM score_events")
                ).scalar()
        self.assertEqual(count, 0)  # the appending transaction failed

    def test_rebuild_equals_fresh_fold(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            projector = ScoreProjector(db)
            with db.session_scope() as s:
                ledger = SqlAlchemyScoreLedger(s)
                ledger.append(_event(team_name="Red"))
                ledger.append(_event(team_name="Blue", ts=_NOW + timedelta(minutes=1)))
            projector.run_until_drained()
            with db.session_scope() as s:
                before = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
            projector.rebuild()
            with db.session_scope() as s:
                after = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
        self.assertEqual(before.as_of_seq, after.as_of_seq)
        self.assertEqual(before.entries["entries"], after.entries["entries"])

    def test_monotonic_upsert_guard_rejects_stale_fold(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            from ctf_generator.domain.ledger.models import (
                ScoreboardProjectionRecord,
            )

            with db.session_scope() as s:
                repo = SqlAlchemyScoreboardProjectionRepository(s)
                repo.upsert(
                    ScoreboardProjectionRecord("cup", 10, entries={"v": "new"})
                )
                repo.upsert(
                    ScoreboardProjectionRecord("cup", 5, entries={"v": "stale"})
                )
            with db.session_scope() as s:
                got = SqlAlchemyScoreboardProjectionRepository(s).get("cup")
        self.assertEqual(got.as_of_seq, 10)
        self.assertEqual(got.entries, {"v": "new"})

    def test_projection_migration_upgrade_downgrade(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            engine = sa.create_engine(url, future=True)
            try:
                command.upgrade(cfg, "0008_score_projection")
                insp = sa.inspect(engine)
                for table in ("score_projection_outbox", "scoreboard_projections"):
                    self.assertIn(table, insp.get_table_names())
                command.downgrade(cfg, "0007_workers")
                insp = sa.inspect(engine)
                self.assertNotIn("score_projection_outbox", insp.get_table_names())
                with engine.connect() as conn:
                    fns = (
                        conn.execute(
                            sa.text(
                                "SELECT proname FROM pg_proc WHERE "
                                "proname = 'score_events_enqueue_projection'"
                            )
                        )
                        .scalars()
                        .all()
                    )
                self.assertEqual(fns, [])
                command.upgrade(cfg, "head")
                self.assertIn(
                    "scoreboard_projections", sa.inspect(engine).get_table_names()
                )
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
