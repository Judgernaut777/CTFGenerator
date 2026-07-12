"""PostgreSQL integration tests for the transactional submission service (M7).

Proves the one-UoW script: N simultaneous correct submissions -> exactly one
Solve + one 'solve' ScoreEvent, with ``solved_at == submitted_at`` by
construction (deferred issue #2), idempotent replay, and nothing persisted on
rejection paths. Docker-gated; skips cleanly off-Docker.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_submission_processing_integration
"""

from __future__ import annotations

import os
import threading
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import IntegrityError

    from ctf_generator.application.submissions.service import (
        SubmissionProcessingService,
    )
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengePublication,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.ledger.processing import (
        ChallengeNotAttachedError,
        FlagUnavailableError,
        IdempotencyConflictError,
        SubmissionRequest,
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
    from ctf_generator.infrastructure.database.solve_repository import (
        SqlAlchemySolveRepository,
    )
    from ctf_generator.infrastructure.database.submission_repository import (
        SqlAlchemyLedgerSubmissionRepository,
    )
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
_FLAG = "ctf{correct_horse_battery}"


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


def _seed(db, *, flag: str | None = _FLAG, attach: bool = True) -> None:
    """Competition + team + published version (+ publication)."""
    spec: dict[str, object] = {"t": 1}
    if flag is not None:
        spec["flag"] = flag
    with db.session_scope() as s:
        SqlAlchemyCompetitionRepository(s).add(
            CompetitionConfig(
                competition_id="cup",
                name="Cup",
                start_time=_NOW - timedelta(hours=1),
                end_time=_NOW + timedelta(hours=47),
            )
        )
        SqlAlchemyTeamRepository(s).add(Team("cup", "Red"))
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
                spec_sha256="h1",
                spec=spec,
                spec_version="1.0",
            )
        )
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish("sql", 1, _NOW)
    if attach:
        with db.session_scope() as s:
            SqlAlchemyChallengePublicationRepository(s).add(
                ChallengePublication(
                    competition_id="cup", definition_slug="sql", version_no=1
                )
            )


def _request(candidate: str, **overrides) -> SubmissionRequest:
    base = dict(
        submission_id=str(uuid.uuid4()),
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        submitted_at=_NOW,
        candidate_flag=candidate,
    )
    base.update(overrides)
    return SubmissionRequest(**base)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class SubmissionProcessingTests(unittest.TestCase):
    def test_isolation_level_is_read_committed(self) -> None:
        # The post-lock re-check depends on READ COMMITTED per-statement
        # snapshots; assert the assumption instead of leaving it tribal.
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                level = s.execute(sa.text("SHOW transaction_isolation")).scalar()
        self.assertEqual(level, "read committed")

    def test_correct_first_submission_produces_solve_and_event(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            service = SubmissionProcessingService(db)
            outcome = service.process_submission(_request(_FLAG))
            self.assertTrue(outcome.accepted)
            self.assertTrue(outcome.first_solve)
            self.assertFalse(outcome.replay)
            # Deferred issue #2 by construction:
            self.assertEqual(outcome.solve.solved_at, outcome.submission.submitted_at)
            self.assertEqual(
                outcome.solve.submission_id, outcome.submission.submission_id
            )
            self.assertEqual(outcome.score_event.type, "solve")
            self.assertIsNotNone(outcome.score_event.seq)
            with db.session_scope() as s:
                events = SqlAlchemyScoreLedger(s).list_for_competition("cup")
                solve = SqlAlchemySolveRepository(s).get_for_challenge(
                    "cup", "Red", "sql", 1
                )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].solve_id, outcome.solve.solve_id)
        self.assertEqual(solve.solved_at, _NOW)

    def test_incorrect_flag_recorded_without_solve(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            service = SubmissionProcessingService(db)
            outcome = service.process_submission(_request("ctf{nope}"))
            self.assertFalse(outcome.accepted)
            self.assertFalse(outcome.first_solve)
            self.assertIsNone(outcome.solve)
            with db.session_scope() as s:
                stored = SqlAlchemyLedgerSubmissionRepository(s).get(
                    outcome.submission.submission_id
                )
                events = SqlAlchemyScoreLedger(s).list_for_competition("cup")
                solves = SqlAlchemySolveRepository(s).list_for_competition("cup")
        self.assertIsNotNone(stored)
        self.assertFalse(stored.correct)
        self.assertEqual(events, [])
        self.assertEqual(solves, [])

    def test_correct_duplicate_records_submission_only(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            service = SubmissionProcessingService(db)
            first = service.process_submission(_request(_FLAG))
            second = service.process_submission(
                _request(_FLAG, submitted_at=_NOW + timedelta(minutes=5))
            )
            self.assertTrue(second.accepted)
            self.assertFalse(second.first_solve)
            self.assertIsNone(second.solve)
            with db.session_scope() as s:
                solves = SqlAlchemySolveRepository(s).list_for_competition("cup")
                events = SqlAlchemyScoreLedger(s).list_for_competition("cup")
        self.assertEqual(len(solves), 1)
        self.assertEqual(solves[0].solve_id, first.solve.solve_id)
        self.assertEqual(len(events), 1)

    def test_idempotent_replay_returns_original_without_writing(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            service = SubmissionProcessingService(db)
            sid = str(uuid.uuid4())
            first = service.process_submission(_request(_FLAG, submission_id=sid))
            replay = service.process_submission(_request(_FLAG, submission_id=sid))
            self.assertTrue(replay.replay)
            self.assertTrue(replay.accepted)
            self.assertTrue(replay.first_solve)
            self.assertEqual(replay.solve.solve_id, first.solve.solve_id)
            with db.session_scope() as s:
                events = SqlAlchemyScoreLedger(s).list_for_competition("cup")
                solves = SqlAlchemySolveRepository(s).list_for_competition("cup")
        self.assertEqual(len(events), 1)  # still exactly one
        self.assertEqual(len(solves), 1)

    def test_replay_with_mismatched_identity_is_a_conflict(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            with db.session_scope() as s:
                SqlAlchemyTeamRepository(s).add(Team("cup", "Blue"))
            service = SubmissionProcessingService(db)
            sid = str(uuid.uuid4())
            service.process_submission(_request(_FLAG, submission_id=sid))
            with self.assertRaises(IdempotencyConflictError):
                service.process_submission(
                    _request(_FLAG, submission_id=sid, team_name="Blue")
                )

    def test_unattached_challenge_rejected_nothing_persisted(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db, attach=False)
            service = SubmissionProcessingService(db)
            request = _request(_FLAG)
            with self.assertRaises(ChallengeNotAttachedError):
                service.process_submission(request)
            with db.session_scope() as s:
                stored = SqlAlchemyLedgerSubmissionRepository(s).get(
                    request.submission_id
                )
                events = SqlAlchemyScoreLedger(s).list_for_competition("cup")
        self.assertIsNone(stored)
        self.assertEqual(events, [])

    def test_flagless_spec_fails_loud_and_persists_nothing(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db, flag=None)
            service = SubmissionProcessingService(db)
            request = _request("ctf{anything}")
            with self.assertRaises(FlagUnavailableError):
                service.process_submission(request)
            with db.session_scope() as s:
                stored = SqlAlchemyLedgerSubmissionRepository(s).get(
                    request.submission_id
                )
        self.assertIsNone(stored)

    def test_archived_but_attached_version_remains_submittable(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeVersionRepository(s).archive(
                    "sql", 1, _NOW + timedelta(hours=1)
                )
            service = SubmissionProcessingService(db)
            outcome = service.process_submission(_request(_FLAG))
        self.assertTrue(outcome.accepted)
        self.assertTrue(outcome.first_solve)

    def test_direct_second_solve_insert_hits_unique_backstop(self) -> None:
        # The advisory lock is the mechanism; the UNIQUE is the backstop. A
        # writer bypassing the service must hit sqlalchemy.exc.IntegrityError
        # (the specific class), proving the backstop bites.
        with _migrated_database() as (db, _url):
            _seed(db)
            service = SubmissionProcessingService(db)
            service.process_submission(_request(_FLAG))
            # A second correct submission (recorded via the service as a
            # duplicate) gives us a valid submission row to hang a rogue
            # solve on.
            dup = service.process_submission(
                _request(_FLAG, submitted_at=_NOW + timedelta(minutes=1))
            )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    ids = s.execute(
                        sa.text(
                            "SELECT competition_id, team_id, challenge_version_id "
                            "FROM submissions WHERE id = :sid"
                        ),
                        {"sid": dup.submission.submission_id},
                    ).one()
                    s.execute(
                        sa.text(
                            "INSERT INTO solves (id, competition_id, team_id, "
                            "challenge_version_id, submission_id, solved_at) "
                            "VALUES (:id, :c, :t, :v, :sid, :at)"
                        ),
                        {
                            "id": uuid.uuid4(),
                            "c": ids[0],
                            "t": ids[1],
                            "v": ids[2],
                            "sid": dup.submission.submission_id,
                            "at": _NOW,
                        },
                    )

    def test_eight_simultaneous_correct_submissions_one_solve(self) -> None:
        with _migrated_database() as (db, _url):
            _seed(db)
            service = SubmissionProcessingService(db)
            outcomes: list[object] = []
            errors: list[BaseException] = []
            barrier = threading.Barrier(8)
            lock = threading.Lock()

            def submit(index: int) -> None:
                try:
                    request = _request(_FLAG)
                    barrier.wait(timeout=30)
                    outcome = service.process_submission(request)
                    with lock:
                        outcomes.append(outcome)
                except BaseException as exc:  # noqa: BLE001 - asserted empty
                    errors.append(exc)

            threads = [threading.Thread(target=submit, args=(i,)) for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=120)

            self.assertEqual(errors, [])  # no thread may raise
            self.assertEqual(len(outcomes), 8)

            winners = [o for o in outcomes if o.first_solve]
            duplicates = [o for o in outcomes if not o.first_solve]
            self.assertEqual(len(winners), 1)
            self.assertEqual(len(duplicates), 7)
            self.assertTrue(all(o.accepted for o in outcomes))

            with db.session_scope() as s:
                solves = SqlAlchemySolveRepository(s).list_for_competition("cup")
                events = SqlAlchemyScoreLedger(s).list_for_competition("cup")
                submissions = SqlAlchemyLedgerSubmissionRepository(s).list_for_team(
                    "cup", "Red"
                )
        # Exactly one solve, one 'solve' event, eight correct submissions.
        self.assertEqual(len(solves), 1)
        self.assertEqual([e.type for e in events], ["solve"])
        self.assertEqual(len(submissions), 8)
        self.assertTrue(all(sub.correct for sub in submissions))
        # The solve derives from the WINNING submission, by construction.
        winner = winners[0]
        self.assertEqual(solves[0].submission_id, winner.submission.submission_id)
        self.assertEqual(solves[0].solved_at, winner.submission.submitted_at)
        self.assertEqual(events[0].solve_id, solves[0].solve_id)


if __name__ == "__main__":
    unittest.main()
