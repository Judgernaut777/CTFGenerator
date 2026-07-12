"""PostgreSQL integration tests for the append-only ledger aggregates (M6 Epic 3).

Docker-gated like the other repository suites; skips cleanly without the db extra
/ CTFGEN_TEST_DATABASE_URL so the stdlib host suite stays green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_ledger_repository_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import IntegrityError, ProgrammingError

    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.identity.models import Team, User
    from ctf_generator.domain.ledger.models import LedgerSubmission, ScoreEvent, Solve
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
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
    from ctf_generator.infrastructure.database.user_repository import (
        SqlAlchemyUserRepository,
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


def _uid() -> str:
    return str(uuid.uuid4())


def _setup_chain(db, competition_id: str = "cup", team_name: str = "Red") -> None:
    """Seed a competition + team + published challenge version to attach a
    ledger against."""
    with db.session_scope() as s:
        SqlAlchemyCompetitionRepository(s).add(
            CompetitionConfig(
                competition_id=competition_id,
                name=f"Comp {competition_id}",
                start_time=_NOW,
                end_time=_NOW + timedelta(hours=48),
            )
        )
        SqlAlchemyTeamRepository(s).add(Team(competition_id, team_name))
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
                spec={"t": 1},
                spec_version="1.0",
            )
        )
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish("sql", 1, _NOW)


def _submission(
    submission_id: str,
    *,
    competition_id: str = "cup",
    team_name: str = "Red",
    correct: bool = True,
    submitter_email: str | None = None,
) -> LedgerSubmission:
    return LedgerSubmission(
        submission_id=submission_id,
        competition_id=competition_id,
        team_name=team_name,
        definition_slug="sql",
        version_no=1,
        submitted_at=_NOW,
        correct=correct,
        submitter_email=submitter_email,
    )


def _solve(solve_id: str, submission_id: str, *, team_name: str = "Red") -> Solve:
    return Solve(
        solve_id=solve_id,
        competition_id="cup",
        team_name=team_name,
        definition_slug="sql",
        version_no=1,
        submission_id=submission_id,
        solved_at=_NOW,
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class SubmissionRepositoryTests(unittest.TestCase):
    def test_add_get_round_trip(self) -> None:
        sid = _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid))
            with db.session_scope() as s:
                got = SqlAlchemyLedgerSubmissionRepository(s).get(sid)
        self.assertIsInstance(got, LedgerSubmission)
        self.assertEqual(got.submission_id, sid)
        self.assertEqual(got.competition_id, "cup")
        self.assertEqual(got.team_name, "Red")
        self.assertEqual(got.definition_slug, "sql")
        self.assertEqual(got.version_no, 1)
        self.assertTrue(got.correct)
        self.assertIsNone(got.submitter_email)

    def test_add_with_submitter_email_resolves_user(self) -> None:
        sid = _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("Player@x.io", "Player"))
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(
                    _submission(sid, submitter_email="player@x.io")
                )
            with db.session_scope() as s:
                got = SqlAlchemyLedgerSubmissionRepository(s).get(sid)
        self.assertEqual(got.submitter_email, "Player@x.io")  # canonical stored

    def test_add_missing_team_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyLedgerSubmissionRepository(s).add(
                        _submission(_uid(), team_name="Ghost")
                    )

    def test_add_unknown_submitter_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyLedgerSubmissionRepository(s).add(
                        _submission(_uid(), submitter_email="nobody@x.io")
                    )

    def test_duplicate_submission_id_raises(self) -> None:
        sid = _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid))
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid))

    def test_list_for_team_ordered(self) -> None:
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                repo = SqlAlchemyLedgerSubmissionRepository(s)
                repo.add(_submission(_uid(), correct=False))
                repo.add(_submission(_uid(), correct=True))
            with db.session_scope() as s:
                subs = SqlAlchemyLedgerSubmissionRepository(s).list_for_team("cup", "Red")
        self.assertEqual(len(subs), 2)

    def test_get_malformed_or_absent_id_returns_none(self) -> None:
        # A malformed id is a clean miss (None), symmetric with an absent uuid --
        # neither leaks a persistence-layer error to the caller.
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                repo = SqlAlchemyLedgerSubmissionRepository(s)
                self.assertIsNone(repo.get("not-a-uuid"))
                self.assertIsNone(repo.get(_uid()))

    def test_append_only_trigger_blocks_update_delete_truncate(self) -> None:
        sid = _uid()
        with _migrated_database() as (db, url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid))
            engine = sa.create_engine(url, future=True)
            try:
                for stmt in (
                    "UPDATE submissions SET correct = false",
                    "DELETE FROM submissions",
                    "TRUNCATE submissions CASCADE",
                ):
                    with self.assertRaises(ProgrammingError):
                        with engine.begin() as conn:
                            conn.execute(sa.text(stmt))
            finally:
                engine.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class SolveRepositoryTests(unittest.TestCase):
    def _seed_correct_submission(self, db, sid: str) -> None:
        with db.session_scope() as s:
            SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid, correct=True))

    def test_add_get_round_trip(self) -> None:
        sid, solve_id = _uid(), _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            self._seed_correct_submission(db, sid)
            with db.session_scope() as s:
                SqlAlchemySolveRepository(s).add(_solve(solve_id, sid))
            with db.session_scope() as s:
                got = SqlAlchemySolveRepository(s).get(solve_id)
                by_chal = SqlAlchemySolveRepository(s).get_for_challenge(
                    "cup", "Red", "sql", 1
                )
        self.assertEqual(got.solve_id, solve_id)
        self.assertEqual(got.submission_id, sid)
        self.assertEqual(by_chal.solve_id, solve_id)

    def test_get_malformed_or_absent_id_returns_none(self) -> None:
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                repo = SqlAlchemySolveRepository(s)
                self.assertIsNone(repo.get("not-a-uuid"))
                self.assertIsNone(repo.get(_uid()))

    def test_at_most_one_solve_per_team_challenge(self) -> None:
        s1, s2, v1, v2 = _uid(), _uid(), _uid(), _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(s1, correct=True))
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(s2, correct=True))
            with db.session_scope() as s:
                SqlAlchemySolveRepository(s).add(_solve(v1, s1))
            # A second solve for the same (competition, team, version) is rejected.
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemySolveRepository(s).add(_solve(v2, s2))

    def test_solve_referencing_incorrect_submission_rejected(self) -> None:
        sid, solve_id = _uid(), _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid, correct=False))
            # The composite FK matches the tuple, but the trigger requires correct.
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    SqlAlchemySolveRepository(s).add(_solve(solve_id, sid))

    def test_solve_with_mismatched_submission_tuple_rejected(self) -> None:
        # Submission belongs to team Red; the solve claims team Blue -> the
        # composite FK (submission_id, competition, team, version) cannot match.
        sid, solve_id = _uid(), _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyTeamRepository(s).add(Team("cup", "Blue"))
                SqlAlchemyLedgerSubmissionRepository(s).add(
                    _submission(sid, team_name="Red", correct=True)
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemySolveRepository(s).add(
                        _solve(solve_id, sid, team_name="Blue")
                    )

    def test_append_only_trigger_blocks_mutation(self) -> None:
        sid, solve_id = _uid(), _uid()
        with _migrated_database() as (db, url):
            _setup_chain(db)
            self._seed_correct_submission(db, sid)
            with db.session_scope() as s:
                SqlAlchemySolveRepository(s).add(_solve(solve_id, sid))
            engine = sa.create_engine(url, future=True)
            try:
                for stmt in ("UPDATE solves SET instance_seed='x'", "DELETE FROM solves"):
                    with self.assertRaises(ProgrammingError):
                        with engine.begin() as conn:
                            conn.execute(sa.text(stmt))
            finally:
                engine.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ScoreLedgerTests(unittest.TestCase):
    def _event(self, type_: str = "submission", **kw) -> ScoreEvent:
        base = dict(
            competition_id="cup",
            team_name="Red",
            definition_slug="sql",
            version_no=1,
            type=type_,
            ts="2026-06-01T12:00:00Z",
        )
        base.update(kw)
        return ScoreEvent(**base)

    def test_append_assigns_monotonic_seq(self) -> None:
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                ledger = SqlAlchemyScoreLedger(s)
                e1 = ledger.append(self._event("submission"))
                e2 = ledger.append(self._event("solve"))
        self.assertIsNotNone(e1.seq)
        self.assertGreater(e2.seq, e1.seq)

    def test_since_and_latest_seq(self) -> None:
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                ledger = SqlAlchemyScoreLedger(s)
                a = ledger.append(self._event("submission"))
                ledger.append(self._event("solve"))
                ledger.append(self._event("first_blood"))
            with db.session_scope() as s:
                ledger = SqlAlchemyScoreLedger(s)
                after_first = ledger.since(a.seq)
                latest = ledger.latest_seq()
        self.assertEqual([e.type for e in after_first], ["solve", "first_blood"])
        self.assertEqual(latest, a.seq + 2)

    def test_empty_ledger_latest_seq_zero_and_since_empty(self) -> None:
        # A ledger with no events reports seq 0 and an empty tail -- the cursor
        # contract's base case (mirrors the pure store's initial state).
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                ledger = SqlAlchemyScoreLedger(s)
                self.assertEqual(ledger.latest_seq(), 0)
                self.assertEqual(ledger.since(0), [])

    def test_payload_and_provenance_round_trip(self) -> None:
        sid = _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid, correct=True))
            with db.session_scope() as s:
                SqlAlchemyScoreLedger(s).append(
                    self._event(
                        "submission",
                        payload={"points": 500, "nested": {"x": [1, 2]}},
                        submission_id=sid,
                    )
                )
            with db.session_scope() as s:
                events = SqlAlchemyScoreLedger(s).list_for_competition("cup")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].payload, {"points": 500, "nested": {"x": [1, 2]}})
        self.assertEqual(events[0].submission_id, sid)

    def test_type_check_backstop_rejects_unknown_type(self) -> None:
        # The domain forbids bad types; prove the DB CHECK is the backstop.
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                comp = s.execute(
                    sa.text("SELECT id FROM competitions WHERE slug='cup'")
                ).scalar_one()
                team = s.execute(
                    sa.text("SELECT id FROM teams WHERE name='Red'")
                ).scalar_one()
                ver = s.execute(
                    sa.text("SELECT id FROM challenge_versions WHERE version_no=1")
                ).scalar_one()
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(
                        sa.text(
                            "INSERT INTO score_events "
                            "(competition_id, team_id, challenge_version_id, type, ts) "
                            "VALUES (:c, :t, :v, 'bogus', '2026')"
                        ),
                        {"c": comp, "t": team, "v": ver},
                    )

    def test_append_only_trigger_blocks_mutation(self) -> None:
        with _migrated_database() as (db, url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyScoreLedger(s).append(self._event("submission"))
            engine = sa.create_engine(url, future=True)
            try:
                for stmt in (
                    "UPDATE score_events SET type='solve'",
                    "DELETE FROM score_events",
                ):
                    with self.assertRaises(ProgrammingError):
                        with engine.begin() as conn:
                            conn.execute(sa.text(stmt))
            finally:
                engine.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class TransactionalProcessingTests(unittest.TestCase):
    def test_submission_solve_scoreevent_are_one_unit_of_work(self) -> None:
        sid, solve_id = _uid(), _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            # A correct submission processed atomically: submission + solve +
            # score event all commit together.
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid, correct=True))
                SqlAlchemySolveRepository(s).add(_solve(solve_id, sid))
                SqlAlchemyScoreLedger(s).append(
                    ScoreEvent(
                        competition_id="cup",
                        team_name="Red",
                        definition_slug="sql",
                        version_no=1,
                        type="solve",
                        ts="2026-06-01T12:00:00Z",
                        submission_id=sid,
                        solve_id=solve_id,
                    )
                )
            with db.session_scope() as s:
                self.assertIsNotNone(SqlAlchemyLedgerSubmissionRepository(s).get(sid))
                self.assertIsNotNone(SqlAlchemySolveRepository(s).get(solve_id))
                self.assertEqual(
                    len(SqlAlchemyScoreLedger(s).list_for_competition("cup")), 1
                )

    def test_duplicate_solve_rolls_back_whole_transaction(self) -> None:
        # Processing a duplicate solve inside one UoW must roll back the
        # submission written in the same scope (no partial ledger state).
        s1, v1 = _uid(), _uid()
        s2, v2 = _uid(), _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(s1, correct=True))
                SqlAlchemySolveRepository(s).add(_solve(v1, s1))
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyLedgerSubmissionRepository(s).add(_submission(s2, correct=True))
                    SqlAlchemySolveRepository(s).add(_solve(v2, s2))  # dup solve
            # The second submission was rolled back with the failed unit of work.
            with db.session_scope() as s:
                self.assertIsNone(SqlAlchemyLedgerSubmissionRepository(s).get(s2))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class LedgerFkAndMigrationTests(unittest.TestCase):
    # Note: the child-side FK RESTRICT (e.g. deleting a submission referenced by
    # a solve) is unreachable and untestable via DELETE -- submissions/solves/
    # score_events are append-only, so a DELETE hits the immutability trigger
    # first (covered by the append-only tests). Only the PARENT-side RESTRICT
    # (deleting a team/version a ledger row points at) is exercisable, and it is
    # tested here against each parent in isolation: a `DELETE competitions` is
    # *not* a valid probe -- the teams->competitions RESTRICT would block it
    # regardless of any ledger row, masking whether the ledger FK bites at all.
    # A solve's own team/version FKs cannot be isolated (a solve always carries a
    # correct submission that references the same team+version), so they are
    # covered transitively by the submission and score_event probes below.

    def _bare_score_event(self, db) -> None:
        with db.session_scope() as s:
            SqlAlchemyScoreLedger(s).append(
                ScoreEvent(
                    competition_id="cup",
                    team_name="Red",
                    definition_slug="sql",
                    version_no=1,
                    type="submission",
                    ts="2026-06-01T12:00:00Z",
                )
            )

    def test_fk_restrict_blocks_deleting_version_referenced_by_submission(self) -> None:
        # The challenge version is referenced ONLY by the submission (it is not
        # attached to a competition_challenges row), so the submission's version
        # FK is the sole blocker -- an isolated probe of that RESTRICT.
        sid = _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid, correct=True))
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM challenge_versions WHERE version_no=1"))

    def test_fk_restrict_blocks_deleting_team_referenced_by_submission(self) -> None:
        # The team is referenced only by the submission (no memberships), so the
        # submission's composite (team_id, competition_id) FK is the sole blocker.
        sid = _uid()
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            with db.session_scope() as s:
                SqlAlchemyLedgerSubmissionRepository(s).add(_submission(sid, correct=True))
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM teams WHERE name='Red'"))

    def test_fk_restrict_blocks_deleting_team_referenced_by_score_event(self) -> None:
        # A bare score_event (no submission/solve provenance) isolates the
        # score_events.team_id FK RESTRICT.
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            self._bare_score_event(db)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM teams WHERE name='Red'"))

    def test_fk_restrict_blocks_deleting_version_referenced_by_score_event(self) -> None:
        # Same probe for the score_events.challenge_version_id FK RESTRICT.
        with _migrated_database() as (db, _url):
            _setup_chain(db)
            self._bare_score_event(db)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM challenge_versions WHERE version_no=1"))

    def test_migration_upgrade_downgrade(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            engine = sa.create_engine(url, future=True)
            try:
                command.upgrade(cfg, "0005_ledger")
                insp = sa.inspect(engine)
                for t in ("submissions", "solves", "score_events"):
                    self.assertIn(t, insp.get_table_names())
                with engine.connect() as conn:
                    self.assertEqual(
                        conn.execute(
                            sa.text("SELECT version_num FROM alembic_version")
                        ).scalar(),
                        "0005_ledger",
                    )
                # Down one step: ledger tables gone, challenge tables remain, and
                # the shared reject_mutation() (owned by 0004) is retained.
                command.downgrade(cfg, "0004_challenges")
                insp = sa.inspect(engine)
                self.assertNotIn("submissions", insp.get_table_names())
                self.assertIn("challenge_versions", insp.get_table_names())
                with engine.connect() as conn:
                    fns = (
                        conn.execute(
                            sa.text(
                                "SELECT proname FROM pg_proc WHERE proname='reject_mutation'"
                            )
                        )
                        .scalars()
                        .all()
                    )
                self.assertEqual(fns, ["reject_mutation"])
                # up -> down -> up is clean.
                command.upgrade(cfg, "0005_ledger")
                self.assertIn("solves", sa.inspect(engine).get_table_names())
                command.downgrade(cfg, "base")
                with engine.connect() as conn:
                    self.assertEqual(
                        conn.execute(
                            sa.text("SELECT count(*) FROM alembic_version")
                        ).scalar(),
                        0,
                    )
                    # A full teardown leaves no ledger machinery behind: both the
                    # 0005 trigger fn and the 0004-owned shared guard are dropped.
                    leftover = (
                        conn.execute(
                            sa.text(
                                "SELECT proname FROM pg_proc WHERE proname IN "
                                "('reject_mutation', 'solve_requires_correct_submission')"
                            )
                        )
                        .scalars()
                        .all()
                    )
                    self.assertEqual(leftover, [])
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
