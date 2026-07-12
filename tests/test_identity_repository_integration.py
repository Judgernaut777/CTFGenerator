"""PostgreSQL integration tests for the Identity aggregates (M6 Epic 1).

Docker-gated, exactly like ``test_competition_repository_integration``. These
require the ``db`` extra and a running PostgreSQL reachable via
``CTFGEN_TEST_DATABASE_URL``; absent either, every test SKIPS so the stdlib-only
host suite stays green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_identity_repository_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

try:  # heavy deps are optional; guard so import never fails the host suite
    import sqlalchemy as sa
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import IntegrityError
    from alembic import command
    from alembic.config import Config as AlembicConfig

    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.identity.models import Membership, Team, User
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.models import (
        Membership as MembershipRow,
        Team as TeamRow,
        User as UserRow,
    )
    from ctf_generator.infrastructure.database.competition_repository import (
        SqlAlchemyCompetitionRepository,
    )
    from ctf_generator.infrastructure.database.user_repository import (
        SqlAlchemyUserRepository,
    )
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )
    from ctf_generator.infrastructure.database.membership_repository import (
        SqlAlchemyMembershipRepository,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - exercised only without the extra
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"db extra not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)


@contextmanager
def _isolated_database():
    """Create a throwaway database, yield its URL string, and drop it after."""
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


def _alembic_config(url) -> "AlembicConfig":
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


@contextmanager
def _migrated_database():
    """Yield a ``Database`` bound to a fresh, schema-migrated throwaway DB."""
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield db, url
        finally:
            db.dispose()


def _competition(competition_id: str = "spring-ctf-2026") -> "CompetitionConfig":
    start = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
    return CompetitionConfig(
        competition_id=competition_id,
        name=f"Competition {competition_id}",
        start_time=start,
        end_time=start + timedelta(hours=48),
    )


def _seed_competition(db, competition_id: str = "spring-ctf-2026") -> str:
    with db.session_scope() as s:
        SqlAlchemyCompetitionRepository(s).add(_competition(competition_id))
    return competition_id


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class UserRepositoryIntegrationTests(unittest.TestCase):
    def test_add_get_round_trip_returns_domain_object(self) -> None:
        user = User(email="Alice@Example.io", display_name="Alice")
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(user)
            with db.session_scope() as s:
                fetched = SqlAlchemyUserRepository(s).get("Alice@Example.io")
        self.assertIsInstance(fetched, User)
        self.assertNotIsInstance(fetched, UserRow)
        self.assertEqual(fetched.email, "Alice@Example.io")
        self.assertEqual(fetched.display_name, "Alice")

    def test_get_is_case_insensitive(self) -> None:
        user = User(email="Bob@Example.io", display_name="Bob")
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(user)
            with db.session_scope() as s:
                # Different case resolves the same row.
                self.assertIsNotNone(SqlAlchemyUserRepository(s).get("bob@example.io"))
                self.assertIsNotNone(SqlAlchemyUserRepository(s).get("BOB@EXAMPLE.IO"))

    def test_duplicate_email_case_insensitive_raises_integrity_error(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("carol@x.io", "Carol"))
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    # Same address, different case -> collides on lower(email).
                    SqlAlchemyUserRepository(s).add(User("Carol@X.io", "Carol Two"))

    def test_get_missing_returns_none(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                self.assertIsNone(SqlAlchemyUserRepository(s).get("ghost@x.io"))

    def test_list_returns_all_as_domain_objects(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                repo = SqlAlchemyUserRepository(s)
                repo.add(User("a@x.io", "A"))
                repo.add(User("b@x.io", "B"))
            with db.session_scope() as s:
                users = SqlAlchemyUserRepository(s).list()
        self.assertEqual(len(users), 2)
        self.assertTrue(all(isinstance(u, User) for u in users))
        self.assertEqual({u.email for u in users}, {"a@x.io", "b@x.io"})

    def test_update_changes_display_name_preserves_identity(self) -> None:
        with _migrated_database() as (db, url):
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("dave@x.io", "Dave"))
            engine = sa.create_engine(url, future=True)
            try:
                with engine.connect() as conn:
                    before = conn.execute(
                        sa.text(
                            "SELECT id, email, created_at FROM users "
                            "WHERE lower(email) = 'dave@x.io'"
                        )
                    ).one()
                with db.session_scope() as s:
                    SqlAlchemyUserRepository(s).update(User("dave@x.io", "David"))
                with db.session_scope() as s:
                    fetched = SqlAlchemyUserRepository(s).get("dave@x.io")
                with engine.connect() as conn:
                    after = conn.execute(
                        sa.text(
                            "SELECT id, email, created_at FROM users "
                            "WHERE lower(email) = 'dave@x.io'"
                        )
                    ).one()
            finally:
                engine.dispose()
        self.assertEqual(fetched.display_name, "David")
        self.assertEqual(after.id, before.id)
        self.assertEqual(after.email, before.email)
        self.assertEqual(after.created_at, before.created_at)

    def test_update_missing_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyUserRepository(s).update(User("nobody@x.io", "Nobody"))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class TeamRepositoryIntegrationTests(unittest.TestCase):
    def test_add_get_round_trip_returns_domain_object(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyTeamRepository(s).add(Team(comp, "Red Team"))
            with db.session_scope() as s:
                fetched = SqlAlchemyTeamRepository(s).get(comp, "Red Team")
        self.assertIsInstance(fetched, Team)
        self.assertNotIsInstance(fetched, TeamRow)
        self.assertEqual(fetched.competition_id, comp)
        self.assertEqual(fetched.name, "Red Team")

    def test_add_under_missing_competition_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyTeamRepository(s).add(Team("no-such-comp", "Red"))

    def test_duplicate_team_name_in_competition_raises_integrity_error(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyTeamRepository(s).add(Team(comp, "Blue"))
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyTeamRepository(s).add(Team(comp, "Blue"))

    def test_same_name_different_competitions_allowed(self) -> None:
        with _migrated_database() as (db, _url):
            comp_a = _seed_competition(db, "comp-a")
            comp_b = _seed_competition(db, "comp-b")
            with db.session_scope() as s:
                repo = SqlAlchemyTeamRepository(s)
                repo.add(Team(comp_a, "Falcons"))
                repo.add(Team(comp_b, "Falcons"))  # same name, other competition
            with db.session_scope() as s:
                repo = SqlAlchemyTeamRepository(s)
                self.assertIsNotNone(repo.get(comp_a, "Falcons"))
                self.assertIsNotNone(repo.get(comp_b, "Falcons"))

    def test_list_for_competition_is_scoped(self) -> None:
        with _migrated_database() as (db, _url):
            comp_a = _seed_competition(db, "comp-a")
            comp_b = _seed_competition(db, "comp-b")
            with db.session_scope() as s:
                repo = SqlAlchemyTeamRepository(s)
                repo.add(Team(comp_a, "A1"))
                repo.add(Team(comp_a, "A2"))
                repo.add(Team(comp_b, "B1"))
            with db.session_scope() as s:
                teams_a = SqlAlchemyTeamRepository(s).list_for_competition(comp_a)
        self.assertEqual({t.name for t in teams_a}, {"A1", "A2"})
        self.assertTrue(all(t.competition_id == comp_a for t in teams_a))

    def test_get_missing_returns_none(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                self.assertIsNone(SqlAlchemyTeamRepository(s).get(comp, "Nope"))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class MembershipRepositoryIntegrationTests(unittest.TestCase):
    def _seed_people(self, db, comp: str, *, with_team: str | None = "Red") -> None:
        with db.session_scope() as s:
            SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
            if with_team is not None:
                SqlAlchemyTeamRepository(s).add(Team(comp, with_team))

    def test_add_get_teamed_round_trip(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            self._seed_people(db, comp)
            with db.session_scope() as s:
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp, "captain", team_name="Red")
                )
            with db.session_scope() as s:
                got = SqlAlchemyMembershipRepository(s).get("player@x.io", comp)
        self.assertIsInstance(got, Membership)
        self.assertNotIsInstance(got, MembershipRow)
        self.assertEqual(got.user_email, "player@x.io")
        self.assertEqual(got.competition_id, comp)
        self.assertEqual(got.role, "captain")
        self.assertEqual(got.team_name, "Red")

    def test_add_get_unteamed_round_trip(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            self._seed_people(db, comp, with_team=None)
            with db.session_scope() as s:
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp, "organizer")
                )
            with db.session_scope() as s:
                got = SqlAlchemyMembershipRepository(s).get("player@x.io", comp)
        self.assertEqual(got.role, "organizer")
        self.assertIsNone(got.team_name)

    def test_get_returns_canonical_stored_email_not_caller_case(self) -> None:
        # Stored canonically; fetched via a different case. The returned
        # aggregate must carry the STORED email so get() and list() agree.
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("Alice@X.io", "Alice"))
            with db.session_scope() as s:
                SqlAlchemyMembershipRepository(s).add(
                    Membership("alice@x.io", comp, "player")
                )
            with db.session_scope() as s:
                repo = SqlAlchemyMembershipRepository(s)
                got = repo.get("ALICE@X.IO", comp)
                listed = repo.list_for_competition(comp)
        self.assertEqual(got.user_email, "Alice@X.io")  # canonical, not caller case
        # get() and list() return equal aggregates for the same row.
        self.assertEqual(got, listed[0])

    def test_update_team_from_other_competition_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            comp_a = _seed_competition(db, "comp-a")
            comp_b = _seed_competition(db, "comp-b")
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
                SqlAlchemyTeamRepository(s).add(Team(comp_b, "Red"))
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp_a, "player")
                )
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyMembershipRepository(s).update(
                        Membership("player@x.io", comp_a, "player", team_name="Red")
                    )

    def test_add_missing_user_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyMembershipRepository(s).add(
                        Membership("ghost@x.io", comp, "player")
                    )

    def test_add_missing_competition_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyMembershipRepository(s).add(
                        Membership("player@x.io", "no-comp", "player")
                    )

    def test_add_team_not_in_competition_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyMembershipRepository(s).add(
                        Membership("player@x.io", comp, "player", team_name="Ghost")
                    )

    def test_add_team_from_other_competition_raises_lookuperror(self) -> None:
        # A team named "Red" exists, but in a DIFFERENT competition.
        with _migrated_database() as (db, _url):
            comp_a = _seed_competition(db, "comp-a")
            comp_b = _seed_competition(db, "comp-b")
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
                SqlAlchemyTeamRepository(s).add(Team(comp_b, "Red"))
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyMembershipRepository(s).add(
                        Membership("player@x.io", comp_a, "player", team_name="Red")
                    )

    def test_duplicate_membership_raises_integrity_error(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            self._seed_people(db, comp)
            with db.session_scope() as s:
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp, "player", team_name="Red")
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyMembershipRepository(s).add(
                        Membership("player@x.io", comp, "captain", team_name="Red")
                    )

    def test_update_role_and_team_preserves_identity(self) -> None:
        with _migrated_database() as (db, url):
            comp = _seed_competition(db)
            self._seed_people(db, comp)
            with db.session_scope() as s:
                SqlAlchemyTeamRepository(s).add(Team(comp, "Blue"))
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp, "player", team_name="Red")
                )
            engine = sa.create_engine(url, future=True)
            try:
                with engine.connect() as conn:
                    before = conn.execute(
                        sa.text(
                            "SELECT m.id, m.created_at FROM memberships m "
                            "JOIN users u ON u.id = m.user_id "
                            "WHERE lower(u.email) = 'player@x.io'"
                        )
                    ).one()
                with db.session_scope() as s:
                    SqlAlchemyMembershipRepository(s).update(
                        Membership("player@x.io", comp, "captain", team_name="Blue")
                    )
                with db.session_scope() as s:
                    got = SqlAlchemyMembershipRepository(s).get("player@x.io", comp)
                with engine.connect() as conn:
                    after = conn.execute(
                        sa.text(
                            "SELECT m.id, m.created_at FROM memberships m "
                            "JOIN users u ON u.id = m.user_id "
                            "WHERE lower(u.email) = 'player@x.io'"
                        )
                    ).one()
            finally:
                engine.dispose()
        self.assertEqual(got.role, "captain")
        self.assertEqual(got.team_name, "Blue")
        self.assertEqual(after.id, before.id)
        self.assertEqual(after.created_at, before.created_at)

    def test_update_can_unteam(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            self._seed_people(db, comp)
            with db.session_scope() as s:
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp, "player", team_name="Red")
                )
            with db.session_scope() as s:
                SqlAlchemyMembershipRepository(s).update(
                    Membership("player@x.io", comp, "support")  # team_name=None
                )
            with db.session_scope() as s:
                got = SqlAlchemyMembershipRepository(s).get("player@x.io", comp)
        self.assertEqual(got.role, "support")
        self.assertIsNone(got.team_name)

    def test_update_missing_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyMembershipRepository(s).update(
                        Membership("player@x.io", comp, "player")
                    )

    def test_list_for_competition_is_scoped(self) -> None:
        with _migrated_database() as (db, _url):
            comp_a = _seed_competition(db, "comp-a")
            comp_b = _seed_competition(db, "comp-b")
            with db.session_scope() as s:
                repo = SqlAlchemyUserRepository(s)
                repo.add(User("u1@x.io", "U1"))
                repo.add(User("u2@x.io", "U2"))
                SqlAlchemyTeamRepository(s).add(Team(comp_a, "Red"))
            with db.session_scope() as s:
                m = SqlAlchemyMembershipRepository(s)
                m.add(Membership("u1@x.io", comp_a, "captain", team_name="Red"))
                m.add(Membership("u2@x.io", comp_a, "player"))
                m.add(Membership("u1@x.io", comp_b, "observer"))
            with db.session_scope() as s:
                members_a = SqlAlchemyMembershipRepository(s).list_for_competition(
                    comp_a
                )
        self.assertEqual(len(members_a), 2)
        self.assertTrue(all(isinstance(x, Membership) for x in members_a))
        self.assertEqual(
            {(x.user_email, x.role) for x in members_a},
            {("u1@x.io", "captain"), ("u2@x.io", "player")},
        )
        # The teamed one carries its team; the unteamed one is None.
        by_email = {x.user_email: x for x in members_a}
        self.assertEqual(by_email["u1@x.io"].team_name, "Red")
        self.assertIsNone(by_email["u2@x.io"].team_name)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class IdentityConstraintTests(unittest.TestCase):
    """DB-level guarantees that don't route through the repositories -- proving
    the schema itself enforces the invariants (defence in depth)."""

    def test_composite_fk_blocks_cross_competition_team(self) -> None:
        # Insert a membership row DIRECTLY (bypassing the repo's pre-check) whose
        # team belongs to a different competition than the membership. The
        # composite FK (team_id, competition_id) -> teams(id, competition_id)
        # must reject it at flush time.
        with _migrated_database() as (db, _url):
            comp_a = _seed_competition(db, "comp-a")
            _seed_competition(db, "comp-b")
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
                SqlAlchemyTeamRepository(s).add(Team("comp-b", "Red"))
            with db.session_scope() as s:
                user_id = s.scalars(
                    sa.select(UserRow.id).where(
                        sa.func.lower(UserRow.email) == "player@x.io"
                    )
                ).one()
                comp_a_id = s.execute(
                    sa.text("SELECT id FROM competitions WHERE slug = :slug"),
                    {"slug": comp_a},
                ).scalar_one()
                team_b_id = s.scalars(sa.select(TeamRow.id)).one()  # the comp-b team
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.add(
                        MembershipRow(
                            user_id=user_id,
                            competition_id=comp_a_id,  # comp A ...
                            team_id=team_b_id,  # ... but team is in comp B
                            role="player",
                        )
                    )

    def test_role_check_rejects_unknown_role(self) -> None:
        # The domain forbids bad roles, so insert a row directly to prove the DB
        # CHECK is the backstop.
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
            with db.session_scope() as s:
                user_id = s.scalars(
                    sa.select(UserRow.id).where(
                        sa.func.lower(UserRow.email) == "player@x.io"
                    )
                ).one()
                comp_id = s.execute(
                    sa.text("SELECT id FROM competitions WHERE slug = :slug"),
                    {"slug": comp},
                ).scalar_one()
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.add(
                        MembershipRow(
                            user_id=user_id,
                            competition_id=comp_id,
                            team_id=None,
                            role="superuser",  # not in VALID_ROLES
                        )
                    )

    def test_nonempty_check_rejects_empty_and_whitespace(self) -> None:
        # The domain rejects empty/whitespace names; prove the DB CHECK is the
        # backstop (the constraint uses !~ '^\\s*$', so blanks are rejected too).
        for email, display in (("", "X"), ("   ", "X"), ("a@x.io", " \t ")):
            with self.subTest(email=email, display=display):
                with _migrated_database() as (db, _url):
                    with self.assertRaises(IntegrityError):
                        with db.session_scope() as s:
                            s.add(UserRow(email=email, display_name=display))

    def test_fk_restrict_blocks_deleting_referenced_competition(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyTeamRepository(s).add(Team(comp, "Red"))
            # A team references the competition -> RESTRICT blocks the delete.
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(
                        sa.text("DELETE FROM competitions WHERE slug = :slug"),
                        {"slug": comp},
                    )

    def test_fk_restrict_blocks_deleting_referenced_user(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp, "player")
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(
                        sa.text("DELETE FROM users WHERE lower(email) = 'player@x.io'")
                    )

    def test_fk_restrict_blocks_deleting_referenced_team(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
                SqlAlchemyTeamRepository(s).add(Team(comp, "Red"))
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp, "player", team_name="Red")
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM teams WHERE name = 'Red'"))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class IdentityMigrationTests(unittest.TestCase):
    def test_migration_upgrade_then_downgrade_runs_clean(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            engine = sa.create_engine(url, future=True)
            try:
                # Upgrade to THIS aggregate's revision explicitly (not "head") so
                # the test stays about the identity migration as later migrations
                # stack on top of it.
                command.upgrade(cfg, "0003_identity")
                insp = sa.inspect(engine)
                for table in ("users", "teams", "memberships"):
                    self.assertIn(table, insp.get_table_names())
                with engine.connect() as conn:
                    version = conn.execute(
                        sa.text("SELECT version_num FROM alembic_version")
                    ).scalar()
                self.assertEqual(version, "0003_identity")

                # Downgrade ONE step lands back on the competitions baseline
                # (identity tables gone, competitions still present).
                command.downgrade(cfg, "0002_competitions")
                insp = sa.inspect(engine)
                for table in ("users", "teams", "memberships"):
                    self.assertNotIn(table, insp.get_table_names())
                self.assertIn("competitions", insp.get_table_names())

                command.downgrade(cfg, "base")
                with engine.connect() as conn:
                    remaining = conn.execute(
                        sa.text("SELECT count(*) FROM alembic_version")
                    ).scalar()
                self.assertEqual(remaining, 0)
            finally:
                engine.dispose()

    def test_returned_objects_usable_after_session_closes(self) -> None:
        with _migrated_database() as (db, _url):
            comp = _seed_competition(db)
            with db.session_scope() as s:
                SqlAlchemyUserRepository(s).add(User("player@x.io", "Player"))
                SqlAlchemyTeamRepository(s).add(Team(comp, "Red"))
            with db.session_scope() as s:
                SqlAlchemyMembershipRepository(s).add(
                    Membership("player@x.io", comp, "captain", team_name="Red")
                )
            with db.session_scope() as s:
                got = SqlAlchemyMembershipRepository(s).get("player@x.io", comp)
            # Session closed; frozen dataclass must remain fully usable.
            self.assertEqual(got.user_email, "player@x.io")
            self.assertEqual(got.team_name, "Red")


if __name__ == "__main__":
    unittest.main()
