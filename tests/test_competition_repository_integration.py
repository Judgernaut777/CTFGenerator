"""PostgreSQL integration tests for the Competition aggregate repository (M6).

Docker-gated, exactly like ``test_database_integration``. These require
SQLAlchemy/Alembic (the ``db`` extra) and a running PostgreSQL reachable via
``CTFGEN_TEST_DATABASE_URL``. When either is absent -- e.g. the PEP 668
stdlib-only host running the unit suite -- every test SKIPS, so this module
never breaks the core gate. Run it in CI's integration tier / a Docker
container with a postgres service:

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_competition_repository_integration
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

    from ctf_generator.domain.challenges.models import (
        ChallengeScoringConfig,
        CompetitionConfig,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.models import Competition
    from ctf_generator.infrastructure.database.competition_repository import (
        SqlAlchemyCompetitionRepository,
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
    """Create a throwaway database, yield its URL string, and drop it after.

    Same approach as ``test_database_integration._isolated_database``: connect
    to the maintenance database with AUTOCOMMIT to CREATE/DROP DATABASE, and
    yield a DSN with the password preserved via ``render_as_string`` (NOT
    ``str(url)``, which masks the password and breaks auth).
    """
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
    """Yield a ``Database`` bound to a fresh, schema-migrated throwaway DB.

    Builds the schema by running ``alembic upgrade head`` (exercising the real
    ``0002_competitions`` migration), then hands back a ``Database`` for the
    unit-of-work / repository under test.
    """
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield db, url
        finally:
            db.dispose()


def _sample_config(competition_id: str = "spring-ctf-2026") -> "CompetitionConfig":
    start = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
    return CompetitionConfig(
        competition_id=competition_id,
        name="Spring CTF 2026",
        start_time=start,
        end_time=start + timedelta(hours=48),
        scoring_start_time=start + timedelta(minutes=30),
        freeze_time=start + timedelta(hours=47),
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CompetitionRepositoryIntegrationTests(unittest.TestCase):
    def test_add_get_round_trip_returns_domain_object(self) -> None:
        cfg = _sample_config()
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyCompetitionRepository(s).add(cfg)
            with db.session_scope() as s:
                fetched = SqlAlchemyCompetitionRepository(s).get(cfg.competition_id)

        # A DOMAIN object comes back -- never an ORM row.
        self.assertIsInstance(fetched, CompetitionConfig)
        self.assertNotIsInstance(fetched, Competition)
        self.assertEqual(fetched.competition_id, cfg.competition_id)
        self.assertEqual(fetched.name, cfg.name)
        self.assertEqual(fetched.start_time, cfg.start_time)
        self.assertEqual(fetched.end_time, cfg.end_time)
        self.assertEqual(fetched.scoring_start_time, cfg.scoring_start_time)
        self.assertEqual(fetched.freeze_time, cfg.freeze_time)
        self.assertIsNone(fetched.default_scoring)

    def test_get_missing_returns_none(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                self.assertIsNone(
                    SqlAlchemyCompetitionRepository(s).get("does-not-exist")
                )

    def test_list_returns_all_as_domain_objects(self) -> None:
        a = _sample_config("comp-a")
        b = _sample_config("comp-b")
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                repo = SqlAlchemyCompetitionRepository(s)
                repo.add(a)
                repo.add(b)
            with db.session_scope() as s:
                all_configs = SqlAlchemyCompetitionRepository(s).list()

        self.assertEqual(len(all_configs), 2)
        self.assertTrue(all(isinstance(c, CompetitionConfig) for c in all_configs))
        self.assertEqual(
            {c.competition_id for c in all_configs}, {"comp-a", "comp-b"}
        )

    def test_update_changes_mutable_preserves_immutable(self) -> None:
        cfg = _sample_config()
        with _migrated_database() as (db, url):
            with db.session_scope() as s:
                SqlAlchemyCompetitionRepository(s).add(cfg)

            # Capture the ORM-managed immutable columns via a direct SQL read.
            engine = sa.create_engine(url, future=True)
            try:
                with engine.connect() as conn:
                    before = conn.execute(
                        sa.text(
                            "SELECT id, created_at, status FROM competitions "
                            "WHERE slug = :slug"
                        ),
                        {"slug": cfg.competition_id},
                    ).one()

                new_start = cfg.start_time + timedelta(days=7)
                updated = CompetitionConfig(
                    competition_id=cfg.competition_id,  # same business key
                    name="Renamed CTF",
                    start_time=new_start,
                    end_time=new_start + timedelta(hours=24),
                    scoring_start_time=new_start + timedelta(minutes=15),
                    freeze_time=new_start + timedelta(hours=23),
                )
                with db.session_scope() as s:
                    SqlAlchemyCompetitionRepository(s).update(updated)

                with db.session_scope() as s:
                    fetched = SqlAlchemyCompetitionRepository(s).get(
                        cfg.competition_id
                    )
                with engine.connect() as conn:
                    after = conn.execute(
                        sa.text(
                            "SELECT id, created_at, status FROM competitions "
                            "WHERE slug = :slug"
                        ),
                        {"slug": cfg.competition_id},
                    ).one()
            finally:
                engine.dispose()

        # Mutable fields changed...
        self.assertEqual(fetched.name, "Renamed CTF")
        self.assertEqual(fetched.start_time, new_start)
        self.assertEqual(fetched.end_time, new_start + timedelta(hours=24))
        self.assertEqual(fetched.freeze_time, new_start + timedelta(hours=23))
        # ...immutable ORM-managed columns did NOT (verified via direct SQL).
        self.assertEqual(after.id, before.id)
        self.assertEqual(after.created_at, before.created_at)
        self.assertEqual(after.status, before.status)  # still 'draft'

    def test_update_missing_raises_lookuperror(self) -> None:
        ghost = _sample_config("never-added")
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyCompetitionRepository(s).update(ghost)

    def test_duplicate_slug_add_raises_integrity_error(self) -> None:
        cfg = _sample_config("dupe")
        clash = _sample_config("dupe")  # same competition_id -> same slug
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyCompetitionRepository(s).add(cfg)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyCompetitionRepository(s).add(clash)

    def test_check_constraint_end_before_start_raises(self) -> None:
        start = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
        bad = CompetitionConfig(
            competition_id="bad-window",
            name="Bad Window",
            start_time=start,
            end_time=start - timedelta(hours=1),  # end_time <= start_time
        )
        with _migrated_database() as (db, _url):
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyCompetitionRepository(s).add(bad)

    def test_rollback_discards_add(self) -> None:
        cfg = _sample_config("rolled-back")
        with _migrated_database() as (db, _url):
            with self.assertRaises(RuntimeError):
                with db.session_scope() as s:
                    SqlAlchemyCompetitionRepository(s).add(cfg)
                    raise RuntimeError("boom")  # aborts the unit of work
            # The add was rolled back with the scope -- nothing persisted.
            with db.session_scope() as s:
                self.assertIsNone(
                    SqlAlchemyCompetitionRepository(s).get(cfg.competition_id)
                )

    def test_timezone_instant_preserved_as_utc(self) -> None:
        # A tz-aware datetime in a NON-UTC offset (+05:00).
        offset = timezone(timedelta(hours=5))
        start = datetime(2026, 6, 1, 14, 0, tzinfo=offset)
        cfg = CompetitionConfig(
            competition_id="tz-comp",
            name="TZ Comp",
            start_time=start,
            end_time=start + timedelta(hours=12),
        )
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyCompetitionRepository(s).add(cfg)
            with db.session_scope() as s:
                fetched = SqlAlchemyCompetitionRepository(s).get("tz-comp")

        # The same INSTANT round-trips: an aware compare against both the
        # original +05:00 value and its UTC equivalent (both hold regardless of
        # the server's session TimeZone GUC -- instant equality is what matters).
        self.assertEqual(fetched.start_time, start)
        self.assertEqual(
            fetched.start_time, datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
        )
        # timestamptz always returns a tz-AWARE datetime (never naive); the exact
        # rendered offset depends on the session tz, so we don't pin it to UTC.
        self.assertIsNotNone(fetched.start_time.utcoffset())

    def test_default_scoring_add_raises_not_implemented(self) -> None:
        cfg = _sample_config("with-scoring")
        cfg = CompetitionConfig(
            competition_id=cfg.competition_id,
            name=cfg.name,
            start_time=cfg.start_time,
            end_time=cfg.end_time,
            default_scoring=ChallengeScoringConfig(challenge_id="c1"),
        )
        with _migrated_database() as (db, _url):
            with self.assertRaises(NotImplementedError):
                with db.session_scope() as s:
                    SqlAlchemyCompetitionRepository(s).add(cfg)

    def test_migration_upgrade_then_downgrade_runs_clean(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            engine = sa.create_engine(url, future=True)
            try:
                # Upgrade to THIS aggregate's revision explicitly (not "head") so
                # the test stays about the competitions migration as later
                # migrations are stacked on top of it.
                command.upgrade(cfg, "0002_competitions")
                insp = sa.inspect(engine)
                self.assertIn("competitions", insp.get_table_names())
                with engine.connect() as conn:
                    version = conn.execute(
                        sa.text("SELECT version_num FROM alembic_version")
                    ).scalar()
                self.assertEqual(version, "0002_competitions")

                command.downgrade(cfg, "base")
                insp = sa.inspect(engine)
                self.assertNotIn("competitions", insp.get_table_names())
                with engine.connect() as conn:
                    remaining = conn.execute(
                        sa.text("SELECT count(*) FROM alembic_version")
                    ).scalar()
                self.assertEqual(remaining, 0)
            finally:
                engine.dispose()

    def test_returned_config_usable_after_session_closes(self) -> None:
        cfg = _sample_config("detached")
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyCompetitionRepository(s).add(cfg)
            with db.session_scope() as s:
                fetched = SqlAlchemyCompetitionRepository(s).get("detached")
            # Session (and its transaction) are now CLOSED. The returned value
            # is a plain frozen dataclass, so attribute access must still work
            # with no lazy-load / DetachedInstanceError.
            self.assertEqual(fetched.competition_id, "detached")
            self.assertEqual(fetched.name, cfg.name)
            self.assertEqual(fetched.start_time, cfg.start_time)
            self.assertEqual(fetched.end_time, cfg.end_time)
            self.assertEqual(fetched.freeze_time, cfg.freeze_time)


if __name__ == "__main__":
    unittest.main()
