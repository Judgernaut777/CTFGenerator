"""PostgreSQL integration tests for the challenge-authoring aggregates (M6 Epic 2).

Docker-gated, like the other repository integration suites: requires the ``db``
extra and ``CTFGEN_TEST_DATABASE_URL``; skips cleanly otherwise so the stdlib
host suite stays green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_challenge_repository_integration
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
    from sqlalchemy.exc import DBAPIError, IntegrityError

    from ctf_generator.domain.authoring.models import (
        ChallengeBuild,
        ChallengeDefinition,
        ChallengePublication,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
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
    from ctf_generator.infrastructure.database.models import (
        ChallengeDefinition as ChallengeDefinitionRow,
    )
    from ctf_generator.infrastructure.database.session import Database

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
_ARCHIVE_TS = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


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


def _competition(competition_id: str = "cup") -> CompetitionConfig:
    return CompetitionConfig(
        competition_id=competition_id,
        name=f"Comp {competition_id}",
        start_time=_NOW,
        end_time=_NOW + timedelta(hours=48),
    )


def _definition(slug: str = "sql-injection", family: str = "web_business_logic_tenant_export"):
    return ChallengeDefinition(family=family, slug=slug, title="SQL Injection")


def _version(
    slug: str = "sql-injection",
    version_no: int = 1,
    *,
    state: str = "draft",
    spec_sha256: str = "spec-hash-1",
    published_at: datetime | None = None,
    cve_refs: tuple[str, ...] = (),
):
    return ChallengeVersion(
        definition_slug=slug,
        version_no=version_no,
        state=state,
        family_version="1.0",
        seed="seed-abc",
        spec_sha256=spec_sha256,
        spec={"title": "SQL Injection", "family": "web", "seed": "seed-abc"},
        spec_version="1.0",
        mode="red",
        cve_refs=cve_refs,
        published_at=published_at,
    )


def _seed_def_and_draft(db, slug: str = "sql-injection") -> None:
    with db.session_scope() as s:
        SqlAlchemyChallengeDefinitionRepository(s).add(_definition(slug))
        SqlAlchemyChallengeVersionRepository(s).add(_version(slug))


def _publish(db, slug: str = "sql-injection", version_no: int = 1) -> None:
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish(slug, version_no, _NOW)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ChallengeDefinitionRepositoryTests(unittest.TestCase):
    def test_add_get_round_trip(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition())
            with db.session_scope() as s:
                got = SqlAlchemyChallengeDefinitionRepository(s).get("sql-injection")
        self.assertIsInstance(got, ChallengeDefinition)
        self.assertNotIsInstance(got, ChallengeDefinitionRow)
        self.assertEqual(got.slug, "sql-injection")
        self.assertEqual(got.title, "SQL Injection")

    def test_duplicate_slug_raises(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition())
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeDefinitionRepository(s).add(_definition())

    def test_update_title_preserves_identity(self) -> None:
        with _migrated_database() as (db, url):
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition())
            engine = sa.create_engine(url, future=True)
            try:
                with engine.connect() as conn:
                    before = conn.execute(
                        sa.text(
                            "SELECT id, family, created_at FROM challenge_definitions "
                            "WHERE slug = 'sql-injection'"
                        )
                    ).one()
                with db.session_scope() as s:
                    SqlAlchemyChallengeDefinitionRepository(s).update(
                        ChallengeDefinition(
                            family="web_business_logic_tenant_export",
                            slug="sql-injection",
                            title="Renamed",
                        )
                    )
                with db.session_scope() as s:
                    got = SqlAlchemyChallengeDefinitionRepository(s).get("sql-injection")
                with engine.connect() as conn:
                    after = conn.execute(
                        sa.text(
                            "SELECT id, family, created_at FROM challenge_definitions "
                            "WHERE slug = 'sql-injection'"
                        )
                    ).one()
            finally:
                engine.dispose()
        self.assertEqual(got.title, "Renamed")
        self.assertEqual(after.id, before.id)
        self.assertEqual(after.created_at, before.created_at)

    def test_update_missing_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeDefinitionRepository(s).update(_definition("ghost"))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ChallengeVersionRepositoryTests(unittest.TestCase):
    def test_add_get_round_trip_including_jsonb(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                got = SqlAlchemyChallengeVersionRepository(s).get("sql-injection", 1)
        self.assertIsInstance(got, ChallengeVersion)
        self.assertEqual(got.state, "draft")
        self.assertIsNone(got.published_at)
        self.assertEqual(got.spec_sha256, "spec-hash-1")
        # jsonb round-trips at the dict level.
        self.assertEqual(got.spec, {"title": "SQL Injection", "family": "web", "seed": "seed-abc"})
        self.assertEqual(got.cve_refs, ())

    def test_cve_refs_round_trip(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition())
                SqlAlchemyChallengeVersionRepository(s).add(
                    _version(cve_refs=("CVE-2023-1", "CVE-2023-2"))
                )
            with db.session_scope() as s:
                got = SqlAlchemyChallengeVersionRepository(s).get("sql-injection", 1)
        self.assertEqual(got.cve_refs, ("CVE-2023-1", "CVE-2023-2"))

    def test_add_missing_definition_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeVersionRepository(s).add(_version("no-def"))

    def test_duplicate_version_no_raises(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeVersionRepository(s).add(
                        _version(version_no=1, spec_sha256="different")
                    )

    def test_duplicate_spec_sha256_raises(self) -> None:
        # Re-generating the identical spec must not fork into a new version row.
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeVersionRepository(s).add(
                        _version(version_no=2, spec_sha256="spec-hash-1")
                    )

    def test_get_by_spec_sha256(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                got = SqlAlchemyChallengeVersionRepository(s).get_by_spec_sha256(
                    "sql-injection", "spec-hash-1"
                )
        self.assertIsNotNone(got)
        self.assertEqual(got.version_no, 1)

    def test_list_for_definition_ordered(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition())
                repo = SqlAlchemyChallengeVersionRepository(s)
                repo.add(_version(version_no=1, spec_sha256="h1"))
                repo.add(_version(version_no=2, spec_sha256="h2"))
                repo.add(_version(version_no=3, spec_sha256="h3"))
            with db.session_scope() as s:
                versions = SqlAlchemyChallengeVersionRepository(s).list_for_definition(
                    "sql-injection"
                )
        self.assertEqual([v.version_no for v in versions], [1, 2, 3])

    def test_publish_then_archive(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            _publish(db)
            with db.session_scope() as s:
                published = SqlAlchemyChallengeVersionRepository(s).get("sql-injection", 1)
            self.assertEqual(published.state, "published")
            self.assertIsNotNone(published.published_at)
            with db.session_scope() as s:
                SqlAlchemyChallengeVersionRepository(s).archive(
                    "sql-injection", 1, _ARCHIVE_TS
                )
            with db.session_scope() as s:
                archived = SqlAlchemyChallengeVersionRepository(s).get("sql-injection", 1)
                # archived_at is stamped (soft-archival convention, design §9).
                archived_at = s.execute(
                    sa.text(
                        "SELECT archived_at FROM challenge_versions WHERE version_no = 1"
                    )
                ).scalar_one()
        self.assertEqual(archived.state, "archived")
        # published_at is RETAINED through archival (provenance preserved).
        self.assertEqual(archived.published_at, published.published_at)
        self.assertIsNotNone(archived_at)  # archive() stamped archived_at

    def test_publish_non_draft_raises_valueerror(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            _publish(db)
            with self.assertRaises(ValueError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeVersionRepository(s).publish("sql-injection", 1, _NOW)

    def test_publish_missing_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition())
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeVersionRepository(s).publish("sql-injection", 99, _NOW)

    def test_archive_non_published_raises_valueerror(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with self.assertRaises(ValueError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeVersionRepository(s).archive(
                        "sql-injection", 1, _ARCHIVE_TS
                    )

    def test_publish_none_timestamp_raises_valueerror(self) -> None:
        # A None timestamp is a clean ValueError, not a raw IntegrityError.
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with self.assertRaises(ValueError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeVersionRepository(s).publish(
                        "sql-injection", 1, None
                    )

    def test_get_by_spec_sha256_miss_returns_none(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                self.assertIsNone(
                    SqlAlchemyChallengeVersionRepository(s).get_by_spec_sha256(
                        "sql-injection", "no-such-hash"
                    )
                )

    def test_trigger_blocks_archived_content_mutation(self) -> None:
        # The freeze backstop must cover ARCHIVED rows too (not just published).
        with _migrated_database() as (db, url):
            _seed_def_and_draft(db)
            _publish(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeVersionRepository(s).archive(
                    "sql-injection", 1, _ARCHIVE_TS
                )
            engine = sa.create_engine(url, future=True)
            try:
                with self.assertRaises(DBAPIError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "UPDATE challenge_versions SET spec_sha256 = 'tampered' "
                                "WHERE version_no = 1"
                            )
                        )
            finally:
                engine.dispose()

    def test_trigger_blocks_archived_reactivation(self) -> None:
        # archived is terminal: archived -> published must be rejected.
        with _migrated_database() as (db, url):
            _seed_def_and_draft(db)
            _publish(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeVersionRepository(s).archive(
                    "sql-injection", 1, _ARCHIVE_TS
                )
            engine = sa.create_engine(url, future=True)
            try:
                with self.assertRaises(DBAPIError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "UPDATE challenge_versions SET state = 'published' "
                                "WHERE version_no = 1"
                            )
                        )
            finally:
                engine.dispose()

    def test_trigger_blocks_published_content_mutation(self) -> None:
        # DB backstop: even a raw UPDATE cannot change published content.
        with _migrated_database() as (db, url):
            _seed_def_and_draft(db)
            _publish(db)
            engine = sa.create_engine(url, future=True)
            try:
                with self.assertRaises(DBAPIError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "UPDATE challenge_versions SET spec_sha256 = 'tampered' "
                                "WHERE version_no = 1"
                            )
                        )
            finally:
                engine.dispose()

    def test_trigger_blocks_illegal_state_move(self) -> None:
        # published -> draft is not allowed by the trigger.
        with _migrated_database() as (db, url):
            _seed_def_and_draft(db)
            _publish(db)
            engine = sa.create_engine(url, future=True)
            try:
                with self.assertRaises(DBAPIError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "UPDATE challenge_versions "
                                "SET state = 'draft', published_at = NULL "
                                "WHERE version_no = 1"
                            )
                        )
            finally:
                engine.dispose()

    def test_check_rejects_draft_with_published_at(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition())
            # A draft carrying a published_at violates the state/timestamp CHECK.
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    def_id = s.execute(
                        sa.text(
                            "SELECT id FROM challenge_definitions WHERE slug='sql-injection'"
                        )
                    ).scalar_one()
                    s.execute(
                        sa.text(
                            "INSERT INTO challenge_versions "
                            "(id, definition_id, version_no, state, family_version, seed, "
                            " mode, spec_sha256, spec_json, spec_version, published_at) "
                            "VALUES (gen_random_uuid(), :d, 5, 'draft', '1.0', 's', 'red', "
                            " 'h', '{}'::jsonb, '1.0', now())"
                        ),
                        {"d": def_id},
                    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ChallengeBuildRepositoryTests(unittest.TestCase):
    def _build(
        self,
        *,
        build_sha256="build-hash-1",
        spec_sha256="spec-hash-1",
        generator_version="0.9.0",
    ):
        return ChallengeBuild(
            build_sha256=build_sha256,
            definition_slug="sql-injection",
            version_no=1,
            family="web_business_logic_tenant_export",
            seed="seed-abc",
            spec_sha256=spec_sha256,
            generator_version=generator_version,
            manifest={"files": ["a", "b"]},
            family_version="1.0",
        )

    def test_add_get_round_trip(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildRepository(s).add(self._build())
            with db.session_scope() as s:
                got = SqlAlchemyChallengeBuildRepository(s).get("build-hash-1")
        self.assertIsInstance(got, ChallengeBuild)
        self.assertEqual(got.definition_slug, "sql-injection")
        self.assertEqual(got.version_no, 1)
        self.assertEqual(got.manifest, {"files": ["a", "b"]})

    def test_add_spec_sha256_mismatch_raises_valueerror(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with self.assertRaises(ValueError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeBuildRepository(s).add(
                        self._build(spec_sha256="does-not-match")
                    )

    def test_add_missing_version_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition())
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeBuildRepository(s).add(self._build())

    def test_duplicate_build_sha256_raises(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildRepository(s).add(self._build())
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeBuildRepository(s).add(self._build())

    def test_list_for_version(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                repo = SqlAlchemyChallengeBuildRepository(s)
                # Two builds of one version = a rebuild under a newer generator
                # (differing on the toolchain half of the unique key).
                repo.add(self._build(build_sha256="b1", generator_version="0.9.0"))
                repo.add(self._build(build_sha256="b2", generator_version="0.9.1"))
            with db.session_scope() as s:
                builds = SqlAlchemyChallengeBuildRepository(s).list_for_version(
                    "sql-injection", 1
                )
        self.assertEqual({b.build_sha256 for b in builds}, {"b1", "b2"})

    def test_trigger_blocks_build_update_and_delete(self) -> None:
        with _migrated_database() as (db, url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildRepository(s).add(self._build())
            engine = sa.create_engine(url, future=True)
            try:
                with self.assertRaises(DBAPIError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "UPDATE challenge_builds SET seed = 'x' "
                                "WHERE build_sha256 = 'build-hash-1'"
                            )
                        )
                with self.assertRaises(DBAPIError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "DELETE FROM challenge_builds "
                                "WHERE build_sha256 = 'build-hash-1'"
                            )
                        )
                # TRUNCATE must also be blocked (row triggers don't fire on it).
                with self.assertRaises(DBAPIError):
                    with engine.begin() as conn:
                        conn.execute(sa.text("TRUNCATE challenge_builds"))
            finally:
                engine.dispose()

    def test_null_family_version_builds_collide_on_toolchain_seed(self) -> None:
        # With NULLS NOT DISTINCT, two builds of one version with the SAME
        # (generator_version, seed) and a NULL family_version must collide.
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildRepository(s).add(
                    ChallengeBuild(
                        build_sha256="null-fam-1",
                        definition_slug="sql-injection",
                        version_no=1,
                        family="web",
                        seed="seed-abc",
                        spec_sha256="spec-hash-1",
                        generator_version="0.9.0",
                        manifest={},
                        family_version=None,
                    )
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyChallengeBuildRepository(s).add(
                        ChallengeBuild(
                            build_sha256="null-fam-2",  # different content hash
                            definition_slug="sql-injection",
                            version_no=1,
                            family="web",
                            seed="seed-abc",
                            spec_sha256="spec-hash-1",
                            generator_version="0.9.0",
                            manifest={},
                            family_version=None,  # same NULL toolchain+seed
                        )
                    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ChallengePublicationRepositoryTests(unittest.TestCase):
    def _setup_published(self, db) -> None:
        with db.session_scope() as s:
            SqlAlchemyCompetitionRepository(s).add(_competition())
        _seed_def_and_draft(db)
        _publish(db)

    def test_add_get_round_trip(self) -> None:
        with _migrated_database() as (db, _url):
            self._setup_published(db)
            with db.session_scope() as s:
                SqlAlchemyChallengePublicationRepository(s).add(
                    ChallengePublication(
                        competition_id="cup",
                        definition_slug="sql-injection",
                        version_no=1,
                        initial_value=400,
                        minimum_value=50,
                        decay_function="linear",
                        decay=10,
                    )
                )
            with db.session_scope() as s:
                got = SqlAlchemyChallengePublicationRepository(s).get(
                    "cup", "sql-injection", 1
                )
        self.assertIsInstance(got, ChallengePublication)
        self.assertEqual(got.initial_value, 400)
        self.assertEqual(got.decay_function, "linear")

    def test_add_unpublished_version_raises_valueerror(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyCompetitionRepository(s).add(_competition())
            _seed_def_and_draft(db)  # draft, NOT published
            with self.assertRaises(ValueError):
                with db.session_scope() as s:
                    SqlAlchemyChallengePublicationRepository(s).add(
                        ChallengePublication(
                            competition_id="cup",
                            definition_slug="sql-injection",
                            version_no=1,
                        )
                    )

    def test_add_missing_competition_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            _publish(db)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyChallengePublicationRepository(s).add(
                        ChallengePublication(
                            competition_id="no-comp",
                            definition_slug="sql-injection",
                            version_no=1,
                        )
                    )

    def test_duplicate_attach_raises(self) -> None:
        with _migrated_database() as (db, _url):
            self._setup_published(db)
            with db.session_scope() as s:
                SqlAlchemyChallengePublicationRepository(s).add(
                    ChallengePublication("cup", "sql-injection", 1)
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyChallengePublicationRepository(s).add(
                        ChallengePublication("cup", "sql-injection", 1)
                    )

    def test_update_scoring_preserves_identity(self) -> None:
        with _migrated_database() as (db, url):
            self._setup_published(db)
            with db.session_scope() as s:
                SqlAlchemyChallengePublicationRepository(s).add(
                    ChallengePublication("cup", "sql-injection", 1, initial_value=500)
                )
            engine = sa.create_engine(url, future=True)
            try:
                with engine.connect() as conn:
                    before = conn.execute(
                        sa.text("SELECT id, created_at FROM competition_challenges")
                    ).one()
                with db.session_scope() as s:
                    SqlAlchemyChallengePublicationRepository(s).update(
                        ChallengePublication(
                            "cup", "sql-injection", 1, initial_value=300, minimum_value=100
                        )
                    )
                with db.session_scope() as s:
                    got = SqlAlchemyChallengePublicationRepository(s).get(
                        "cup", "sql-injection", 1
                    )
                with engine.connect() as conn:
                    after = conn.execute(
                        sa.text("SELECT id, created_at FROM competition_challenges")
                    ).one()
            finally:
                engine.dispose()
        self.assertEqual(got.initial_value, 300)
        self.assertEqual(after.id, before.id)
        self.assertEqual(after.created_at, before.created_at)

    def test_update_missing_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            self._setup_published(db)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyChallengePublicationRepository(s).update(
                        ChallengePublication("cup", "sql-injection", 1)
                    )

    def test_list_for_competition(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyCompetitionRepository(s).add(_competition())
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition("a"))
                SqlAlchemyChallengeDefinitionRepository(s).add(_definition("b"))
                vr = SqlAlchemyChallengeVersionRepository(s)
                vr.add(_version("a", spec_sha256="ha"))
                vr.add(_version("b", spec_sha256="hb"))
            with db.session_scope() as s:
                vr = SqlAlchemyChallengeVersionRepository(s)
                vr.publish("a", 1, _NOW)
                vr.publish("b", 1, _NOW)
            with db.session_scope() as s:
                pr = SqlAlchemyChallengePublicationRepository(s)
                pr.add(ChallengePublication("cup", "a", 1))
                pr.add(ChallengePublication("cup", "b", 1))
            with db.session_scope() as s:
                pubs = SqlAlchemyChallengePublicationRepository(s).list_for_competition("cup")
        self.assertEqual({p.definition_slug for p in pubs}, {"a", "b"})


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ChallengeConstraintTests(unittest.TestCase):
    """DB-level backstops that don't route through the repositories -- proving
    the schema itself enforces FK RESTRICT and the scoring CHECKs."""

    def _setup_published_attached(self, db) -> None:
        with db.session_scope() as s:
            SqlAlchemyCompetitionRepository(s).add(_competition())
        _seed_def_and_draft(db)
        _publish(db)

    def test_fk_restrict_blocks_deleting_definition_with_version(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(
                        sa.text(
                            "DELETE FROM challenge_definitions WHERE slug='sql-injection'"
                        )
                    )

    def test_fk_restrict_blocks_deleting_version_with_build(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_def_and_draft(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildRepository(s).add(
                    ChallengeBuild(
                        build_sha256="b1",
                        definition_slug="sql-injection",
                        version_no=1,
                        family="web",
                        seed="seed-abc",
                        spec_sha256="spec-hash-1",
                        generator_version="0.9.0",
                        manifest={},
                    )
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM challenge_versions WHERE version_no=1"))

    def test_fk_restrict_blocks_deleting_version_with_publication(self) -> None:
        with _migrated_database() as (db, _url):
            self._setup_published_attached(db)
            with db.session_scope() as s:
                SqlAlchemyChallengePublicationRepository(s).add(
                    ChallengePublication("cup", "sql-injection", 1)
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM challenge_versions WHERE version_no=1"))

    def test_fk_restrict_blocks_deleting_competition_with_publication(self) -> None:
        with _migrated_database() as (db, _url):
            self._setup_published_attached(db)
            with db.session_scope() as s:
                SqlAlchemyChallengePublicationRepository(s).add(
                    ChallengePublication("cup", "sql-injection", 1)
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM competitions WHERE slug='cup'"))

    def _raw_insert_publication(self, db, **cols) -> None:
        """Raw-insert a competition_challenges row (bypassing the domain) with
        resolved FKs and caller-overridable scoring columns, to exercise DB CHECKs."""
        defaults = {
            "initial_value": 500,
            "minimum_value": 100,
            "decay_function": "static",
            "decay": 0,
        }
        defaults.update(cols)
        with db.session_scope() as s:
            comp_id = s.execute(
                sa.text("SELECT id FROM competitions WHERE slug='cup'")
            ).scalar_one()
            ver_id = s.execute(
                sa.text("SELECT id FROM challenge_versions WHERE version_no=1")
            ).scalar_one()
            s.execute(
                sa.text(
                    "INSERT INTO competition_challenges "
                    "(id, competition_id, challenge_version_id, initial_value, "
                    " minimum_value, decay_function, decay) VALUES "
                    "(gen_random_uuid(), :c, :v, :iv, :mv, :df, :d)"
                ),
                {
                    "c": comp_id,
                    "v": ver_id,
                    "iv": defaults["initial_value"],
                    "mv": defaults["minimum_value"],
                    "df": defaults["decay_function"],
                    "d": defaults["decay"],
                },
            )

    def test_check_minimum_gt_initial_rejected(self) -> None:
        with _migrated_database() as (db, _url):
            self._setup_published_attached(db)
            with self.assertRaises(IntegrityError):
                self._raw_insert_publication(db, initial_value=100, minimum_value=200)

    def test_check_negative_initial_rejected(self) -> None:
        with _migrated_database() as (db, _url):
            self._setup_published_attached(db)
            with self.assertRaises(IntegrityError):
                self._raw_insert_publication(db, initial_value=-1, minimum_value=-1)

    def test_check_bad_decay_function_rejected(self) -> None:
        with _migrated_database() as (db, _url):
            self._setup_published_attached(db)
            with self.assertRaises(IntegrityError):
                self._raw_insert_publication(db, decay_function="exponential")


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ChallengeMigrationTests(unittest.TestCase):
    @staticmethod
    def _trigger_functions(conn) -> set[str]:
        return set(
            conn.execute(
                sa.text(
                    "SELECT proname FROM pg_proc WHERE proname IN "
                    "('reject_mutation', 'freeze_published_version')"
                )
            )
            .scalars()
            .all()
        )

    def test_migration_upgrade_downgrade(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            engine = sa.create_engine(url, future=True)
            try:
                # Upgrade to THIS aggregate's revision explicitly (not "head") so
                # the test stays stable when Epic 3 stacks 0005 on top.
                command.upgrade(cfg, "0004_challenges")
                insp = sa.inspect(engine)
                for t in (
                    "challenge_definitions",
                    "challenge_versions",
                    "challenge_builds",
                    "competition_challenges",
                ):
                    self.assertIn(t, insp.get_table_names())
                with engine.connect() as conn:
                    self.assertEqual(
                        conn.execute(
                            sa.text("SELECT version_num FROM alembic_version")
                        ).scalar(),
                        "0004_challenges",
                    )
                    # Both trigger functions exist after upgrade.
                    self.assertEqual(
                        self._trigger_functions(conn),
                        {"reject_mutation", "freeze_published_version"},
                    )
                # One step back removes the challenge tables, keeps identity, and
                # drops the trigger functions.
                command.downgrade(cfg, "0003_identity")
                insp = sa.inspect(engine)
                self.assertNotIn("challenge_versions", insp.get_table_names())
                self.assertIn("users", insp.get_table_names())
                with engine.connect() as conn:
                    self.assertEqual(self._trigger_functions(conn), set())

                # up -> down -> up must be clean (triggers/functions re-create,
                # not error on a leaked object).
                command.upgrade(cfg, "0004_challenges")
                insp = sa.inspect(engine)
                self.assertIn("challenge_builds", insp.get_table_names())

                command.downgrade(cfg, "base")
                with engine.connect() as conn:
                    self.assertEqual(
                        conn.execute(
                            sa.text("SELECT count(*) FROM alembic_version")
                        ).scalar(),
                        0,
                    )
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
