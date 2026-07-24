"""PostgreSQL integration test: instance launch resolves the built image
(build_challenge slice 2).

Proves the launch-side wiring: when ``request_instance`` is called without an
explicit ``image_ref``, it resolves the freshly-built image for
``(definition_slug, version_no)`` from the ``challenge_build_images`` registry a
worker populated at build-completion time, and threads it onto the persisted
``Instance.image_ref``. A version with no recorded build leaves ``image_ref``
``None`` (the create-time behaviour is preserved -- no hard reject), and an
explicit ``image_ref`` bypasses the lookup entirely.

Docker-gated like the other repository suites; skips cleanly without the db
extra / ``CTFGEN_TEST_DATABASE_URL``.
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

    from ctf_generator.application.instances.service import InstanceLifecycleService
    from ctf_generator.application.jobs.service import JobService
    from ctf_generator.application.scheduling.service import SchedulingService
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.scheduling.models import (
        PLATFORM_SCOPE_KEY,
        ReservationItem,
        ResourceQuota,
        WorkerRequirements,
    )
    from ctf_generator.infrastructure.database.challenge_build_image_repository import (
        SqlAlchemyChallengeBuildImageRepository,
    )
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
    from ctf_generator.infrastructure.database.instance_repository import (
        SqlAlchemyInstanceRepository,
    )
    from ctf_generator.infrastructure.database.quota_repository import (
        SqlAlchemyQuotaPolicyRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
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

_NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(hours=2)
_IMG = "ctfgen-build/sql:v1-abcdef0123456789"
_DIGEST = "sha256:" + "f" * 64
_BUNDLE = "0" * 64


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
            yield db
        finally:
            db.dispose()


def _seed_parents(db) -> None:
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
                spec={"t": 1},
                spec_version="1.0",
            )
        )
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish("sql", 1, _NOW)
    with db.session_scope() as s:
        reg = SqlAlchemyWorkerRegistry(s)
        reg.add(
            Worker("w1", "docker-rootless", ("x86_64",), ("launch_instance",), 4, "1")
        )
        reg.approve("w1")
        reg.heartbeat("w1", _NOW)
    with db.session_scope() as s:
        SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
            ResourceQuota("platform", PLATFORM_SCOPE_KEY, "active_instances", 100)
        )


def _record_build_image(db) -> None:
    with db.session_scope() as s:
        SqlAlchemyChallengeBuildImageRepository(s).add(
            "sql", 1, _IMG, _DIGEST, _BUNDLE, _NOW
        )


def _requirements() -> WorkerRequirements:
    return WorkerRequirements(
        architecture="x86_64", required_capabilities=frozenset({"launch_instance"})
    )


def _platform_item(amount: int = 1) -> ReservationItem:
    return ReservationItem("platform", PLATFORM_SCOPE_KEY, "active_instances", amount)


def _lifecycle(db) -> InstanceLifecycleService:
    return InstanceLifecycleService(
        db, scheduling=SchedulingService(db), jobs=JobService(db)
    )


def _request(lifecycle, iid, **overrides):
    kwargs = dict(
        instance_id=iid,
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        requirements=_requirements(),
        pooled_items=(_platform_item(),),
        expires_at=_LATER,
        now=_NOW,
    )
    kwargs.update(overrides)
    return lifecycle.request_instance(**kwargs)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class InstanceLaunchImageWiringTests(unittest.TestCase):
    def test_built_image_is_resolved_onto_the_instance(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            _record_build_image(db)
            iid = str(uuid.uuid4())
            placed = _request(_lifecycle(db), iid)
            with db.session_scope() as s:
                stored = SqlAlchemyInstanceRepository(s).get(iid)
        self.assertEqual(placed.image_ref, _IMG)
        self.assertEqual(stored.image_ref, _IMG)

    def test_missing_build_leaves_image_ref_none(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)  # no build image recorded
            iid = str(uuid.uuid4())
            placed = _request(_lifecycle(db), iid)
            with db.session_scope() as s:
                stored = SqlAlchemyInstanceRepository(s).get(iid)
        self.assertIsNone(placed.image_ref)
        self.assertIsNone(stored.image_ref)

    def test_explicit_image_ref_bypasses_the_lookup(self) -> None:
        with _migrated_database() as db:
            _seed_parents(db)
            _record_build_image(db)  # a built image exists...
            iid = str(uuid.uuid4())
            # ...but an explicit image_ref must win (back-compat with callers
            # that pin the image, e.g. tests).
            placed = _request(_lifecycle(db), iid, image_ref="pinned/image:v9")
            with db.session_scope() as s:
                stored = SqlAlchemyInstanceRepository(s).get(iid)
        self.assertEqual(placed.image_ref, "pinned/image:v9")
        self.assertEqual(stored.image_ref, "pinned/image:v9")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
