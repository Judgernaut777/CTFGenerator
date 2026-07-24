"""PostgreSQL integration tests for the challenge_build_images registry
(build_challenge slice 2).

Docker-gated like the other repository suites: requires the ``db`` extra and
``CTFGEN_TEST_DATABASE_URL``; skips cleanly otherwise so the stdlib host suite
stays green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest \\
      test_challenge_build_image_repository_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ProgrammingError

    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
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
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.models import (
        ChallengeBuildImage as ChallengeBuildImageRow,
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

_NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
_SLUG = "invoice-drift"
_IMG_A = "ctfgen-build/invoice-drift:v1-aaaaaaaaaaaaaaaa"
_IMG_B = "ctfgen-build/invoice-drift:v1-bbbbbbbbbbbbbbbb"
_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_BUNDLE = "c" * 64


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


def _seed_version(db) -> None:
    with db.session_scope() as s:
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family="web", slug=_SLUG, title="Invoice Drift")
        )
        SqlAlchemyChallengeVersionRepository(s).add(
            ChallengeVersion(
                definition_slug=_SLUG,
                version_no=1,
                state="draft",
                family_version="1.0",
                seed="seed-abc",
                spec_sha256="spec-hash-1",
                spec={"title": "Invoice Drift"},
                spec_version="1.0",
                mode="red",
                published_at=None,
            )
        )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ChallengeBuildImageRepositoryTests(unittest.TestCase):
    def test_add_then_latest_round_trip(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildImageRepository(s).add(
                    _SLUG, 1, _IMG_A, _DIGEST_A, _BUNDLE, _NOW
                )
            with db.session_scope() as s:
                got = SqlAlchemyChallengeBuildImageRepository(
                    s
                ).latest_image_ref_for_version(_SLUG, 1)
        self.assertEqual(got, _IMG_A)

    def test_latest_is_none_for_version_without_a_build(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            with db.session_scope() as s:
                got = SqlAlchemyChallengeBuildImageRepository(
                    s
                ).latest_image_ref_for_version(_SLUG, 1)
        self.assertIsNone(got)

    def test_latest_is_none_for_unknown_version(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            with db.session_scope() as s:
                got = SqlAlchemyChallengeBuildImageRepository(
                    s
                ).latest_image_ref_for_version("no-such-slug", 99)
        self.assertIsNone(got)

    def test_add_is_idempotent_on_same_version_and_digest(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            # Two completions of the same deterministic build (same digest) must
            # collapse to ONE row via ON CONFLICT DO NOTHING -- never raise.
            for _ in range(2):
                with db.session_scope() as s:
                    SqlAlchemyChallengeBuildImageRepository(s).add(
                        _SLUG, 1, _IMG_A, _DIGEST_A, _BUNDLE, _NOW
                    )
            with db.session_scope() as s:
                count = s.scalar(
                    sa.select(sa.func.count()).select_from(ChallengeBuildImageRow)
                )
        self.assertEqual(count, 1)

    def test_latest_returns_newest_by_created_at(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            # Two DISTINCT digests in two separate transactions -> distinct
            # transaction-start now() -> deterministic newest.
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildImageRepository(s).add(
                    _SLUG, 1, _IMG_A, _DIGEST_A, _BUNDLE, _NOW
                )
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildImageRepository(s).add(
                    _SLUG, 1, _IMG_B, _DIGEST_B, _BUNDLE, _NOW
                )
            with db.session_scope() as s:
                got = SqlAlchemyChallengeBuildImageRepository(
                    s
                ).latest_image_ref_for_version(_SLUG, 1)
        self.assertEqual(got, _IMG_B)

    def test_add_raises_lookup_error_for_unknown_version(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            with db.session_scope() as s:
                with self.assertRaises(LookupError):
                    SqlAlchemyChallengeBuildImageRepository(s).add(
                        "no-such-slug", 99, _IMG_A, _DIGEST_A, _BUNDLE, _NOW
                    )

    def test_row_is_append_only_update_is_rejected(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildImageRepository(s).add(
                    _SLUG, 1, _IMG_A, _DIGEST_A, _BUNDLE, _NOW
                )
            # The shared reject_mutation() trigger raises on UPDATE.
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(
                        sa.update(ChallengeBuildImageRow).values(image_ref="tampered")
                    )

    def test_row_is_append_only_delete_is_rejected(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            with db.session_scope() as s:
                SqlAlchemyChallengeBuildImageRepository(s).add(
                    _SLUG, 1, _IMG_A, _DIGEST_A, _BUNDLE, _NOW
                )
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.delete(ChallengeBuildImageRow))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
