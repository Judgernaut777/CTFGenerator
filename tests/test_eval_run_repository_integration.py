"""PostgreSQL integration tests for the EvalRun aggregate (M15 slice 15a).

Docker-gated like the other repository suites: requires the ``db`` extra and
``CTFGEN_TEST_DATABASE_URL``; skips cleanly otherwise so the stdlib host suite
stays green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_eval_run_repository_integration
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
    from alembic.script import ScriptDirectory
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import IntegrityError, ProgrammingError

    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.evaluation.models import EvalRun
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.eval_run_repository import (
        SqlAlchemyEvalRunRepository,
    )
    from ctf_generator.infrastructure.database.models import EvalRun as EvalRunRow
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
_DONE = datetime(2026, 7, 13, 12, 5, tzinfo=UTC)
_SLUG = "sqli"


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


def _version(state: str = "published") -> ChallengeVersion:
    return ChallengeVersion(
        definition_slug=_SLUG,
        version_no=1,
        state=state,
        family_version="1.0",
        seed="seed-abc",
        spec_sha256="spec-hash-1",
        spec={"title": "SQLi"},
        spec_version="1.0",
        mode="red",
        published_at=_NOW if state != "draft" else None,
    )


def _seed_published_version(db) -> None:
    with db.session_scope() as s:
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family="web", slug=_SLUG, title="SQLi")
        )
        SqlAlchemyChallengeVersionRepository(s).add(_version(state="draft"))
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish(_SLUG, 1, _NOW)


def _pending(profile: str = "writeup_replay", adversarial: bool = False) -> EvalRun:
    return EvalRun(
        eval_run_id=str(uuid.uuid4()),
        definition_slug=_SLUG,
        version_no=1,
        profile=profile,
        adversarial=adversarial,
        status="pending",
        requested_at=_NOW,
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class EvalRunRepositoryTests(unittest.TestCase):
    def test_head_is_eval_runs(self) -> None:
        cfg = _alembic_config(_TEST_URL)
        head = ScriptDirectory.from_config(cfg).get_current_head()
        self.assertEqual(head, "0013_eval_runs")

    def test_add_get_round_trip_returns_domain(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_published_version(db)
            run = _pending()
            with db.session_scope() as s:
                SqlAlchemyEvalRunRepository(s).add(run)
            with db.session_scope() as s:
                got = SqlAlchemyEvalRunRepository(s).get(run.eval_run_id)
        self.assertIsInstance(got, EvalRun)
        self.assertNotIsInstance(got, EvalRunRow)
        self.assertEqual(got.definition_slug, _SLUG)
        self.assertEqual(got.version_no, 1)
        self.assertEqual(got.status, "pending")
        self.assertIsNone(got.completed_at)
        self.assertIsNone(got.solved)

    def test_get_for_version_and_list(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_published_version(db)
            a = _pending(profile="writeup_replay")
            b = _pending(profile="one_shot_prompt", adversarial=True)
            with db.session_scope() as s:
                repo = SqlAlchemyEvalRunRepository(s)
                repo.add(a)
                repo.add(b)
            with db.session_scope() as s:
                repo = SqlAlchemyEvalRunRepository(s)
                found = repo.get_for_version(_SLUG, 1, "one_shot_prompt", True)
                listed = repo.list_for_version(_SLUG, 1)
        self.assertIsNotNone(found)
        self.assertEqual(found.eval_run_id, b.eval_run_id)
        self.assertEqual({r.eval_run_id for r in listed}, {a.eval_run_id, b.eval_run_id})

    def test_status_transition_persists(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_published_version(db)
            run = _pending()
            with db.session_scope() as s:
                SqlAlchemyEvalRunRepository(s).add(run)
            succeeded = EvalRun(
                eval_run_id=run.eval_run_id,
                definition_slug=_SLUG,
                version_no=1,
                profile=run.profile,
                adversarial=run.adversarial,
                status="succeeded",
                requested_at=_NOW,
                completed_at=_DONE,
                solved=True,
                steps=4,
                success_dropped=False,
                step_delta=2,
                blended_score=71.0,
                notes=("explored /flag",),
            )
            with db.session_scope() as s:
                SqlAlchemyEvalRunRepository(s).update(succeeded)
            with db.session_scope() as s:
                got = SqlAlchemyEvalRunRepository(s).get(run.eval_run_id)
        self.assertEqual(got.status, "succeeded")
        self.assertTrue(got.solved)
        self.assertEqual(got.steps, 4)
        self.assertEqual(got.blended_score, 71.0)
        self.assertEqual(got.completed_at, _DONE)

    def test_duplicate_dedupe_key_raises(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_published_version(db)
            with db.session_scope() as s:
                SqlAlchemyEvalRunRepository(s).add(_pending())
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    # Same (version, profile, adversarial), different id.
                    SqlAlchemyEvalRunRepository(s).add(_pending())

    def test_add_missing_version_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyEvalRunRepository(s).add(_pending())

    def test_update_missing_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_published_version(db)
            ghost = EvalRun(
                eval_run_id=str(uuid.uuid4()),
                definition_slug=_SLUG,
                version_no=1,
                profile="writeup_replay",
                adversarial=False,
                status="failed",
                requested_at=_NOW,
                completed_at=_DONE,
                error="boom",
            )
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyEvalRunRepository(s).update(ghost)

    def test_terminal_record_is_frozen_by_trigger(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_published_version(db)
            run = _pending()
            with db.session_scope() as s:
                SqlAlchemyEvalRunRepository(s).add(run)
            failed = EvalRun(
                eval_run_id=run.eval_run_id,
                definition_slug=_SLUG,
                version_no=1,
                profile=run.profile,
                adversarial=run.adversarial,
                status="failed",
                requested_at=_NOW,
                completed_at=_DONE,
                error="boom",
            )
            with db.session_scope() as s:
                SqlAlchemyEvalRunRepository(s).update(failed)
            # A second update to an already-terminal row is rejected by the guard.
            second = EvalRun(
                eval_run_id=run.eval_run_id,
                definition_slug=_SLUG,
                version_no=1,
                profile=run.profile,
                adversarial=run.adversarial,
                status="failed",
                requested_at=_NOW,
                completed_at=_DONE,
                error="different boom",
            )
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    SqlAlchemyEvalRunRepository(s).update(second)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
