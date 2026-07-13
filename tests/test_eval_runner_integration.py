"""PostgreSQL integration tests for SingleHostEvalJobRunner's control logic (M15b).

The concrete worker-side eval runner loads a published version from the DB and
renders its bundle, so its branch/guard logic needs a real version row -- but the
Docker leg (agent_eval building/running the challenge) is patched out here so this
proves, WITHOUT Docker, that:

* a non-adversarial profile routes to ``run_agent_eval`` and an adversarial one to
  ``run_adversarial_delta`` (a swap would silently mis-measure);
* a draft/unpublished version raises (never a silent eval of unpublished content);
* a missing version raises LookupError;
* the FULL bundle is rendered (the injected generator's create_challenge is called
  with the version's family/seed).

The real Docker scripted eval is documented in docs/evaluation/eval-worker-
limitations.md for lead verification. SKIPS cleanly without [db]/CTFGEN_TEST_DATABASE_URL.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_eval_runner_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.spec_generator import default_spec, spec_to_dict
    from ctf_generator.workers.eval_runner import SingleHostEvalJobRunner

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)
_SKIP = (
    f"[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)

_FAMILY = "web_business_logic_tenant_export"
_SLUG = "tenant-export"
_SEED = "eval-runner-seed"
_NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)


@contextmanager
def _migrated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_evrun_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        url = base.set(database=name).render_as_string(hide_password=False)
        cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield db
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _seed_version(db, *, state: str) -> None:
    spec_dict = spec_to_dict(
        default_spec(seed=_SEED, title="Tenant Export", difficulty="medium", family=_FAMILY)
    )
    with db.session_scope() as s:
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family=_FAMILY, slug=_SLUG, title="Tenant Export")
        )
        SqlAlchemyChallengeVersionRepository(s).add(
            ChallengeVersion(
                definition_slug=_SLUG,
                version_no=1,
                state="draft",
                family_version="1.0.0",
                seed=_SEED,
                spec_sha256="spec-hash-x",
                spec=spec_dict,
                spec_version="1.1",
                mode="red",
                published_at=None,
            )
        )
    if state == "published":
        with db.session_scope() as s:
            SqlAlchemyChallengeVersionRepository(s).publish(_SLUG, 1, _NOW)


class _RecordingGenerator:
    """A create_challenge double: records the call, writes nothing (the Docker leg
    is patched out, so the on-disk bundle is never read)."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def create_challenge(self, **kwargs):
        self.calls.append(kwargs)
        return Path(kwargs["output_dir"])


@unittest.skipUnless(_ENABLED, _SKIP)
class SingleHostEvalRunnerTests(unittest.TestCase):
    def _run(self, db, *, adversarial: bool):
        gen = _RecordingGenerator()
        runner = SingleHostEvalJobRunner(db, generator=gen)
        with mock.patch("ctf_generator.agent_eval.run_agent_eval") as plain, \
                mock.patch("ctf_generator.agent_eval.run_adversarial_delta") as delta:
            plain.return_value = "PLAIN"
            delta.return_value = "DELTA"
            out = runner.run(
                definition_slug=_SLUG,
                version_no=1,
                profile="writeup_replay",
                adversarial=adversarial,
                now=_NOW,
            )
        return out, gen, plain, delta

    def test_non_adversarial_routes_to_run_agent_eval(self) -> None:
        with _migrated_database() as db:
            _seed_version(db, state="published")
            out, gen, plain, delta = self._run(db, adversarial=False)
            self.assertEqual(out, "PLAIN")
            plain.assert_called_once()
            delta.assert_not_called()
            # The FULL bundle was rendered from the version's family/seed.
            self.assertEqual(len(gen.calls), 1)
            self.assertEqual(gen.calls[0]["family"], _FAMILY)
            self.assertEqual(gen.calls[0]["seed"], _SEED)

    def test_adversarial_routes_to_run_adversarial_delta(self) -> None:
        with _migrated_database() as db:
            _seed_version(db, state="published")
            out, _gen, plain, delta = self._run(db, adversarial=True)
            self.assertEqual(out, "DELTA")
            delta.assert_called_once()
            plain.assert_not_called()

    def test_unpublished_version_raises_and_renders_nothing(self) -> None:
        with _migrated_database() as db:
            _seed_version(db, state="draft")  # published NOT called
            gen = _RecordingGenerator()
            runner = SingleHostEvalJobRunner(db, generator=gen)
            with self.assertRaises(ValueError):
                runner.run(
                    definition_slug=_SLUG, version_no=1, profile="writeup_replay",
                    adversarial=False, now=_NOW,
                )
            self.assertEqual(gen.calls, [])  # never rendered a draft

    def test_missing_version_raises_lookuperror(self) -> None:
        with _migrated_database() as db:
            runner = SingleHostEvalJobRunner(db, generator=_RecordingGenerator())
            with self.assertRaises(LookupError):
                runner.run(
                    definition_slug=_SLUG, version_no=99, profile="writeup_replay",
                    adversarial=False, now=_NOW,
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
