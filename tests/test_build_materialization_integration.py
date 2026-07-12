"""PostgreSQL integration tests for build materialization (M14 slice 14c-1).

Docker-gated, like the other repository/service integration suites: requires the
``db`` extra and ``CTFGEN_TEST_DATABASE_URL``; skips cleanly otherwise so the
stdlib host suite stays green. Each test runs on a fresh, uuid-named database
migrated to alembic head, and uses a REAL
:class:`LocalFilesystemArtifactStore` over a temp dir plus real PostgreSQL.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_build_materialization_integration
"""

from __future__ import annotations

import io
import os
import re
import tarfile
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator import generator as _generator_module
    from ctf_generator.application.authoring.materialization import (
        BuildMaterializationService,
    )
    from ctf_generator.application.catalog.challenge_service import spec_content_hash
    from ctf_generator.domain.authoring.models import (
        ChallengeBuild,
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.infrastructure.artifacts.local_store import (
        LocalFilesystemArtifactStore,
    )
    from ctf_generator.infrastructure.database.challenge_build_repository import (
        SqlAlchemyChallengeBuildRepository,
    )
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.schema import SPEC_SCHEMA, current_version
    from ctf_generator.spec_generator import default_spec, spec_from_dict, spec_to_dict

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
_FAMILY = "web_business_logic_tenant_export"
_SLUG = "tenant-export"
_SEED = "mat-seed-1"


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


@contextmanager
def _store():
    with tempfile.TemporaryDirectory(prefix="materialize-store-") as tmp:
        yield LocalFilesystemArtifactStore(Path(tmp) / "artifacts")


def _spec_dict() -> dict:
    """The canonical spec payload stored on a version (spec_to_dict format, which
    ``spec_from_dict`` reconstructs)."""
    spec = default_spec(seed=_SEED, title="Export", difficulty="medium", family=_FAMILY)
    return spec_to_dict(spec)


def _seed_definition_and_draft(db, *, publish: bool) -> str:
    """Seed a definition + version; publish it when requested. Returns the version's
    spec_sha256."""
    spec_dict = _spec_dict()
    sha = spec_content_hash(spec_dict)
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
                spec_sha256=sha,
                spec=spec_dict,
                spec_version=current_version(SPEC_SCHEMA),
                mode="red",
            )
        )
    if publish:
        with db.session_scope() as s:
            SqlAlchemyChallengeVersionRepository(s).publish(_SLUG, 1, _NOW)
    return sha


def _rendered_flag() -> str:
    """Render the FULL bundle out-of-band and extract the ACTUAL generated flag,
    so the R-22 assertion checks the real secret token (deterministic from the
    seed), not a generic ``ctf{`` substring (which the public description
    legitimately contains as a format hint)."""
    spec = spec_from_dict(dict(_spec_dict()))
    with tempfile.TemporaryDirectory(prefix="materialize-flag-") as tmp:
        out = Path(tmp) / "bundle"
        _generator_module.create_challenge(
            output_dir=out,
            seed=spec.seed,
            title=spec.title,
            difficulty=spec.difficulty,
            family=spec.family,
            force=True,
            spec=spec,
        )
        env_text = (out / ".env.example").read_text(encoding="utf-8")
    match = re.search(r"ctf\{[^}]*\}", env_text)
    assert match is not None, "expected a generated flag in .env.example"
    return match.group(0)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class BuildMaterializationTests(unittest.TestCase):
    def test_materialize_writes_build_row_with_storage_uri(self) -> None:
        with _migrated_database() as db, _store() as store:
            sha = _seed_definition_and_draft(db, publish=True)
            svc = BuildMaterializationService(db, store)
            build = svc.materialize(_SLUG, 1)

            self.assertIsInstance(build, ChallengeBuild)
            self.assertEqual(build.definition_slug, _SLUG)
            self.assertEqual(build.version_no, 1)
            self.assertEqual(build.spec_sha256, sha)
            self.assertEqual(build.seed, _SEED)
            self.assertTrue(build.storage_uri)
            self.assertTrue(build.storage_uri.startswith("builds/"))
            # The row is persisted and re-readable by content address.
            with db.session_scope() as s:
                got = SqlAlchemyChallengeBuildRepository(s).get(build.build_sha256)
            self.assertIsNotNone(got)
            self.assertEqual(got.storage_uri, build.storage_uri)
            # The bytes the row points at actually exist in the store.
            self.assertTrue(store.exists(build.storage_uri))

    def test_artifact_contains_only_public_and_no_private_leak(self) -> None:
        # R-22: the persisted artifact must carry ONLY public/ files and must not
        # contain the private flag, solver, solution, or any private path.
        flag = _rendered_flag()
        with _migrated_database() as db, _store() as store:
            _seed_definition_and_draft(db, publish=True)
            build = BuildMaterializationService(db, store).materialize(_SLUG, 1)
            tar_bytes = store.get(build.storage_uri)

        self.assertIsNotNone(tar_bytes)
        names = tarfile.open(fileobj=io.BytesIO(tar_bytes)).getnames()
        self.assertTrue(names, "artifact tar is empty")
        self.assertTrue(
            all(n.startswith("public/") for n in names),
            f"non-public entry in artifact: {names}",
        )
        # The real flag token is ABSENT from the raw bytes ...
        self.assertNotIn(flag.encode("utf-8"), tar_bytes)
        # ... and so is every private/forbidden marker.
        self.assertNotIn(b"private/", tar_bytes)
        self.assertNotIn(b"CTFGEN_FLAG", tar_bytes)
        self.assertNotIn(b"solver.py", tar_bytes)
        self.assertNotIn(b"solution", tar_bytes)

    def test_rematerialize_is_idempotent_same_hash_single_row(self) -> None:
        with _migrated_database() as db, _store() as store:
            _seed_definition_and_draft(db, publish=True)
            svc = BuildMaterializationService(db, store)
            first = svc.materialize(_SLUG, 1)
            second = svc.materialize(_SLUG, 1)

            # Same content address, no duplicate row, no error.
            self.assertEqual(first.build_sha256, second.build_sha256)
            self.assertEqual(first.storage_uri, second.storage_uri)
            with db.session_scope() as s:
                builds = SqlAlchemyChallengeBuildRepository(s).list_for_version(
                    _SLUG, 1
                )
            self.assertEqual(len(builds), 1)
            # The stored bytes are identical across both runs.
            self.assertEqual(store.get(first.storage_uri), store.get(second.storage_uri))

    def test_two_versions_same_public_output_get_distinct_builds(self) -> None:
        # Two versions of one definition with IDENTICAL public output (same
        # seed/family; differing only in difficulty -> different spec_sha256) must
        # get DISTINCT build rows, each correctly attributed to its OWN version --
        # build_sha256 folds the version's spec identity, so version 2's
        # materialize is NOT misattributed to version 1's existing row. The stored
        # BYTES, addressed by the public content hash, are physically deduplicated.
        with _migrated_database() as db, _store() as store:
            d1 = spec_to_dict(
                default_spec(seed=_SEED, title="Export", difficulty="medium", family=_FAMILY)
            )
            d2 = spec_to_dict(
                default_spec(seed=_SEED, title="Export", difficulty="hard", family=_FAMILY)
            )
            sha1, sha2 = spec_content_hash(d1), spec_content_hash(d2)
            self.assertNotEqual(sha1, sha2)  # genuinely distinct specs
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(
                    ChallengeDefinition(family=_FAMILY, slug=_SLUG, title="Tenant Export")
                )
                repo = SqlAlchemyChallengeVersionRepository(s)
                for vno, (sd, sh) in enumerate(((d1, sha1), (d2, sha2)), start=1):
                    repo.add(
                        ChallengeVersion(
                            definition_slug=_SLUG, version_no=vno, state="draft",
                            family_version="1.0.0", seed=_SEED, spec_sha256=sh, spec=sd,
                            spec_version=current_version(SPEC_SCHEMA), mode="red",
                        )
                    )
            with db.session_scope() as s:
                vrepo = SqlAlchemyChallengeVersionRepository(s)
                vrepo.publish(_SLUG, 1, _NOW)
                vrepo.publish(_SLUG, 2, _NOW)

            svc = BuildMaterializationService(db, store)
            b1 = svc.materialize(_SLUG, 1)
            b2 = svc.materialize(_SLUG, 2)

            # Distinct build identity, correctly attributed to each version.
            self.assertNotEqual(b1.build_sha256, b2.build_sha256)
            self.assertEqual(b1.version_no, 1)
            self.assertEqual(b2.version_no, 2)
            self.assertEqual(b1.spec_sha256, sha1)
            self.assertEqual(b2.spec_sha256, sha2)
            # Each version's own build is listed (v2 is NOT missing).
            with db.session_scope() as s:
                brepo = SqlAlchemyChallengeBuildRepository(s)
                self.assertEqual(len(brepo.list_for_version(_SLUG, 1)), 1)
                self.assertEqual(len(brepo.list_for_version(_SLUG, 2)), 1)
            # Identical public output -> the bytes are deduplicated (same key).
            self.assertEqual(b1.storage_uri, b2.storage_uri)

    def test_unpublished_version_raises_valueerror(self) -> None:
        with _migrated_database() as db, _store() as store:
            _seed_definition_and_draft(db, publish=False)  # draft, NOT published
            with self.assertRaises(ValueError):
                BuildMaterializationService(db, store).materialize(_SLUG, 1)
            # Nothing was persisted for a rejected materialization.
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyChallengeBuildRepository(s).list_for_version(_SLUG, 1), []
                )

    def test_missing_version_raises_lookuperror(self) -> None:
        with _migrated_database() as db, _store() as store:
            with self.assertRaises(LookupError):
                BuildMaterializationService(db, store).materialize("ghost", 1)


if __name__ == "__main__":
    unittest.main()
