"""PostgreSQL integration tests for the M14 slice 14c-2 CONTESTANT public-artifact
download (JSON API surface).

``GET /competitions/{competition_id}/challenges/{slug}/{version_no}/artifact``
streams the MATERIALIZED public bundle to a principal who may read the competition.
The invariants under test:

* an authorized reader (competition:read in the competition) gets the exact
  materialized tar bytes -> 200, ``application/x-tar``, sanitized
  ``Content-Disposition`` filename, ``Cache-Control: no-store``, and NO private
  leak (only ``public/`` paths; the real generated flag is absent);
* a principal WITHOUT competition:read in that competition -> existence-hiding 404
  (``ctfgen.error`` envelope, never a 403 oracle, never a 500);
* a published-but-UNMATERIALIZED challenge -> a 404 envelope (never a 500).

The artifact is produced by the REAL
:class:`~ctf_generator.application.authoring.materialization.BuildMaterializationService`
over a REAL :class:`LocalFilesystemArtifactStore`, wired into ``create_app``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_artifact_download_integration
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
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator import generator as _generator_module
    from ctf_generator.application.authoring.materialization import (
        BuildMaterializationService,
    )
    from ctf_generator.application.catalog import (
        ChallengeDefinitionService,
        ChallengeVersionService,
        CompetitionService,
    )
    from ctf_generator.application.catalog.publication_service import PublicationService
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengePublication,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.infrastructure.artifacts.local_store import (
        LocalFilesystemArtifactStore,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.spec_generator import default_spec, spec_from_dict, spec_to_dict

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_CID = "alpha-ctf-2026"
_CID_B = "bravo-ctf-2026"
_FAMILY = "web_business_logic_tenant_export"
_SLUG = "tenant-export"
_SEED = "api-download-seed-1"
_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)

_ADMIN = "admintoken"  # noqa: S105 - test fixture
_READER = "readertoken"  # noqa: S105 - player in _CID (competition:read)
_OUTSIDER = "outsidertoken"  # noqa: S105 - no membership in _CID


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_dl_{uuid.uuid4().hex[:12]}"
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


def _authenticator() -> StubAuthenticator:
    return StubAuthenticator(
        {
            _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
            # A contestant with a player membership in _CID -> holds competition:read
            # there (via ROLE_PERMISSIONS[player]); no team needed to download.
            _READER: principal_for(
                "reader-player", {"player"}, memberships={_CID: ("player", None)}
            ),
            # A player of a DIFFERENT competition -> no competition:read in _CID, so
            # the download is an existence-hiding 404 (not a 403).
            _OUTSIDER: principal_for(
                "outsider-player", {"player"}, memberships={_CID_B: ("player", None)}
            ),
        }
    )


def _competition_config(cid: str, name: str) -> CompetitionConfig:
    return CompetitionConfig(
        competition_id=cid,
        name=name,
        start_time=_NOW,
        end_time=_NOW + timedelta(days=2),
        scoring_start_time=_NOW,
        default_scoring=None,
    )


def _renderable_spec() -> dict:
    spec = default_spec(seed=_SEED, title="Tenant Export", difficulty="medium", family=_FAMILY)
    return spec_to_dict(spec)


def _rendered_flag(spec_dict: dict) -> str:
    """The ACTUAL generated flag (from .env.example) so the no-leak assertion tests
    the real secret token, not a generic ``ctf{`` format hint."""
    spec = spec_from_dict(dict(spec_dict))
    with tempfile.TemporaryDirectory(prefix="api-dl-flag-") as tmp:
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
    assert match is not None
    return match.group(0)


def _seed_published(db: Database, cid: str, slug: str) -> tuple[int, dict]:
    """Create the competition (if absent) + a renderable published challenge attached
    to it. Returns (version_no, spec_dict)."""
    competitions = CompetitionService(db)
    if competitions.get(cid) is None:
        competitions.create(_competition_config(cid, cid))
    spec_dict = _renderable_spec()
    ChallengeDefinitionService(db).create(
        ChallengeDefinition(family=_FAMILY, slug=slug, title="Tenant Export")
    )
    versions = ChallengeVersionService(db)
    version = versions.create_draft(
        definition_slug=slug, seed=_SEED, family_version="1.0.0", spec=spec_dict
    )
    versions.publish(slug, version.version_no, _NOW)
    PublicationService(db).attach(
        ChallengePublication(
            competition_id=cid, definition_slug=slug, version_no=version.version_no
        )
    )
    return version.version_no, spec_dict


@contextmanager
def _client_and_db(store):
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(
                ApiSettings(),
                database=db,
                authenticator=_authenticator(),
                artifact_store=store,
            )
            yield TestClient(app), db
        finally:
            db.dispose()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _url(cid: str, slug: str, ver: int) -> str:
    return f"/api/v1/competitions/{cid}/challenges/{slug}/{ver}/artifact"


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ArtifactDownloadApiTests(unittest.TestCase):
    def test_authorized_reader_gets_exact_public_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="api-dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with _client_and_db(store) as (client, db):
                ver, spec_dict = _seed_published(db, _CID, _SLUG)
                build = BuildMaterializationService(db, store).materialize(_SLUG, ver)
                tar_bytes = store.get(build.storage_uri)
                flag = _rendered_flag(spec_dict)

                resp = client.get(_url(_CID, _SLUG, ver), headers=_auth(_READER))
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(resp.headers["content-type"], "application/x-tar")
                self.assertEqual(
                    resp.headers["content-disposition"],
                    f'attachment; filename="{_SLUG}-v{ver}.tar"',
                )
                self.assertEqual(resp.headers["cache-control"], "no-store")
                self.assertEqual(resp.content, tar_bytes)

                names = tarfile.open(fileobj=io.BytesIO(resp.content)).getnames()
                self.assertTrue(names)
                self.assertTrue(all(n.startswith("public/") for n in names), names)
                self.assertNotIn(flag.encode("utf-8"), resp.content)
                self.assertNotIn(b"private/", resp.content)
                self.assertNotIn(b"solver.py", resp.content)

    def test_outsider_gets_existence_hiding_404_envelope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="api-dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with _client_and_db(store) as (client, db):
                ver, _spec = _seed_published(db, _CID, _SLUG)
                BuildMaterializationService(db, store).materialize(_SLUG, ver)

                resp = client.get(_url(_CID, _SLUG, ver), headers=_auth(_OUTSIDER))
                self.assertEqual(resp.status_code, 404, resp.text)
                body = resp.json()
                self.assertEqual(body["error"]["code"], "not_found")
                # A generic message -- never confirms the competition/challenge exists.
                self.assertNotIn(_SLUG, body["error"]["message"])

    def test_published_elsewhere_not_here_is_404_no_cross_tenant_leak(self) -> None:
        # The load-bearing tenancy guard: the resolver is competition-AGNOSTIC, so
        # the ONLY cross-tenant gate is the handler's published-in-THIS-competition
        # check. The reader can read _CID, but the (slug,ver) is published +
        # materialized ONLY in _CID_B. A request via the _CID path must 404 and
        # NEVER stream _CID_B's materialized bytes.
        with tempfile.TemporaryDirectory(prefix="api-dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with _client_and_db(store) as (client, db):
                # _CID exists (the reader's competition); publish+materialize in _CID_B.
                CompetitionService(db).create(_competition_config(_CID, _CID))
                ver, spec_dict = _seed_published(db, _CID_B, _SLUG)  # _CID_B only
                build = BuildMaterializationService(db, store).materialize(_SLUG, ver)
                tar_bytes = store.get(build.storage_uri)
                flag = _rendered_flag(spec_dict)

                # _READER reads _CID (passes authz); the slug is NOT published in _CID.
                resp = client.get(_url(_CID, _SLUG, ver), headers=_auth(_READER))
                self.assertEqual(resp.status_code, 404, resp.text)
                self.assertEqual(resp.json()["error"]["code"], "not_found")
                self.assertNotIn(flag.encode("utf-8"), resp.content)
                self.assertNotEqual(resp.content, tar_bytes)

    def test_unmaterialized_is_404_envelope_not_500(self) -> None:
        with tempfile.TemporaryDirectory(prefix="api-dl-store-") as tmp:
            store = LocalFilesystemArtifactStore(Path(tmp) / "artifacts")
            with _client_and_db(store) as (client, db):
                ver, _spec = _seed_published(db, _CID, _SLUG)
                # Published but deliberately NOT materialized -> no build/bytes.
                resp = client.get(_url(_CID, _SLUG, ver), headers=_auth(_READER))
                self.assertEqual(resp.status_code, 404, resp.text)
                self.assertEqual(resp.json()["error"]["code"], "not_found")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
