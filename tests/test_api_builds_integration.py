"""PostgreSQL integration tests for the M9 slice-c builds API ([api]+[db]).

list + detail of content-addressed builds; a trigger ENQUEUES a ``build_challenge``
job (asserting a queued job row appears -- NOT an in-process build); a contestant
is 403. SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_builds_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.domain.authoring.models import ChallengeBuild
    from ctf_generator.infrastructure.database.challenge_build_repository import (
        SqlAlchemyChallengeBuildRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.deps import StubAuthenticator, principal_for
    from ctf_generator.interfaces.api.settings import ApiSettings

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

_ADMIN = "admintoken"  # noqa: S105
_ORGANIZER = "orgtoken"  # noqa: S105
_PLAYER = "playertoken"  # noqa: S105

_SLUG = "sqli"
_SPEC_SHA = "spec-sha-abc123"


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_build_{uuid.uuid4().hex[:12]}"
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
            # Builds are an AUTHORING surface (flat require_permission, unchanged in
            # M10b): an author/organizer builds challenges independent of any
            # competition, so no membership is needed here.
            _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
            _ORGANIZER: principal_for("org-user", {"organizer"}),
            _PLAYER: principal_for("player-user", {"player"}, team="Red"),
        }
    )


@contextmanager
def _client_and_db():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(
                ApiSettings(), database=db, authenticator=_authenticator()
            )
            yield TestClient(app), db
        finally:
            db.dispose()


def _auth(token: str = _ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed_version(client: TestClient) -> None:
    assert client.post(
        "/api/v1/challenge-definitions",
        headers=_auth(),
        json={"family": "web", "slug": _SLUG, "title": "SQLi"},
    ).status_code == 201
    # The version's spec_sha256 is derived from the spec; we plant a build whose
    # spec_sha256 must match, so read the version back for its hash.
    assert client.post(
        "/api/v1/challenge-versions",
        headers=_auth(),
        json={
            "definition_slug": _SLUG,
            "seed": "s",
            "family_version": "1.0.0",
            "spec": {"title": "SQLi"},
        },
    ).status_code == 201


def _plant_build(db: Database) -> str:
    """Insert a build whose spec_sha256 matches the version's (read from the DB)."""
    with db.session_scope() as s:
        version_sha = s.execute(
            sa.text("SELECT spec_sha256 FROM challenge_versions LIMIT 1")
        ).scalar_one()
    build_sha = f"build-{uuid.uuid4().hex}"
    with db.session_scope() as s:
        SqlAlchemyChallengeBuildRepository(s).add(
            ChallengeBuild(
                build_sha256=build_sha,
                definition_slug=_SLUG,
                version_no=1,
                family="web",
                seed="s",
                spec_sha256=version_sha,
                generator_version="1.0.0",
                manifest={"files": ["a"]},
            )
        )
    return build_sha


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class BuildsApiIntegrationTests(unittest.TestCase):
    def test_list_and_detail(self) -> None:
        with _client_and_db() as (client, db):
            _seed_version(client)
            build_sha = _plant_build(db)
            lst = client.get(
                f"/api/v1/challenge-definitions/{_SLUG}/builds?version_no=1",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertEqual(lst.json()["schema"], "ctfgen.build-list")
            self.assertIn(
                build_sha, [b["build_sha256"] for b in lst.json()["data"]]
            )
            detail = client.get(
                f"/api/v1/builds/{build_sha}", headers=_auth(_ORGANIZER)
            )
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertEqual(detail.json()["build_sha256"], build_sha)
            self.assertIn("manifest", detail.json())

    def test_trigger_enqueues_build_job(self) -> None:
        with _client_and_db() as (client, db):
            _seed_version(client)
            r = client.post(
                f"/api/v1/challenge-definitions/{_SLUG}/builds",
                headers=_auth(_ORGANIZER),
                json={"version_no": 1},
            )
            self.assertEqual(r.status_code, 202, r.text)
            body = r.json()
            self.assertEqual(body["job_type"], "build_challenge")
            self.assertEqual(body["status"], "queued")
            # A REAL queued job row exists -- the control plane did NOT build.
            with db.session_scope() as s:
                count = s.execute(
                    sa.text(
                        "SELECT count(*) FROM jobs "
                        "WHERE job_type='build_challenge' AND status='queued'"
                    )
                ).scalar_one()
            self.assertEqual(count, 1)
            # No payload/secret leaked into the response.
            self.assertNotIn("payload", body)

    def test_trigger_unknown_version_is_404(self) -> None:
        with _client_and_db() as (client, db):
            _seed_version(client)
            r = client.post(
                f"/api/v1/challenge-definitions/{_SLUG}/builds",
                headers=_auth(_ORGANIZER),
                json={"version_no": 99},
            )
            self.assertEqual(r.status_code, 404, r.text)

    def test_contestant_is_forbidden(self) -> None:
        with _client_and_db() as (client, db):
            _seed_version(client)
            probes = [
                client.get(
                    f"/api/v1/challenge-definitions/{_SLUG}/builds?version_no=1",
                    headers=_auth(_PLAYER),
                ),
                client.get("/api/v1/builds/nope", headers=_auth(_PLAYER)),
                client.post(
                    f"/api/v1/challenge-definitions/{_SLUG}/builds",
                    headers=_auth(_PLAYER),
                    json={"version_no": 1},
                ),
            ]
            for r in probes:
                self.assertEqual(r.status_code, 403, r.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
