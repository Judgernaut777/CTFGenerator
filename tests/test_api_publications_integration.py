"""PostgreSQL integration tests for the M9 slice-c publications API ([api]+[db]).

attach -> list -> detach; duplicate attach -> 409; unknown version -> 404; a
contestant is 403. SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_publications_integration
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

_CID = "spring-ctf-2026"
_SLUG = "sqli"


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_pub_{uuid.uuid4().hex[:12]}"
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
            _ADMIN: principal_for("admin-user", {"admin"}),
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


def _seed(client: TestClient) -> None:
    assert client.post(
        "/api/v1/competitions",
        headers=_auth(),
        json={
            "competition_id": _CID,
            "name": "Spring CTF",
            "start_time": "2026-06-01T09:00:00Z",
            "end_time": "2026-06-03T09:00:00Z",
        },
    ).status_code == 201
    assert client.post(
        "/api/v1/challenge-definitions",
        headers=_auth(),
        json={"family": "web", "slug": _SLUG, "title": "SQLi"},
    ).status_code == 201
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
    assert client.post(
        f"/api/v1/challenge-versions/{_SLUG}/1/publish", headers=_auth()
    ).status_code == 200


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class PublicationsApiIntegrationTests(unittest.TestCase):
    def test_attach_list_detach(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client)
            attach = client.post(
                f"/api/v1/competitions/{_CID}/publications",
                headers=_auth(_ORGANIZER),
                json={"definition_slug": _SLUG, "version_no": 1, "initial_value": 400},
            )
            self.assertEqual(attach.status_code, 201, attach.text)
            self.assertEqual(attach.json()["schema"], "ctfgen.publication")
            self.assertEqual(attach.json()["initial_value"], 400)

            lst = client.get(
                f"/api/v1/competitions/{_CID}/publications", headers=_auth(_ORGANIZER)
            )
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertEqual(
                [p["definition_slug"] for p in lst.json()["data"]], [_SLUG]
            )

            detach = client.delete(
                f"/api/v1/competitions/{_CID}/publications/{_SLUG}/1",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(detach.status_code, 204, detach.text)
            after = client.get(
                f"/api/v1/competitions/{_CID}/publications", headers=_auth(_ORGANIZER)
            )
            self.assertEqual(after.json()["data"], [])

    def test_duplicate_attach_conflicts(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client)
            body = {"definition_slug": _SLUG, "version_no": 1}
            first = client.post(
                f"/api/v1/competitions/{_CID}/publications",
                headers=_auth(_ORGANIZER), json=body,
            )
            self.assertEqual(first.status_code, 201, first.text)
            dup = client.post(
                f"/api/v1/competitions/{_CID}/publications",
                headers=_auth(_ORGANIZER), json=body,
            )
            self.assertEqual(dup.status_code, 409, dup.text)
            self.assertEqual(dup.json()["error"]["code"], "conflict")

    def test_unknown_version_is_404(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client)
            r = client.post(
                f"/api/v1/competitions/{_CID}/publications",
                headers=_auth(_ORGANIZER),
                json={"definition_slug": _SLUG, "version_no": 99},
            )
            self.assertEqual(r.status_code, 404, r.text)
            self.assertEqual(r.json()["error"]["code"], "not_found")

    def test_detach_unknown_is_404(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client)
            r = client.delete(
                f"/api/v1/competitions/{_CID}/publications/{_SLUG}/1",
                headers=_auth(_ORGANIZER),
            )
            self.assertEqual(r.status_code, 404, r.text)

    def test_contestant_is_forbidden(self) -> None:
        with _client_and_db() as (client, db):
            _seed(client)
            attach = client.post(
                f"/api/v1/competitions/{_CID}/publications",
                headers=_auth(_PLAYER),
                json={"definition_slug": _SLUG, "version_no": 1},
            )
            self.assertEqual(attach.status_code, 403, attach.text)
            lst = client.get(
                f"/api/v1/competitions/{_CID}/publications", headers=_auth(_PLAYER)
            )
            self.assertEqual(lst.status_code, 403, lst.text)
            detach = client.delete(
                f"/api/v1/competitions/{_CID}/publications/{_SLUG}/1",
                headers=_auth(_PLAYER),
            )
            self.assertEqual(detach.status_code, 403, detach.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
