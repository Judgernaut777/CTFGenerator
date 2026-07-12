"""PostgreSQL integration tests for the M9 slice-b users API ([api]+[db], real PG).

register -> get -> list(paginated); duplicate email -> 409; unknown user -> 404;
unknown role -> 422; player cannot register (403). SKIPS cleanly without the
``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_users_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:  # heavy deps optional; guard so import never fails the host suite
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
except Exception as exc:  # pragma: no cover - only without the extras
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_ADMIN = "admintoken"  # noqa: S105 - test fixture token, not a real secret
_PLAYER = "playertoken"  # noqa: S105 - test fixture token, not a real secret


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_it_{uuid.uuid4().hex[:12]}"
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
            _PLAYER: principal_for("player-user", {"player"}, team="Red"),
        }
    )


@contextmanager
def _client():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            app = create_app(
                ApiSettings(), database=db, authenticator=_authenticator()
            )
            yield TestClient(app)
        finally:
            db.dispose()


def _auth(token: str = _ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class UsersApiIntegrationTests(unittest.TestCase):
    def test_register_get_list_round_trip(self) -> None:
        with _client() as client:
            r = client.post(
                "/api/v1/users",
                headers=_auth(),
                json={
                    "email": "Ada@example.com",
                    "display_name": "Ada Lovelace",
                    "role": "player",
                },
            )
            self.assertEqual(r.status_code, 201, r.text)
            self.assertEqual(r.json()["schema"], "ctfgen.user")
            self.assertEqual(r.json()["email"], "Ada@example.com")
            self.assertEqual(r.json()["display_name"], "Ada Lovelace")
            self.assertTrue(r.headers["ETag"])
            # No credential/role field is echoed as if persisted.
            self.assertNotIn("role", r.json())
            self.assertNotIn("password", r.json())

            # GET is case-insensitive on the email key.
            r = client.get("/api/v1/users/ada@example.com", headers=_auth())
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["display_name"], "Ada Lovelace")

            # A second user, then a paginated list stable-sorted by email.
            client.post(
                "/api/v1/users",
                headers=_auth(),
                json={
                    "email": "bob@example.com",
                    "display_name": "Bob",
                    "role": "organizer",
                },
            )
            first = client.get("/api/v1/users?limit=1", headers=_auth())
            self.assertEqual(first.status_code, 200)
            self.assertEqual([u["email"] for u in first.json()["data"]], ["Ada@example.com"])
            self.assertTrue(first.json()["page"]["has_more"])
            cursor = first.json()["page"]["next_cursor"]
            second = client.get(
                f"/api/v1/users?limit=1&cursor={cursor}", headers=_auth()
            )
            self.assertEqual(second.status_code, 200)
            self.assertEqual([u["email"] for u in second.json()["data"]], ["bob@example.com"])

    def test_duplicate_email_is_409(self) -> None:
        with _client() as client:
            body = {"email": "dup@example.com", "display_name": "Dup", "role": "player"}
            self.assertEqual(
                client.post("/api/v1/users", headers=_auth(), json=body).status_code,
                201,
            )
            # Case-insensitive duplicate.
            r = client.post(
                "/api/v1/users",
                headers=_auth(),
                json={"email": "DUP@example.com", "display_name": "Dup2", "role": "player"},
            )
            self.assertEqual(r.status_code, 409, r.text)
            self.assertEqual(r.json()["error"]["code"], "conflict")

    def test_unknown_user_is_404(self) -> None:
        with _client() as client:
            r = client.get("/api/v1/users/ghost@example.com", headers=_auth())
            self.assertEqual(r.status_code, 404)
            self.assertEqual(r.json()["error"]["code"], "not_found")

    def test_unknown_role_is_422(self) -> None:
        with _client() as client:
            r = client.post(
                "/api/v1/users",
                headers=_auth(),
                json={"email": "x@example.com", "display_name": "X", "role": "wizard"},
            )
            self.assertEqual(r.status_code, 422, r.text)
            self.assertEqual(r.json()["error"]["code"], "validation_failed")

    def test_player_cannot_register_users(self) -> None:
        with _client() as client:
            r = client.post(
                "/api/v1/users",
                headers=_auth(_PLAYER),
                json={"email": "y@example.com", "display_name": "Y", "role": "player"},
            )
            self.assertEqual(r.status_code, 403)
            self.assertEqual(r.json()["error"]["code"], "forbidden")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
