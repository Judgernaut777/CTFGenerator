"""End-to-end seam-swap tests for the real DbAuthenticator (M10a; [api]+[db]).

Proves the M9 StubAuthenticator seam is truly replaced: a caller logs in, gets an
opaque session token, and that token drives the EXISTING ``require_permission``
resource routes -- with the flat permission set resolved from the user's REAL
system roles + competition memberships. Also proves the fail-closed paths:
garbage / revoked / expired tokens are all 401 on a gated route. SKIPS cleanly
without the extras / CTFGEN_TEST_DATABASE_URL.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_dbauthenticator_integration
"""

from __future__ import annotations

import hashlib
import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.application.auth import AuthService
    from ctf_generator.application.auth.hashing import Pbkdf2Sha256Hasher
    from ctf_generator.domain.identity.models import Membership, Team, User
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.membership_repository import (
        SqlAlchemyMembershipRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )
    from ctf_generator.infrastructure.database.user_repository import (
        SqlAlchemyUserRepository,
    )
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
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

_PW = "a-decent-password"  # noqa: S105 - test fixture, not a real secret
_COMP = "spring-ctf"


def _comp_body(cid=_COMP):
    return {
        "competition_id": cid,
        "name": "Spring CTF",
        "start_time": "2026-08-01T00:00:00+00:00",
        "end_time": "2026-08-02T00:00:00+00:00",
    }


@contextmanager
def _fixture():
    base = make_url(_TEST_URL)
    name = f"ctfgen_dbauth_it_{uuid.uuid4().hex[:12]}"
    admin_engine = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin_engine.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        url = base.set(database=name).render_as_string(hide_password=False)
        cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        db = Database(DatabaseConfig(url=url))
        try:
            service = AuthService(db, hasher=Pbkdf2Sha256Hasher(iterations=1000))
            now = datetime.now(UTC)
            # Seed three accounts with credentials.
            with db.session_scope() as s:
                users = SqlAlchemyUserRepository(s)
                users.add(User("admin@x.io", "Admin"))
                users.add(User("org@x.io", "Org"))
                users.add(User("player@x.io", "Player"))
            for email in ("admin@x.io", "org@x.io", "player@x.io"):
                service.set_password(email, _PW, now)
            service.grant_system_role("admin@x.io", "admin")
            app = create_app(
                ApiSettings(),
                database=db,
                auth_service=service,
                authenticator=DbAuthenticator(service),
            )
            client = TestClient(app)

            # Admin (system role) creates the competition through the REAL gated
            # route using its issued session token -- proving the seam swap.
            admin_token = _login(client, "admin@x.io")
            created = client.post(
                "/api/v1/competitions", json=_comp_body(), headers=_auth(admin_token)
            )
            assert created.status_code == 201, created.text

            # Competition-scoped memberships (organizer unteamed; player on Red).
            with db.session_scope() as s:
                SqlAlchemyTeamRepository(s).add(Team(_COMP, "Red"))
                memberships = SqlAlchemyMembershipRepository(s)
                memberships.add(Membership("org@x.io", _COMP, "organizer"))
                memberships.add(Membership("player@x.io", _COMP, "player", "Red"))

            yield client, service, db
        finally:
            db.dispose()
    finally:
        with admin_engine.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin_engine.dispose()


def _login(client, email):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": _PW})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class DbAuthenticatorSeamTests(unittest.TestCase):
    def test_issued_token_drives_require_permission_route(self) -> None:
        with _fixture() as (client, _service, _db):
            token = _login(client, "org@x.io")
            # organizer holds competition:read (via the real membership).
            r = client.get(f"/api/v1/competitions/{_COMP}", headers=_auth(token))
            self.assertEqual(r.status_code, 200, r.text)

    def test_flat_permissions_match_real_roles(self) -> None:
        with _fixture() as (client, _service, _db):
            org_token = _login(client, "org@x.io")
            player_token = _login(client, "player@x.io")

            # organizer -> competition:write granted (can create another comp).
            org_write = client.post(
                "/api/v1/competitions",
                json=_comp_body("autumn-ctf"),
                headers=_auth(org_token),
            )
            self.assertEqual(org_write.status_code, 201, org_write.text)

            # player -> read yes, write no (403), proving the flat set resolved
            # from the real competition role gates require_permission.
            player_read = client.get(
                f"/api/v1/competitions/{_COMP}", headers=_auth(player_token)
            )
            self.assertEqual(player_read.status_code, 200)
            player_write = client.post(
                "/api/v1/competitions",
                json=_comp_body("winter-ctf"),
                headers=_auth(player_token),
            )
            self.assertEqual(player_write.status_code, 403)
            self.assertEqual(player_write.json()["error"]["code"], "forbidden")

    def test_me_reflects_real_memberships(self) -> None:
        with _fixture() as (client, _service, _db):
            token = _login(client, "player@x.io")
            body = client.get("/api/v1/auth/me", headers=_auth(token)).json()
            self.assertEqual(body["subject"], "player@x.io")
            self.assertEqual(body["roles"], ["player"])
            self.assertEqual(
                body["memberships"],
                [{"competition_id": _COMP, "role": "player", "team": "Red"}],
            )

    def test_garbage_token_is_401(self) -> None:
        with _fixture() as (client, _service, _db):
            r = client.get(
                f"/api/v1/competitions/{_COMP}", headers=_auth("not-a-real-token")
            )
            self.assertEqual(r.status_code, 401)

    def test_revoked_token_is_401(self) -> None:
        with _fixture() as (client, _service, _db):
            token = _login(client, "org@x.io")
            client.post("/api/v1/auth/logout", headers=_auth(token))
            r = client.get(f"/api/v1/competitions/{_COMP}", headers=_auth(token))
            self.assertEqual(r.status_code, 401)

    def test_expired_token_is_401(self) -> None:
        with _fixture() as (client, _service, db):
            raw = "expired-" + uuid.uuid4().hex
            token_hash = hashlib.sha256(raw.encode()).hexdigest()
            past = datetime.now(UTC) - timedelta(hours=1)
            # Craft an already-expired session directly for org@x.io.
            with db.session_scope() as s:
                uid = s.execute(
                    sa.text("SELECT id FROM users WHERE email = 'org@x.io'")
                ).scalar()
                s.execute(
                    sa.text(
                        "INSERT INTO sessions "
                        "(id, user_id, token_hash, issued_at, expires_at) "
                        "VALUES (:i, :u, :h, :issued, :exp)"
                    ),
                    {
                        "i": str(uuid.uuid4()),
                        "u": uid,
                        "h": token_hash,
                        "issued": past - timedelta(hours=1),
                        "exp": past,
                    },
                )
            r = client.get(f"/api/v1/competitions/{_COMP}", headers=_auth(raw))
            self.assertEqual(r.status_code, 401)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
