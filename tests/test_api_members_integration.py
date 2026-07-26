"""PostgreSQL integration tests for the membership (roster) API + the end-to-end
grant it unblocks ([api]+[db], real PG).

The operator roster surface (`PUT /competitions/{id}/members/{email}`) is the path
that turns a registered user into a competition participant. These tests prove:

* an ORGANIZER of the competition can assign a player membership (200), and the
  assignment is an idempotent upsert (re-role / re-team changes placement);
* the write is COMPETITION-scoped: an organizer of B is denied in A (403), and a
  plain player cannot assign at all (403);
* unknown team -> 404, invalid role -> 400 (surfaced by the domain + repo);
* END-TO-END: after the assignment, the target user -- authenticating with a REAL
  password credential + session (DbAuthenticator) -- actually resolves with
  `submission:create` in that competition. This is the permission that was
  previously ungrantable through any shipped interface.

SKIPS cleanly without the [api]/[db] extras or CTFGEN_TEST_DATABASE_URL.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_members_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from unittest import mock

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.application.auth import AuthService
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
    from ctf_generator.interfaces.api.deps import (
        Permission,
        StubAuthenticator,
        competition_permissions,
        principal_for,
    )
    from ctf_generator.interfaces.api.settings import ApiSettings

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)

_ADMIN = "admintoken"  # noqa: S105 - fixture token
_ORG_A = "orgAtoken"  # noqa: S105 - fixture token
_ORG_B = "orgBtoken"  # noqa: S105 - fixture token
_PLAYER = "playertoken"  # noqa: S105 - fixture token
_CID_A = "alpha-ctf"
_CID_B = "beta-ctf"
_PLAYER_EMAIL = "newplayer@example.com"
_PLAYER_PW = "correct-horse-battery-staple-7"  # noqa: S105 - test fixture


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_members_it_{uuid.uuid4().hex[:12]}"
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
            _ORG_A: principal_for(
                "org-a", {"organizer"}, memberships={_CID_A: ("organizer", None)}
            ),
            _ORG_B: principal_for(
                "org-b", {"organizer"}, memberships={_CID_B: ("organizer", None)}
            ),
            _PLAYER: principal_for(
                "a-player",
                {"player"},
                team="Red",
                memberships={_CID_A: ("player", "Red")},
            ),
        }
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class MembershipApiTests(unittest.TestCase):
    @contextmanager
    def _ctx(self):
        with _isolated_database() as url:
            self._url = url
            command.upgrade(_alembic_config(url), "head")
            db = Database(DatabaseConfig(url=url))
            try:
                auth_service = AuthService(db)
                app = create_app(
                    ApiSettings(),
                    database=db,
                    auth_service=auth_service,
                    authenticator=_authenticator(),
                )
                client = TestClient(app)
                self._seed(client, db, auth_service)
                yield client, db, auth_service
            finally:
                db.dispose()

    def _seed(self, client, db, auth_service) -> None:
        # Two competitions (A owned by org A, B by org B), a team + a user in A.
        for cid in (_CID_A, _CID_B):
            r = client.post(
                "/api/v1/competitions",
                headers=_auth(_ADMIN),
                json={
                    "competition_id": cid,
                    "name": cid,
                    "start_time": "2026-06-01T09:00:00Z",
                    "end_time": "2026-06-03T09:00:00Z",
                },
            )
            self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(
            client.post(
                "/api/v1/teams",
                headers=_auth(_ADMIN),
                json={"competition_id": _CID_A, "name": "Red"},
            ).status_code,
            201,
        )
        self.assertEqual(
            client.post(
                "/api/v1/users",
                headers=_auth(_ADMIN),
                json={
                    "email": _PLAYER_EMAIL,
                    "display_name": "New Player",
                    "role": "player",
                },
            ).status_code,
            201,
        )

    def _put(self, client, token, cid, email, body):
        return client.put(
            f"/api/v1/competitions/{cid}/members/{email}",
            headers=_auth(token),
            json=body,
        )

    def test_organizer_assigns_player_and_upserts(self) -> None:
        with self._ctx() as (client, _db, _auth_service):
            r = self._put(
                client,
                _ORG_A,
                _CID_A,
                _PLAYER_EMAIL,
                {"role": "player", "team_name": "Red"},
            )
            self.assertEqual(r.status_code, 200, r.text)
            body = r.json()
            self.assertEqual(body["role"], "player")
            self.assertEqual(body["team_name"], "Red")
            self.assertEqual(body["user_email"], _PLAYER_EMAIL)
            # Idempotent upsert: re-role to captain (same identity) -> 200, changed.
            r2 = self._put(
                client,
                _ORG_A,
                _CID_A,
                _PLAYER_EMAIL,
                {"role": "captain", "team_name": "Red"},
            )
            self.assertEqual(r2.status_code, 200, r2.text)
            self.assertEqual(r2.json()["role"], "captain")

    def test_scoped_write_denies_cross_competition_and_player(self) -> None:
        with self._ctx() as (client, _db, _auth_service):
            # Organizer of B cannot assign in A.
            self.assertEqual(
                self._put(
                    client,
                    _ORG_B,
                    _CID_A,
                    _PLAYER_EMAIL,
                    {"role": "player", "team_name": "Red"},
                ).status_code,
                403,
            )
            # A plain player cannot assign memberships at all.
            self.assertEqual(
                self._put(
                    client,
                    _PLAYER,
                    _CID_A,
                    _PLAYER_EMAIL,
                    {"role": "player", "team_name": "Red"},
                ).status_code,
                403,
            )

    def test_unknown_team_404_and_bad_role_400(self) -> None:
        with self._ctx() as (client, _db, _auth_service):
            self.assertEqual(
                self._put(
                    client,
                    _ORG_A,
                    _CID_A,
                    _PLAYER_EMAIL,
                    {"role": "player", "team_name": "Nonexistent"},
                ).status_code,
                404,
            )
            self.assertEqual(
                self._put(
                    client,
                    _ORG_A,
                    _CID_A,
                    _PLAYER_EMAIL,
                    {"role": "not-a-role", "team_name": "Red"},
                ).status_code,
                400,
            )

    def test_assigned_player_resolves_with_submit_permission(self) -> None:
        with self._ctx() as (client, db, auth_service):
            # Assign the player membership through the API.
            self.assertEqual(
                self._put(
                    client,
                    _ORG_A,
                    _CID_A,
                    _PLAYER_EMAIL,
                    {"role": "player", "team_name": "Red"},
                ).status_code,
                200,
            )
            # Give the user a real password + session, then resolve via DbAuthenticator.
            now = datetime.now(UTC)
            auth_service.set_password(_PLAYER_EMAIL, _PLAYER_PW, now)
            issued = auth_service.authenticate(_PLAYER_EMAIL, _PLAYER_PW, now)
            principal = DbAuthenticator(auth_service).authenticate(issued.token)
            self.assertIsNotNone(principal)
            perms = competition_permissions(principal, _CID_A)
            self.assertIn(Permission.SUBMISSION_CREATE, perms)

    def test_cli_grant_membership_and_set_password_onboard_a_contestant(self) -> None:
        # The operator CLI twins provision the same onboarding without HTTP: create
        # the user+team+comp (via the app), then grant-membership + set-password on
        # the CLI, and confirm the contestant resolves with submit permission.
        from ctf_generator.interfaces.cli.admin import main as admin_main

        with self._ctx() as (client, db, auth_service):
            with mock.patch.dict(os.environ, {"CTFGEN_DATABASE_URL": self._url}):
                self.assertEqual(
                    admin_main(
                        [
                            "grant-membership",
                            "--competition",
                            _CID_A,
                            "--email",
                            _PLAYER_EMAIL,
                            "--role",
                            "player",
                            "--team",
                            "Red",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    admin_main(
                        [
                            "set-password",
                            "--email",
                            _PLAYER_EMAIL,
                            "--password",
                            _PLAYER_PW,
                        ]
                    ),
                    0,
                )
            now = datetime.now(UTC)
            issued = auth_service.authenticate(_PLAYER_EMAIL, _PLAYER_PW, now)
            principal = DbAuthenticator(auth_service).authenticate(issued.token)
            self.assertIsNotNone(principal)
            self.assertIn(
                Permission.SUBMISSION_CREATE,
                competition_permissions(principal, _CID_A),
            )


if __name__ == "__main__":
    unittest.main()
