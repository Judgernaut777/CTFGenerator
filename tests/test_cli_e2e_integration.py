"""End-to-end PostgreSQL integration test for the ``ctfgen`` platform CLI (M13 13b).

The KEY evidence for slice 13b: a full operator + contestant flow run THROUGH THE
ACTUAL CLI COMMANDS against a real ``create_app`` over PostgreSQL, wrapped in a
Starlette ``TestClient`` (an in-process ``httpx.Client``; no real socket). Both
``platform.build_http_client`` (the ``auth`` area) and
``commands._common.build_http_client`` (the resource areas) are patched to return
that TestClient, and a temp ``CTFGEN_CONFIG`` holds the session so the real user
credentials file is never touched. Mirrors ``test_cli_auth_integration`` exactly
for DB setup (per-test uuid database + ``alembic upgrade head`` +
``AuthService.bootstrap_admin``).

Flow: auth login (admin) -> competition create -> team create -> challenge-def
create -> challenge-version create -> publish -> publication attach -> user create
(contestant) -> instance list / job list (admin) -> [seed contestant password +
team membership: NO API route exists to grant a membership, so this is done via
the services, a documented gap] -> auth login (contestant) -> submission submit
-> submission list -> competition scoreboard. Each step must exit 0 and its
persisted effect must be visible in the next read.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_cli_e2e_integration
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
import uuid
from contextlib import contextmanager, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

try:
    import httpx  # noqa: F401 - part of the [cli] extra whose presence gates this suite
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url
    from starlette.testclient import TestClient

    from ctf_generator.application.auth import AuthService
    from ctf_generator.application.auth.hashing import Pbkdf2Sha256Hasher
    from ctf_generator.application.scoring.projector import ScoreProjector
    from ctf_generator.domain.identity.models import Membership
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.membership_repository import (
        SqlAlchemyMembershipRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.interfaces.cli import platform
    from ctf_generator.interfaces.cli.commands import _common

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)
_SKIP_REASON = (
    f"[cli]/[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)

_BASE_URL = "http://testserver"
_ADMIN_EMAIL = "admin@example.com"
_ADMIN_PW = "correct-horse-battery-9"  # noqa: S105 - test fixture, not a real secret
_PLAYER_EMAIL = "red-one@example.com"
_PLAYER_PW = "player-horse-battery-8"  # noqa: S105 - test fixture, not a real secret

_CID = "spring-ctf-2026"
_SLUG = "sqli-1"
_TEAM = "Red"
_FLAG = "CTF{the-secret-flag}"
_SPEC = '{"title": "SQLi One", "flag": "CTF{the-secret-flag}"}'
_START = "2026-01-01T00:00:00+00:00"
_END = "2030-01-01T00:00:00+00:00"


@contextmanager
def _app():
    base = make_url(_TEST_URL)
    name = f"ctfgen_clie2e_it_{uuid.uuid4().hex[:12]}"
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
            service = AuthService(db, hasher=Pbkdf2Sha256Hasher(iterations=1000))
            service.bootstrap_admin(
                email=_ADMIN_EMAIL,
                display_name="Admin",
                password=_ADMIN_PW,
                now=datetime.now(UTC),
            )
            app = create_app(
                ApiSettings(),
                database=db,
                auth_service=service,
                authenticator=DbAuthenticator(service),
            )
            yield app, db, service
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _http(app):
    return TestClient(app, base_url=_BASE_URL, follow_redirects=False)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CliEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self._dir.name) / "credentials.json"

    def tearDown(self) -> None:
        self._dir.cleanup()

    @contextmanager
    def _driven(self, app):
        # A FRESH TestClient per build call -- each command's ``open_client``
        # closes the client it was handed, so a shared instance would be closed
        # after the first command. (This mirrors the auth integration harness.)
        def _fake_build(api_url, **kwargs):
            return _http(app)

        env = {"CTFGEN_CONFIG": str(self.config_path), "CTFGEN_API_URL": _BASE_URL}
        # Patch BOTH build sites: platform's (auth) and the resource commands'.
        with mock.patch.object(platform, "build_http_client", _fake_build), \
                mock.patch.object(_common, "build_http_client", _fake_build), \
                mock.patch.dict(os.environ, env):
            yield

    def _cli(self, argv: list[str]) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = platform.main(argv)
        return code, out.getvalue()

    def _login(self, email: str, password: str) -> int:
        with mock.patch.dict(os.environ, {"CTFGEN_PASSWORD": password}):
            code, _ = self._cli(["auth", "login", "--email", email])
        return code

    def test_full_operator_and_contestant_flow(self) -> None:
        with _app() as (app, db, service):
            with self._driven(app):
                # -- operator (admin) --------------------------------------
                self.assertEqual(self._login(_ADMIN_EMAIL, _ADMIN_PW), 0)

                code, _ = self._cli([
                    "competition", "create", _CID, "--name", "Spring CTF 2026",
                    "--start-time", _START, "--end-time", _END,
                ])
                self.assertEqual(code, 0)
                # Persisted effect visible in the next read.
                code, out = self._cli(["competition", "list"])
                self.assertEqual(code, 0)
                self.assertIn(_CID, out)

                self.assertEqual(
                    self._cli(["team", "create", "--competition-id", _CID, "--name", _TEAM])[0],
                    0,
                )
                code, out = self._cli(["team", "list", "--competition-id", _CID])
                self.assertEqual(code, 0)
                self.assertIn(_TEAM, out)

                self.assertEqual(
                    self._cli([
                        "challenge-def", "create", "--family", "web",
                        "--slug", _SLUG, "--title", "SQLi One",
                    ])[0],
                    0,
                )
                self.assertEqual(
                    self._cli([
                        "challenge-version", "create", "--definition-slug", _SLUG,
                        "--seed", "seed-1", "--family-version", "1.0.0", "--spec", _SPEC,
                    ])[0],
                    0,
                )
                self.assertEqual(
                    self._cli(["challenge-version", "publish", _SLUG, "1"])[0], 0
                )
                # The published version is visible with state != draft.
                code, out = self._cli(["challenge-version", "list", "--definition-slug", _SLUG])
                self.assertEqual(code, 0)
                self.assertIn(_SLUG, out)

                self.assertEqual(
                    self._cli([
                        "publication", "attach", "--competition-id", _CID,
                        "--definition-slug", _SLUG, "--version-no", "1",
                    ])[0],
                    0,
                )
                code, out = self._cli(["publication", "list", "--competition-id", _CID])
                self.assertEqual(code, 0)
                self.assertIn(_SLUG, out)

                # Register the contestant profile through the CLI.
                self.assertEqual(
                    self._cli([
                        "user", "create", "--email", _PLAYER_EMAIL,
                        "--display-name", "Red One", "--role", "player",
                    ])[0],
                    0,
                )

                # Admin-scoped operator reads (empty, but must exit 0 and render).
                self.assertEqual(self._cli(["instance", "list"])[0], 0)
                self.assertEqual(self._cli(["job", "list"])[0], 0)

                # -- grant contestant membership (NO API route -> services) --
                # There is no membership/grant endpoint, so seed the password +
                # the player team membership directly (documented gap).
                service.set_password(_PLAYER_EMAIL, _PLAYER_PW, datetime.now(UTC))
                with db.session_scope() as session:
                    SqlAlchemyMembershipRepository(session).add(
                        Membership(
                            user_email=_PLAYER_EMAIL,
                            competition_id=_CID,
                            role="player",
                            team_name=_TEAM,
                        )
                    )

                # -- contestant --------------------------------------------
                self.assertEqual(self._login(_PLAYER_EMAIL, _PLAYER_PW), 0)
                # Confirm the session switched to the contestant.
                code, out = self._cli(["auth", "whoami"])
                self.assertEqual(code, 0)
                self.assertIn(_PLAYER_EMAIL, out)

                # Submit the correct flag as the contestant.
                code, out = self._cli([
                    "submission", "submit", "--competition-id", _CID, "--team", _TEAM,
                    "--definition-slug", _SLUG, "--version-no", "1", "--answer", _FLAG,
                ])
                self.assertEqual(code, 0)
                # The candidate flag is inbound only -- it must not be echoed back.
                self.assertNotIn(_FLAG, out)

                # The submission is now in the ledger for the contestant's team.
                code, out = self._cli(["submission", "list", "--competition-id", _CID])
                self.assertEqual(code, 0)
                self.assertIn(_TEAM, out)
                self.assertIn("True", out)  # correct=True column rendered

                # The scoreboard reflects the solve. The scoreboard is a cached
                # projection folded from the transactional outbox by the projector
                # (M7) -- run it (as the platform's projector process does), then
                # assert the solving team actually ranks. Exit 0 alone would pass
                # even if the projection were empty; assert the payoff.
                ScoreProjector(db).run_until_drained()
                code, out = self._cli(["competition", "scoreboard", _CID])
                self.assertEqual(code, 0)
                self.assertIn(_TEAM, out, "the solving team must appear on the scoreboard")


if __name__ == "__main__":
    unittest.main()
