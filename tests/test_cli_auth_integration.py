"""PostgreSQL integration tests for the platform CLI auth area (M13 slice 13a).

Drives the real ``ApiClient`` + the ``ctfgen auth`` commands against a genuine
``create_app`` over PostgreSQL, wrapped in an in-process ``httpx.ASGITransport``
(no real socket). Seeds a login-able admin via ``AuthService.bootstrap_admin``,
then asserts: login stores a 0600 token (never printed), whoami shows the admin
subject + admin system role, logout revokes it (a later whoami -> AuthRequired),
and a revoked/garbage token -> AuthRequired.

Uses a temp ``CTFGEN_CONFIG`` so the real user credentials file is never touched.
SKIPS cleanly without [api]+[db]+CTFGEN_TEST_DATABASE_URL.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_cli_auth_integration
"""

from __future__ import annotations

import io
import os
import stat
import tempfile
import unittest
import uuid
from contextlib import contextmanager
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
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.interfaces.cli import platform
    from ctf_generator.interfaces.cli.client import ApiClient
    from ctf_generator.interfaces.cli.config import TokenStore
    from ctf_generator.interfaces.cli.errors import AuthRequired

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

_EMAIL = "admin@example.com"
_PASSWORD = "correct-horse-battery-9"  # noqa: S105 - test fixture, not a real secret
_BASE_URL = "http://testserver"


@contextmanager
def _app():
    base = make_url(_TEST_URL)
    name = f"ctfgen_cliauth_it_{uuid.uuid4().hex[:12]}"
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
                email=_EMAIL,
                display_name="Admin",
                password=_PASSWORD,
                now=datetime.now(UTC),
            )
            app = create_app(
                ApiSettings(),
                database=db,
                auth_service=service,
                authenticator=DbAuthenticator(service),
            )
            yield app
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _http(app):
    # Starlette's TestClient IS an httpx.Client that drives an ASGI app
    # SYNCHRONOUSLY (via an anyio portal). A plain httpx.Client + ASGITransport
    # is async-only (handle_async_request) and cannot be driven by the CLI's sync
    # ApiClient -- TestClient is the correct in-process transport here. Redirects
    # off to match the production build_http_client (no cross-origin token leak).
    return TestClient(app, base_url=_BASE_URL, follow_redirects=False)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CliAuthClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.store = TokenStore(Path(self._dir.name) / "credentials.json")

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_login_whoami_logout_flow(self) -> None:
        with _app() as app:
            http = _http(app)
            try:
                # login (unauthenticated).
                issued = ApiClient(http, self.store, _BASE_URL).request(
                    "POST", "/auth/login",
                    json={"email": _EMAIL, "password": _PASSWORD},
                    authed=False,
                )
                token = issued["token"]
                self.assertTrue(token)
                # /auth/me with the fresh token shows the admin subject + role.
                me = ApiClient(http, self.store, _BASE_URL, token_override=token).request(
                    "GET", "/auth/me"
                )
                self.assertEqual(me["subject"], _EMAIL)
                self.assertIn("admin", me["system_roles"])

                # Persist the session and confirm 0600 + token not otherwise leaked.
                from ctf_generator.interfaces.cli.config import Session

                self.store.save(
                    Session(api_url=_BASE_URL, token=token, subject=me["subject"])
                )
                self.assertEqual(
                    stat.S_IMODE(self.store.path.stat().st_mode), 0o600
                )

                # whoami via the stored session.
                who = ApiClient(http, self.store, _BASE_URL).request("GET", "/auth/me")
                self.assertEqual(who["subject"], _EMAIL)

                # logout revokes the session server-side.
                ApiClient(http, self.store, _BASE_URL).request("POST", "/auth/logout")

                # The now-revoked token no longer authenticates -> AuthRequired
                # (401 -> refresh with the revoked token also 401 -> AuthRequired).
                with self.assertRaises(AuthRequired):
                    ApiClient(http, self.store, _BASE_URL).request("GET", "/auth/me")
            finally:
                http.close()

    def test_garbage_token_raises_auth_required(self) -> None:
        with _app() as app:
            http = _http(app)
            try:
                with self.assertRaises(AuthRequired):
                    ApiClient(
                        http, self.store, _BASE_URL, token_override="garbage-token"
                    ).request("GET", "/auth/me")
            finally:
                http.close()

    def test_wrong_password_is_apierror_not_auth_required(self) -> None:
        from ctf_generator.interfaces.cli.errors import ApiError

        with _app() as app:
            http = _http(app)
            try:
                with self.assertRaises(ApiError) as cm:
                    ApiClient(http, self.store, _BASE_URL).request(
                        "POST", "/auth/login",
                        json={"email": _EMAIL, "password": "wrong"},
                        authed=False,
                    )
                self.assertEqual(cm.exception.status_code, 401)
            finally:
                http.close()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CliAuthCommandTests(unittest.TestCase):
    """Drive the actual ``ctfgen auth`` command functions (login/whoami/logout)
    against the ASGI app by pointing ``build_http_client`` at it and the token
    store at a temp ``CTFGEN_CONFIG`` file."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self._dir.name) / "credentials.json"

    def tearDown(self) -> None:
        self._dir.cleanup()

    @contextmanager
    def _driven(self, app):
        def _fake_build(api_url, **kwargs):
            return _http(app)

        env = {
            "CTFGEN_CONFIG": str(self.config_path),
            "CTFGEN_API_URL": _BASE_URL,
            "CTFGEN_PASSWORD": _PASSWORD,
        }
        with mock.patch.object(platform, "build_http_client", _fake_build), \
                mock.patch.dict(os.environ, env):
            yield

    def test_login_command_stores_session_without_printing_token(self) -> None:
        with _app() as app, self._driven(app):
            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                code = platform.main(["auth", "login", "--email", _EMAIL])
            self.assertEqual(code, 0)
            printed = out.getvalue()
            self.assertIn(_EMAIL, printed)
            # 0600 file, and the token is never in stdout.
            self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode), 0o600)
            stored = TokenStore(self.config_path).load()
            self.assertIsNotNone(stored)
            self.assertNotIn(stored.token, printed)

            # whoami over the stored session.
            who = io.StringIO()
            with mock.patch("sys.stdout", who):
                code = platform.main(["auth", "whoami"])
            self.assertEqual(code, 0)
            self.assertIn(_EMAIL, who.getvalue())

            # logout clears the store and revokes server-side.
            code = platform.main(["auth", "logout"])
            self.assertEqual(code, 0)
            self.assertIsNone(TokenStore(self.config_path).load())

            # whoami now has no session -> auth-required exit code (3).
            code = platform.main(["auth", "whoami"])
            self.assertEqual(code, 3)

    def test_logout_without_session_is_friendly_noop(self) -> None:
        with _app() as app, self._driven(app):
            code = platform.main(["auth", "logout"])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
