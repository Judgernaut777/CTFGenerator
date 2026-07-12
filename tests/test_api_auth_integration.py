"""PostgreSQL integration tests for the /auth API (M10a; [api]+[db], real PG).

login (correct -> token; wrong password -> 401; unknown email -> 401 and
INDISTINGUISHABLE); the unknown-email timing side channel (the KDF still runs);
/auth/me returns the real principal; refresh rotates (old token dies, new works);
logout revokes; and REQ-INV-011 -- the raw token / password / hash never appears
in any log record. SKIPS cleanly without the extras / CTFGEN_TEST_DATABASE_URL.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_auth_integration
"""

from __future__ import annotations

import hashlib
import logging
import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from fastapi.testclient import TestClient
    from sqlalchemy.engine import make_url

    from ctf_generator.application.auth import AuthService
    from ctf_generator.application.auth.hashing import Pbkdf2Sha256Hasher
    from ctf_generator.domain.identity.models import User
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
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

_EMAIL = "alice@example.com"
_PASSWORD = "correct-horse-battery"  # noqa: S105 - test fixture, not a real secret


class _SpyHasher:
    """A fast hasher that records verify calls (so a test can assert the KDF ran
    even for an unknown email). Delegates to a low-iteration PBKDF2."""

    def __init__(self) -> None:
        self._inner = Pbkdf2Sha256Hasher(iterations=1000)
        self.verify_calls: list[str] = []

    def hash(self, password: str) -> str:
        return self._inner.hash(password)

    def verify(self, password: str, encoded: str) -> bool:
        self.verify_calls.append(encoded)
        return self._inner.verify(password, encoded)

    def needs_rehash(self, encoded: str) -> bool:
        return self._inner.needs_rehash(encoded)


@contextmanager
def _app(hasher=None, *, seed=True):
    base = make_url(_TEST_URL)
    name = f"ctfgen_apiauth_it_{uuid.uuid4().hex[:12]}"
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
            service = AuthService(db, hasher=hasher or Pbkdf2Sha256Hasher(iterations=1000))
            if seed:
                with db.session_scope() as s:
                    SqlAlchemyUserRepository(s).add(
                        User(email=_EMAIL, display_name="Alice")
                    )
                service.set_password(_EMAIL, _PASSWORD, datetime.now(UTC))
                service.grant_system_role(_EMAIL, "admin")
            app = create_app(
                ApiSettings(),
                database=db,
                auth_service=service,
                authenticator=DbAuthenticator(service),
            )
            yield TestClient(app), service
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _login(client, email=_EMAIL, password=_PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AuthApiIntegrationTests(unittest.TestCase):
    def test_login_success_returns_token_and_me_returns_principal(self) -> None:
        with _app() as (client, _service):
            r = _login(client)
            self.assertEqual(r.status_code, 200, r.text)
            token = r.json()["token"]
            self.assertTrue(token)
            self.assertIn("expires_at", r.json())

            me = client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(me.status_code, 200, me.text)
            body = me.json()
            self.assertEqual(body["subject"], _EMAIL)
            self.assertEqual(body["system_roles"], ["admin"])
            self.assertIn("admin", body["roles"])
            # /auth/me NEVER leaks a token or hash.
            self.assertNotIn("token", body)
            self.assertNotIn("password", body)

    def test_wrong_password_and_unknown_email_are_indistinguishable(self) -> None:
        with _app() as (client, _service):
            wrong = _login(client, password="not-the-password")  # noqa: S106
            unknown = _login(client, email="ghost@example.com")
            self.assertEqual(wrong.status_code, 401)
            self.assertEqual(unknown.status_code, 401)
            # Same code AND same message -> no oracle for account existence
            # (request_id differs per request and is not part of the signal).
            wrong_err = {k: v for k, v in wrong.json()["error"].items() if k != "request_id"}
            unknown_err = {
                k: v for k, v in unknown.json()["error"].items() if k != "request_id"
            }
            self.assertEqual(wrong_err, unknown_err)
            self.assertEqual(wrong_err["code"], "unauthorized")

    def test_unknown_email_still_runs_the_kdf(self) -> None:
        # Structural proof the timing side channel is closed: the hasher's verify
        # (the KDF) is invoked even when the email does not exist -- login does
        # not early-return before hashing.
        spy = _SpyHasher()
        with _app(hasher=spy) as (client, _service):
            before = len(spy.verify_calls)
            r = _login(client, email="nobody@example.com")
            self.assertEqual(r.status_code, 401)
            self.assertGreater(
                len(spy.verify_calls), before, "KDF was not run for unknown email"
            )

    def test_refresh_rotates_token(self) -> None:
        with _app() as (client, _service):
            token = _login(client).json()["token"]
            r = client.post(
                "/api/v1/auth/refresh",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(r.status_code, 200, r.text)
            new_token = r.json()["token"]
            self.assertNotEqual(new_token, token)
            # Old token is dead; new token works.
            old = client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(old.status_code, 401)
            new = client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"}
            )
            self.assertEqual(new.status_code, 200)

    def test_logout_revokes_token(self) -> None:
        with _app() as (client, _service):
            token = _login(client).json()["token"]
            out = client.post(
                "/api/v1/auth/logout",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(out.status_code, 204)
            after = client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(after.status_code, 401)

    def test_missing_bearer_on_me_is_401(self) -> None:
        with _app() as (client, _service):
            self.assertEqual(client.get("/api/v1/auth/me").status_code, 401)

    def test_token_password_and_hash_never_logged(self) -> None:
        # REQ-INV-011: drive login + refresh with a root log capture and assert
        # the raw token, the password, and the token's sha256 hash never appear.
        records: list[str] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                try:
                    records.append(record.getMessage())
                except Exception:  # pragma: no cover
                    records.append(str(record.msg))

        handler = _Capture()
        root = logging.getLogger()
        prev_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            with _app() as (client, _service):
                token = _login(client).json()["token"]
                refreshed = client.post(
                    "/api/v1/auth/refresh",
                    headers={"Authorization": f"Bearer {token}"},
                ).json()["token"]
        finally:
            root.removeHandler(handler)
            root.setLevel(prev_level)

        blob = "\n".join(records)
        self.assertNotIn(token, blob)
        self.assertNotIn(refreshed, blob)
        self.assertNotIn(_PASSWORD, blob)
        self.assertNotIn(hashlib.sha256(token.encode()).hexdigest(), blob)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
