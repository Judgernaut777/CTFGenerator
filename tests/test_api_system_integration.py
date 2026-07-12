"""Tests for the M9 slice-c system probes (health / readiness / version).

The unauthenticated probes need no database for health / version / the
readiness-DOWN path (``database=None``) and the readiness helper's failure branch
(a stub DB), so those run with just the ``[api]`` extra. The readiness-UP path
runs a real ``SELECT 1`` against Docker PG when ``CTFGEN_TEST_DATABASE_URL`` is
set. SKIPS cleanly otherwise.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_system_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:
    from fastapi.testclient import TestClient

    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.routers.system import database_ready
    from ctf_generator.interfaces.api.settings import ApiSettings

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database

    _DB_IMPORT_OK = True
except Exception:  # pragma: no cover
    _DB_IMPORT_OK = False

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_API_OK = _IMPORT_ERROR is None
_ENABLED = _API_OK and _DB_IMPORT_OK and bool(_TEST_URL)
_API_REASON = f"[api] not importable ({_IMPORT_ERROR})"
_DB_REASON = "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"


class _RaisingDatabase:
    """A stub whose session_scope raises -- the DB-down readiness branch."""

    def session_scope(self):
        raise RuntimeError("connection refused")


class _WorkingDatabase:
    @contextmanager
    def session_scope(self):
        class _S:
            def execute(self, *_a, **_k):
                return None

        yield _S()


@unittest.skipUnless(_API_OK, _API_REASON)
class SystemReadinessHelperTests(unittest.TestCase):
    def test_none_database_is_not_ready(self) -> None:
        self.assertFalse(database_ready(None))

    def test_raising_database_is_not_ready(self) -> None:
        self.assertFalse(database_ready(_RaisingDatabase()))

    def test_working_database_is_ready(self) -> None:
        self.assertTrue(database_ready(_WorkingDatabase()))


@unittest.skipUnless(_API_OK, _API_REASON)
class SystemProbeTests(unittest.TestCase):
    def _client(self, *, database=None) -> TestClient:
        return TestClient(create_app(ApiSettings(), database=database))

    def test_health_is_200_without_auth(self) -> None:
        r = self._client().get("/api/v1/system/health")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "ok")
        self.assertEqual(r.json()["schema"], "ctfgen.system-health")

    def test_version_shape(self) -> None:
        r = self._client().get("/api/v1/system/version")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIn("name", body)
        self.assertIn("version", body)
        self.assertEqual(body["version"], ApiSettings().version)

    def test_ready_returns_503_envelope_when_db_down(self) -> None:
        # No database configured -> unavailable, in the envelope, no auth needed.
        r = self._client(database=None).get("/api/v1/system/ready")
        self.assertEqual(r.status_code, 503, r.text)
        self.assertEqual(r.json()["status"], "unavailable")
        self.assertEqual(r.json()["schema"], "ctfgen.system-readiness")


@unittest.skipUnless(_ENABLED, _DB_REASON if _API_OK else _API_REASON)
class SystemReadinessUpTests(unittest.TestCase):
    def test_ready_is_200_when_db_up(self) -> None:
        base = make_url(_TEST_URL)
        name = f"ctfgen_api_sys_{uuid.uuid4().hex[:12]}"
        admin = sa.create_engine(
            base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
        )
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        url = base.set(database=name).render_as_string(hide_password=False)
        try:
            cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
            cfg.set_main_option(
                "script_location", os.path.join(_REPO_ROOT, "alembic")
            )
            cfg.set_main_option("sqlalchemy.url", str(url))
            command.upgrade(cfg, "head")
            db = Database(DatabaseConfig(url=url))
            try:
                client = TestClient(create_app(ApiSettings(), database=db))
                r = client.get("/api/v1/system/ready")
                self.assertEqual(r.status_code, 200, r.text)
                self.assertEqual(r.json()["status"], "ready")
            finally:
                db.dispose()
        finally:
            with admin.connect() as conn:
                conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            admin.dispose()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
