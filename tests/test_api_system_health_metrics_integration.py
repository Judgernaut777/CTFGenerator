"""PostgreSQL integration tests for the M16b readiness DEPTH + metrics endpoint
([api]+[db]).

* ``/system/ready`` returns the structured multi-check body: DB up + migrations
  at head -> ``ready`` (200); a dead-lettered job surfaces as ``degraded`` (200,
  NOT 503 -- serving but attention-needed); an out-of-date ``alembic_version``
  (migrations behind, a HARD dependency) -> 503.
* ``/system/metrics`` returns Prometheus v0.0.4 text with the expected gauges +
  build_info, is admin/support-gated (contestant -> 403), never 500s, and leaks
  no secret.

SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_system_health_metrics_integration
"""

from __future__ import annotations

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

    from ctf_generator.domain.work.models import Job
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.job_queue_repository import (
        SqlAlchemyJobQueue,
    )
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
_SUPPORT = "supporttoken"  # noqa: S105
_PLAYER = "playertoken"  # noqa: S105

_NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_sys_{uuid.uuid4().hex[:12]}"
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
            _SUPPORT: principal_for(
                "support-user", {"support"}, system_roles={"support"}
            ),
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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _job(*, max_attempts=2) -> Job:
    return Job(
        job_id=str(uuid.uuid4()),
        job_type="build_challenge",
        idempotency_key=f"idem-{uuid.uuid4().hex}",
        available_at=_NOW,
        max_attempts=max_attempts,
        payload={"definition_slug": "sqli", "version_no": 1},
    )


def _drive_to_dead_letter(db: Database, job: Job) -> None:
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).enqueue(job)
    now = _NOW
    for _ in range(job.max_attempts):
        now = now + timedelta(hours=1)
        with db.session_scope() as s:
            lease = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, now)
        assert lease is not None
        with db.session_scope() as s:
            SqlAlchemyJobQueue(s).start(job.job_id, lease.lease_token, now)
        with db.session_scope() as s:
            SqlAlchemyJobQueue(s).fail(
                job.job_id, lease.lease_token, "transient", None, True, now
            )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class ReadinessDepthTests(unittest.TestCase):
    def test_ready_when_db_up_and_migrations_at_head(self) -> None:
        with _client_and_db() as (client, _db):
            r = client.get("/api/v1/system/ready")
            self.assertEqual(r.status_code, 200, r.text)
            body = r.json()
            self.assertEqual(body["status"], "ready")
            self.assertFalse(body["degraded"])
            checks = body["checks"]
            self.assertEqual(checks["database"]["status"], "up")
            self.assertEqual(checks["migrations"]["status"], "ok")
            self.assertEqual(checks["dead_letter"]["status"], "ok")
            self.assertEqual(checks["projection_lag"]["status"], "ok")

    def test_dead_letter_is_degraded_not_down(self) -> None:
        with _client_and_db() as (client, db):
            _drive_to_dead_letter(db, _job())
            r = client.get("/api/v1/system/ready")
            # Soft signal: SERVING (200) but flagged degraded.
            self.assertEqual(r.status_code, 200, r.text)
            body = r.json()
            self.assertEqual(body["status"], "degraded")
            self.assertTrue(body["degraded"])
            self.assertEqual(body["checks"]["dead_letter"]["status"], "degraded")
            self.assertGreaterEqual(body["checks"]["dead_letter"]["count"], 1)

    def test_migrations_behind_is_503(self) -> None:
        with _client_and_db() as (client, db):
            # Simulate a code-ahead deployment: the DB is at an OLD revision.
            with db.session_scope() as s:
                s.execute(
                    sa.text("UPDATE alembic_version SET version_num = :v"),
                    {"v": "0001_stale"},
                )
            r = client.get("/api/v1/system/ready")
            self.assertEqual(r.status_code, 503, r.text)
            body = r.json()
            self.assertEqual(body["status"], "unavailable")
            self.assertEqual(body["checks"]["migrations"]["status"], "behind")
            self.assertEqual(body["checks"]["database"]["status"], "up")

    def test_health_and_live_are_200(self) -> None:
        with _client_and_db() as (client, _db):
            for path in ("/api/v1/system/health", "/api/v1/system/live"):
                r = client.get(path)
                self.assertEqual(r.status_code, 200, r.text)
                self.assertEqual(r.json()["status"], "ok")


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class MetricsEndpointTests(unittest.TestCase):
    def test_metrics_prometheus_text_and_gauges(self) -> None:
        with _client_and_db() as (client, db):
            _drive_to_dead_letter(db, _job())
            r = client.get("/api/v1/system/metrics", headers=_auth(_ADMIN))
            self.assertEqual(r.status_code, 200, r.text)
            self.assertIn("version=0.0.4", r.headers["content-type"])
            text = r.text
            self.assertIn("# TYPE ctfgen_jobs_dead_letter gauge", text)
            self.assertIn("ctfgen_projection_pending ", text)
            self.assertIn("ctfgen_projection_failed ", text)
            self.assertIn("ctfgen_eval_runs_non_terminal ", text)
            self.assertRegex(text, r"ctfgen_build_info\{version=\"[^\"]+\"\} 1")
            # dead-letter gauge reflects the driven job.
            dl = _gauge_value(text, "ctfgen_jobs_dead_letter")
            self.assertGreaterEqual(dl, 1)

    def test_metrics_requires_admin_or_support(self) -> None:
        with _client_and_db() as (client, _db):
            self.assertEqual(
                client.get(
                    "/api/v1/system/metrics", headers=_auth(_ADMIN)
                ).status_code,
                200,
            )
            self.assertEqual(
                client.get(
                    "/api/v1/system/metrics", headers=_auth(_SUPPORT)
                ).status_code,
                200,
            )
            # A contestant is denied.
            self.assertEqual(
                client.get(
                    "/api/v1/system/metrics", headers=_auth(_PLAYER)
                ).status_code,
                403,
            )
            # Unauthenticated is denied (metrics are not public).
            self.assertEqual(
                client.get("/api/v1/system/metrics").status_code, 401
            )

    def test_metrics_are_secret_free(self) -> None:
        with _client_and_db() as (client, _db):
            text = client.get(
                "/api/v1/system/metrics", headers=_auth(_ADMIN)
            ).text
            for shape in ("ctf{", "sk-ant-", "postgres://", "postgresql://", "Bearer "):
                self.assertNotIn(shape, text)


def _gauge_value(text: str, name: str) -> int:
    for line in text.splitlines():
        if line.startswith(name + " "):
            return int(line.split(" ", 1)[1])
    raise AssertionError(f"gauge {name} not found in:\n{text}")


@unittest.skipUnless(_IMPORT_ERROR is None, _SKIP_REASON)
class MetricsAndReadinessNoDbTests(unittest.TestCase):
    """The never-500 guards need NO PostgreSQL -- an app built with database=None
    exercises the read-model-failure / all-gauges-omitted + DB-down paths."""

    def _client(self) -> TestClient:
        app = create_app(
            ApiSettings(), database=None, authenticator=_authenticator()
        )
        return TestClient(app)

    def test_metrics_with_no_database_is_200_not_500(self) -> None:
        client = self._client()
        r = client.get("/api/v1/system/metrics", headers=_auth(_ADMIN))
        self.assertEqual(r.status_code, 200, r.text)  # never a 500
        # build_info always renders; the DB-backed gauges are omitted, not crashed.
        self.assertIn("ctfgen_build_info", r.text)
        # Secret-free + valid content type.
        self.assertIn("text/plain", r.headers["content-type"])

    def test_ready_with_no_database_is_503_not_500(self) -> None:
        client = self._client()
        r = client.get("/api/v1/system/ready")
        self.assertEqual(r.status_code, 503, r.text)  # DB down -> hard-unready
        self.assertNotIn("Traceback", r.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
