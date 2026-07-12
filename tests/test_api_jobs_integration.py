"""PostgreSQL integration tests for the M9 slice-c jobs API ([api]+[db]).

get + dead-letter list + cancel + retry; the ops surface is admin/support only
(organizer / player -> 403); and a POSITIVE CONTROL that a job whose payload
carries a flag/seed does NOT leak it in the response (payload is never mapped).
SKIPS cleanly without the extras / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_api_jobs_integration
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
_ORGANIZER = "orgtoken"  # noqa: S105
_PLAYER = "playertoken"  # noqa: S105

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_api_jobs_{uuid.uuid4().hex[:12]}"
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
            # Jobs are a SYSTEM surface (flat require_permission, unchanged in
            # M10b); admin/support are deployment-global system roles.
            _ADMIN: principal_for("admin-user", {"admin"}, system_roles={"admin"}),
            _SUPPORT: principal_for(
                "support-user", {"support"}, system_roles={"support"}
            ),
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


def _job(payload=None, *, max_attempts=3) -> Job:
    return Job(
        job_id=str(uuid.uuid4()),
        job_type="build_challenge",
        idempotency_key=f"idem-{uuid.uuid4().hex}",
        available_at=_NOW,
        max_attempts=max_attempts,
        payload=payload or {"definition_slug": "sqli", "version_no": 1},
    )


def _enqueue(db: Database, job: Job) -> Job:
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).enqueue(job)
    return job


def _drive_to_dead_letter(db: Database, job: Job) -> None:
    """Exhaust a retryable job to dead_letter (claim -> start -> fail x N)."""
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
class JobsApiIntegrationTests(unittest.TestCase):
    def test_get_job(self) -> None:
        with _client_and_db() as (client, db):
            job = _enqueue(db, _job())
            r = client.get(f"/api/v1/jobs/{job.job_id}", headers=_auth(_ADMIN))
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["schema"], "ctfgen.job")
            self.assertEqual(r.json()["status"], "queued")
            self.assertEqual(r.json()["job_type"], "build_challenge")

    def test_get_missing_job_is_404(self) -> None:
        with _client_and_db() as (client, db):
            r = client.get(f"/api/v1/jobs/{uuid.uuid4()}", headers=_auth(_ADMIN))
            self.assertEqual(r.status_code, 404, r.text)

    def test_dead_letter_list_and_retry(self) -> None:
        with _client_and_db() as (client, db):
            job = _enqueue(db, _job(max_attempts=2))
            _drive_to_dead_letter(db, job)
            lst = client.get("/api/v1/jobs/dead-letter", headers=_auth(_SUPPORT))
            self.assertEqual(lst.status_code, 200, lst.text)
            self.assertIn(job.job_id, [j["job_id"] for j in lst.json()["data"]])

            retry = client.post(
                f"/api/v1/jobs/{job.job_id}/retry", headers=_auth(_SUPPORT)
            )
            self.assertEqual(retry.status_code, 200, retry.text)
            self.assertEqual(retry.json()["status"], "queued")

    def test_cancel_job(self) -> None:
        with _client_and_db() as (client, db):
            job = _enqueue(db, _job())
            r = client.post(
                f"/api/v1/jobs/{job.job_id}/cancel", headers=_auth(_ADMIN)
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["status"], "cancelled")

    def test_payload_flag_does_not_leak(self) -> None:
        with _client_and_db() as (client, db):
            secret_flag = "CTF{super-secret-flag-leak-check}"  # noqa: S105
            secret_seed = "seed-abcdef-secret"  # noqa: S105
            job = _enqueue(
                db, _job(payload={"flag": secret_flag, "seed": secret_seed})
            )
            r = client.get(f"/api/v1/jobs/{job.job_id}", headers=_auth(_ADMIN))
            self.assertEqual(r.status_code, 200, r.text)
            self.assertNotIn(secret_flag, r.text)
            self.assertNotIn(secret_seed, r.text)
            self.assertNotIn("payload", r.json())

    def test_authz_admin_and_support_only(self) -> None:
        with _client_and_db() as (client, db):
            job = _enqueue(db, _job())
            # organizer and player are denied the whole ops surface.
            for token in (_ORGANIZER, _PLAYER):
                for method, path in (
                    ("get", f"/api/v1/jobs/{job.job_id}"),
                    ("get", "/api/v1/jobs/dead-letter"),
                    ("post", f"/api/v1/jobs/{job.job_id}/cancel"),
                    ("post", f"/api/v1/jobs/{job.job_id}/retry"),
                ):
                    r = getattr(client, method)(path, headers=_auth(token))
                    self.assertEqual(
                        r.status_code, 403, f"{token} {method} {path}: {r.text}"
                    )
            # support (ops staff) may read.
            ok = client.get(f"/api/v1/jobs/{job.job_id}", headers=_auth(_SUPPORT))
            self.assertEqual(ok.status_code, 200, ok.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
