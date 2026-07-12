"""PostgreSQL integration tests for the worker-facing job service (M8).

Docker-gated; skips cleanly without the db extra / CTFGEN_TEST_DATABASE_URL.

Proves the gate the M7 ``JobQueue.claim`` docstring demands: every queue verb is
authenticated and eligibility-checked, ``worker_id`` is derived only from the
credential (no spoofing), and a draining / quarantined / revoked / stale worker
is refused on the appropriate verbs -- with ``drain_requested_at`` now live.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_worker_job_service_integration
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
    from sqlalchemy.engine import make_url

    from ctf_generator.application.execution.worker_job_service import (
        WorkerAuthenticationError,
        WorkerDrainingError,
        WorkerJobService,
        WorkerStaleError,
    )
    from ctf_generator.application.worker_enrollment import (
        ScopeError,
        WorkerEnrollmentService,
    )
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.work.models import Job
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.job_queue_repository import (
        SqlAlchemyJobQueue,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"db extra not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
_CAPS = ("launch_instance", "collect_logs")


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_it_{uuid.uuid4().hex[:12]}"
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


@contextmanager
def _migrated_database():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield db, url
        finally:
            db.dispose()


def _enroll(db, enrollment, name, *, caps=_CAPS, capacity=2, scopes=None) -> str:
    enrollment.register_worker(
        Worker(name, "docker-rootless", ("x86_64",), caps, capacity, "1.0.0")
    )
    if scopes is None:
        issued = enrollment.approve_worker(name, _NOW)
    else:
        issued = enrollment.approve_worker(name, _NOW, scopes=scopes)
    return issued.token()


def _enqueue_launch_job(db, *, key=None) -> str:
    job = Job(
        job_id=str(uuid.uuid4()),
        job_type="launch_instance",
        idempotency_key=key or f"key-{uuid.uuid4().hex}",
        available_at=_NOW,
        required_capabilities=("launch_instance",),
    )
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).enqueue(job)
    return job.job_id


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerJobServiceHappyPathTests(unittest.TestCase):
    def test_full_lease_lifecycle_with_token(self) -> None:
        with _migrated_database() as (db, _url):
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wa")
            svc = WorkerJobService(db, enrollment)
            svc.ping(token, _NOW)  # establish liveness
            job_id = _enqueue_launch_job(db)

            lease = svc.claim(token, 60, _NOW)
            self.assertIsNotNone(lease)
            self.assertEqual(lease.job.job_id, job_id)
            # worker_id is derived from the credential, never request-supplied.
            self.assertEqual(lease.job.claimed_by, "wa")

            svc.start(token, job_id, lease.lease_token, _NOW)
            cancelled = svc.heartbeat(token, job_id, lease.lease_token, 60, _NOW)
            self.assertFalse(cancelled)
            svc.complete(token, job_id, lease.lease_token, {"ok": True}, None, None, _NOW)

            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyJobQueue(s).get(job_id).status, "succeeded")

    def test_claimed_by_is_the_credential_owner_not_a_spoof(self) -> None:
        with _migrated_database() as (db, _url):
            enrollment = WorkerEnrollmentService(db)
            token_a = _enroll(db, enrollment, "wa")
            _enroll(db, enrollment, "wb")  # a second identity exists
            svc = WorkerJobService(db, enrollment)
            svc.ping(token_a, _NOW)
            _enqueue_launch_job(db)

            lease = svc.claim(token_a, 60, _NOW)
            # No API surface accepts a worker_id; the claim is stamped with the
            # authenticated identity, so a caller cannot claim as "wb".
            self.assertEqual(lease.job.claimed_by, "wa")


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerJobServiceRejectionTests(unittest.TestCase):
    def test_bad_token_rejected(self) -> None:
        with _migrated_database() as (db, _url):
            enrollment = WorkerEnrollmentService(db)
            svc = WorkerJobService(db, enrollment)
            with self.assertRaises(WorkerAuthenticationError):
                svc.claim("ctfw1.not.a.real.token", 60, _NOW)

    def test_quarantined_worker_refused_on_every_verb(self) -> None:
        with _migrated_database() as (db, _url):
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wa")
            svc = WorkerJobService(db, enrollment)
            svc.ping(token, _NOW)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).quarantine("wa", _NOW, "isolation breach")
            with self.assertRaises(WorkerAuthenticationError):
                svc.claim(token, 60, _NOW)
            with self.assertRaises(WorkerAuthenticationError):
                svc.complete(token, str(uuid.uuid4()), str(uuid.uuid4()), None, None, None, _NOW)
            with self.assertRaises(WorkerAuthenticationError):
                svc.ping(token, _NOW)

    def test_revoked_worker_refused(self) -> None:
        with _migrated_database() as (db, _url):
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wa")
            svc = WorkerJobService(db, enrollment)
            svc.ping(token, _NOW)
            enrollment.revoke_worker("wa", _NOW)
            with self.assertRaises(WorkerAuthenticationError):
                svc.claim(token, 60, _NOW)

    def test_draining_worker_cannot_claim_but_can_finish(self) -> None:
        with _migrated_database() as (db, _url):
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wa")
            svc = WorkerJobService(db, enrollment)
            svc.ping(token, _NOW)
            job_id = _enqueue_launch_job(db)
            lease = svc.claim(token, 60, _NOW)  # claimed before drain
            svc.start(token, job_id, lease.lease_token, _NOW)

            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).drain("wa", _NOW)

            # New work is refused (drain_requested_at is now live) ...
            _enqueue_launch_job(db)
            with self.assertRaises(WorkerDrainingError):
                svc.claim(token, 60, _NOW)
            # ... but the in-flight lease can still be finished.
            svc.complete(token, job_id, lease.lease_token, None, None, None, _NOW)
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyJobQueue(s).get(job_id).status, "succeeded")

    def test_stale_worker_refused_then_ping_recovers(self) -> None:
        with _migrated_database() as (db, _url):
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wa")
            svc = WorkerJobService(db, enrollment)
            # last heartbeat is an hour old -> stale.
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).heartbeat("wa", _NOW - timedelta(hours=1))
            _enqueue_launch_job(db)
            with self.assertRaises(WorkerStaleError):
                svc.claim(token, 60, _NOW)
            svc.ping(token, _NOW)  # refresh liveness
            self.assertIsNotNone(svc.claim(token, 60, _NOW))

    def test_scope_enforced_before_queue(self) -> None:
        with _migrated_database() as (db, _url):
            enrollment = WorkerEnrollmentService(db)
            # A claim-only credential: it may not heartbeat.
            token = _enroll(db, enrollment, "wa", scopes=("jobs:claim",))
            svc = WorkerJobService(db, enrollment)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).heartbeat("wa", _NOW)
            with self.assertRaises(ScopeError):
                svc.heartbeat(token, str(uuid.uuid4()), str(uuid.uuid4()), 60, _NOW)


if __name__ == "__main__":
    unittest.main()
