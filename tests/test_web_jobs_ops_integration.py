"""PostgreSQL integration tests for the M11c JOB-QUEUE ops views (admin/support).

Dead-letter list + a job lookup render; cancel / retry drive job state (DB-verified)
for a system-role caller; an organizer WITHOUT a system role is 403 (nothing
performed); a job whose payload carries a flag/seed never leaks it on any page
(the DTO exposes type/state/attempts/timestamps/error-class only); CSRF is
enforced on cancel + retry. SKIPS cleanly without the extras / test DB.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_web_jobs_ops_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from datetime import timedelta

try:
    import sqlalchemy as sa
    import web_support as ws

    from ctf_generator.domain.work.models import Job
    from ctf_generator.infrastructure.database.job_queue_repository import (
        SqlAlchemyJobQueue,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_SKIP_REASON = (
    f"[api]/[web]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

# A payload carrying exactly the kind of secret the DTO must refuse to surface.
_FLAG = "CTF{payload-flag-must-not-leak}"
_SEED = "payload-SEED-must-not-leak"  # noqa: S105


def _job(*, max_attempts: int = 3, payload=None) -> Job:
    return Job(
        job_id=str(uuid.uuid4()),
        job_type="build_challenge",
        idempotency_key=f"idem-{uuid.uuid4().hex}",
        available_at=ws.NOW,
        max_attempts=max_attempts,
        payload=payload or {"definition_slug": "sqli", "version_no": 1},
    )


def _enqueue(db, job: Job) -> Job:
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).enqueue(job)
    return job


def _drive_to_dead_letter(db, job: Job) -> None:
    now = ws.NOW
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


def _status(db, jid: str) -> str | None:
    with db.session_scope() as s:
        return s.execute(
            sa.text("SELECT status FROM jobs WHERE id = :jid"), {"jid": jid}
        ).scalar_one_or_none()


def _csrf(client, path):
    r = client.get(path)
    return r, ws.extract_csrf(r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class JobsOpsWebTests(unittest.TestCase):
    def test_dead_letter_list_and_lookup_for_admin(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.DAVE)  # system admin
            job = _job()
            _enqueue(db, job)
            _drive_to_dead_letter(db, job)

            page = client.get("/app/ops/jobs")
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn(job.job_id, page.text)
            self.assertIn("build_challenge", page.text)

            lookup = client.get("/app/ops/jobs", params={"job_id": job.job_id})
            self.assertEqual(lookup.status_code, 200, lookup.text)
            self.assertIn("dead_letter", lookup.text)

    def test_retry_and_cancel_drive_state_for_support(self) -> None:
        with ws.web_client() as (client, db, svc):
            svc.grant_system_role(ws.NOBODY, "support")
            ws.login(client, ws.NOBODY)  # support: JOB_READ + JOB_OPERATE

            dead = _job()
            _enqueue(db, dead)
            _drive_to_dead_letter(db, dead)
            _r, token = _csrf(client, "/app/ops/jobs")
            retry = client.post(
                f"/app/ops/jobs/{dead.job_id}/retry",
                data={"csrf_token": token},
                follow_redirects=False,
            )
            self.assertEqual(retry.status_code, 303, retry.text)
            self.assertEqual(_status(db, dead.job_id), "queued")

            # Cancel a queued job.
            queued = _enqueue(db, _job())
            _r, token = _csrf(client, "/app/ops/jobs")
            cancel = client.post(
                f"/app/ops/jobs/{queued.job_id}/cancel",
                data={"csrf_token": token},
                follow_redirects=False,
            )
            self.assertEqual(cancel.status_code, 303, cancel.text)
            self.assertEqual(_status(db, queued.job_id), "cancelled")

    def test_organizer_without_system_role_is_403(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.ALICE)  # organizer, no system role
            self.assertEqual(client.get("/app/ops/jobs").status_code, 403)

            queued = _enqueue(db, _job())
            _r, token = _csrf(client, f"/app/competitions/{ws.COMP_A}")
            resp = client.post(
                f"/app/ops/jobs/{queued.job_id}/cancel",
                data={"csrf_token": token or ""},
                follow_redirects=False,
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(_status(db, queued.job_id), "queued")  # unchanged

    def test_contestant_is_403(self) -> None:
        with ws.web_client() as (client, _db, _svc):
            ws.login(client, ws.EVE)
            self.assertEqual(client.get("/app/ops/jobs").status_code, 403)

    def test_payload_flag_and_seed_never_leak(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.DAVE)
            job = _job(payload={"flag": _FLAG, "seed": _SEED, "version_no": 1})
            _enqueue(db, job)
            _drive_to_dead_letter(db, job)

            listing = client.get("/app/ops/jobs")
            lookup = client.get("/app/ops/jobs", params={"job_id": job.job_id})
            for page in (listing, lookup):
                self.assertEqual(page.status_code, 200, page.text)
                self.assertNotIn(_FLAG, page.text)
                self.assertNotIn(_SEED, page.text)
                self.assertNotIn("style=", page.text)

    def test_cancel_without_csrf_is_403_and_no_change(self) -> None:
        with ws.web_client() as (client, db, _svc):
            ws.login(client, ws.DAVE)
            queued = _enqueue(db, _job())
            resp = client.post(
                f"/app/ops/jobs/{queued.job_id}/cancel", follow_redirects=False
            )
            self.assertEqual(resp.status_code, 403, resp.text)
            self.assertEqual(_status(db, queued.job_id), "queued")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
