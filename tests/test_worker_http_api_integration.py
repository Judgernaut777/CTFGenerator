"""PostgreSQL integration tests for the M9 worker HTTP gateway ([api]+[db]).

This is the SECURITY slice -- the worker trust boundary over the network. The
tests PROVE, over the real FastAPI app + a real PostgreSQL, that:

* the happy path works end-to-end (auth -> claim -> start/heartbeat/complete;
  report health/endpoint/transition on an OWNED instance);
* worker identity is derived EXCLUSIVELY from the credential -- a spoofed
  ``worker_name`` in the body is ignored and the action is attributed to the
  credential's worker (asserted via the DB);
* a bad / revoked / non-trusted / draining / quarantined / stale credential is
  refused with the correct 401 / 409, never a success;
* a wrong ``lease_token`` (a job the worker did not claim) is rejected;
* a worker cannot read / report / transition an instance it does not own;
* the worker auth plane and the human Principal auth plane are DISJOINT; and
* no response ever carries the credential token, a flag, or a seed.

Skips cleanly without the ``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_worker_http_api_integration
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

    from ctf_generator.application.worker_enrollment import WorkerEnrollmentService
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.instances.models import Instance, InstanceCredential
    from ctf_generator.domain.work.models import Job
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.competition_repository import (
        SqlAlchemyCompetitionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.instance_repository import (
        SqlAlchemyInstanceRepository,
    )
    from ctf_generator.infrastructure.database.job_queue_repository import (
        SqlAlchemyJobQueue,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
    )
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
_ORGANIZER = "orgtoken"  # noqa: S105
_PLAYER = "playertoken"  # noqa: S105
_CID = "spring-ctf-2026"
_WORKER = "w1"
_OTHER_WORKER = "w2"
_CAPS = ("launch_instance", "stop_instance")
_SEED_SECRET = "SEED-must-not-leak-9f9f"  # noqa: S105
_CRED_SECRET = "vault://cred-must-not-leak-1a1a"  # noqa: S105


def _now() -> datetime:
    return datetime.now(UTC)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_wh_{uuid.uuid4().hex[:12]}"
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
            _ADMIN: principal_for("admin-user", {"admin"}),
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
            app = create_app(ApiSettings(), database=db, authenticator=_authenticator())
            yield TestClient(app), db
        finally:
            db.dispose()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _enroll_worker(
    db, name=_WORKER, *, caps=_CAPS, architectures=("x86_64",), fresh=True, scopes=None
) -> str:
    """Register + approve a worker and return its bearer token. Establishes a fresh
    liveness heartbeat unless ``fresh`` is False (used for the stale test)."""
    enrollment = WorkerEnrollmentService(db)
    enrollment.register_worker(
        Worker(name, "docker-rootless", architectures, caps, 4, "1.0.0")
    )
    now = _now()
    issued = (
        enrollment.approve_worker(name, now)
        if scopes is None
        else enrollment.approve_worker(name, now, scopes=scopes)
    )
    if fresh:
        with db.session_scope() as s:
            SqlAlchemyWorkerRegistry(s).heartbeat(name, now)
    return issued.token()


def _enqueue_launch_job(db, *, key=None, instance_id=None) -> str:
    payload = {"instance_id": instance_id} if instance_id else {}
    job = Job(
        job_id=str(uuid.uuid4()),
        job_type="launch_instance",
        idempotency_key=key or f"key-{uuid.uuid4().hex}",
        available_at=_now() - timedelta(seconds=5),
        required_capabilities=("launch_instance",),
        payload=payload,
    )
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).enqueue(job)
    return job.job_id


def _ensure_parents(db) -> None:
    """Seed the competition / team / challenge version an instance references
    (idempotent: a no-op once the competition exists)."""
    with db.session_scope() as s:
        if SqlAlchemyCompetitionRepository(s).get(_CID) is not None:
            return
    now = _now()
    with db.session_scope() as s:
        SqlAlchemyCompetitionRepository(s).add(
            CompetitionConfig(
                competition_id=_CID, name="Spring CTF",
                start_time=now - timedelta(hours=1),
                end_time=now + timedelta(hours=47),
            )
        )
        SqlAlchemyTeamRepository(s).add(Team(_CID, "Red"))
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family="web", slug="sqli", title="SQLi")
        )
        SqlAlchemyChallengeVersionRepository(s).add(
            ChallengeVersion(
                definition_slug="sqli", version_no=1, state="draft",
                family_version="1.0", seed="s", spec_sha256="h1",
                spec={"t": 1}, spec_version="1.0",
            )
        )
    with db.session_scope() as s:
        SqlAlchemyChallengeVersionRepository(s).publish("sqli", 1, now)


def _seed_instance(db, *, assigned=_WORKER, state="starting", with_secrets=False) -> str:
    _ensure_parents(db)
    iid = str(uuid.uuid4())
    with db.session_scope() as s:
        repo = SqlAlchemyInstanceRepository(s)
        repo.add(
            Instance(
                instance_id=iid,
                competition_id=_CID,
                team_name="Red",
                definition_slug="sqli",
                version_no=1,
                state=state,
                desired_state="active",
                assigned_worker=assigned,
                image_ref="registry.example/sqli@sha256:abc",
                instance_seed=_SEED_SECRET,
                expires_at=_now() + timedelta(hours=1),
            ),
            _now(),
        )
        if with_secrets:
            repo.record_credential(
                InstanceCredential(
                    instance_id=iid, name="ssh", secret_ref=_CRED_SECRET,
                    scopes=("shell",),
                )
            )
    return iid


def _job_status(db, job_id: str) -> str:
    with db.session_scope() as s:
        return SqlAlchemyJobQueue(s).get(job_id).status


def _job_claimed_by(db, job_id: str) -> str | None:
    with db.session_scope() as s:
        return SqlAlchemyJobQueue(s).get(job_id).claimed_by


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerHttpHappyPathTests(unittest.TestCase):
    def test_auth_claim_start_heartbeat_complete(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            job_id = _enqueue_launch_job(db)

            auth = client.post("/api/v1/worker/auth", headers=_bearer(token))
            self.assertEqual(auth.status_code, 200, auth.text)
            body = auth.json()
            self.assertEqual(body["worker_name"], _WORKER)
            self.assertIn("jobs:claim", body["scopes"])
            # The credential secret is NEVER echoed.
            self.assertNotIn(token, auth.text)

            claim = client.post(
                "/api/v1/worker/jobs/claim",
                headers=_bearer(token),
                json={"lease_seconds": 60},
            )
            self.assertEqual(claim.status_code, 200, claim.text)
            lease = claim.json()
            self.assertEqual(lease["job_id"], job_id)
            self.assertEqual(lease["job_type"], "launch_instance")
            self.assertEqual(lease["claimed_by"], _WORKER)
            lease_token = lease["lease_token"]

            start = client.post(
                f"/api/v1/worker/jobs/{job_id}/start",
                headers=_bearer(token),
                json={"lease_token": lease_token},
            )
            self.assertEqual(start.status_code, 204, start.text)

            hb = client.post(
                f"/api/v1/worker/jobs/{job_id}/heartbeat",
                headers=_bearer(token),
                json={"lease_token": lease_token, "lease_seconds": 60},
            )
            self.assertEqual(hb.status_code, 200, hb.text)
            self.assertFalse(hb.json()["cancel_requested"])

            done = client.post(
                f"/api/v1/worker/jobs/{job_id}/complete",
                headers=_bearer(token),
                json={"lease_token": lease_token, "result": {"ok": True}},
            )
            self.assertEqual(done.status_code, 204, done.text)
            self.assertEqual(_job_status(db, job_id), "succeeded")

    def test_report_health_endpoint_transition_on_owned_instance(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            iid = _seed_instance(db, assigned=_WORKER, state="starting")

            health = client.post(
                f"/api/v1/worker/instances/{iid}/health",
                headers=_bearer(token),
                json={
                    "observed_state": "starting", "healthy": False,
                    "generation": 1, "observed_at": _now().isoformat(),
                },
            )
            self.assertEqual(health.status_code, 204, health.text)

            ep = client.post(
                f"/api/v1/worker/instances/{iid}/endpoint",
                headers=_bearer(token),
                json={
                    "name": "web", "host": "10.0.0.2", "port": 8080,
                    "protocol": "tcp", "url": "tcp://10.0.0.2:8080", "internal": True,
                },
            )
            self.assertEqual(ep.status_code, 204, ep.text)

            res = client.post(
                f"/api/v1/worker/instances/{iid}/resource",
                headers=_bearer(token),
                json={"kind": "container", "external_ref": "c-abc", "generation": 1},
            )
            self.assertEqual(res.status_code, 204, res.text)

            trans = client.post(
                f"/api/v1/worker/instances/{iid}/transition",
                headers=_bearer(token),
                json={"to_state": "healthy", "reason": "health check passed"},
            )
            self.assertEqual(trans.status_code, 204, trans.text)
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemyInstanceRepository(s).get(iid).state, "healthy"
                )

    def test_get_owned_instance_view(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            iid = _seed_instance(db, assigned=_WORKER)
            r = client.get(
                f"/api/v1/worker/instances/{iid}", headers=_bearer(token)
            )
            self.assertEqual(r.status_code, 200, r.text)
            body = r.json()
            self.assertEqual(body["instance_id"], iid)
            self.assertEqual(body["assigned_worker"], _WORKER)
            self.assertEqual(body["image_ref"], "registry.example/sqli@sha256:abc")
            # The seed (a flag-influencing input) is never in the worker view.
            self.assertNotIn("instance_seed", body)
            self.assertNotIn(_SEED_SECRET, r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerHttpIdentityIsFromCredentialTests(unittest.TestCase):
    def test_spoofed_worker_name_in_body_is_ignored(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db, name=_WORKER)
            # A second identity exists so "attribute to the credential" is a real
            # claim, not a vacuous one.
            _enroll_worker(db, name=_OTHER_WORKER)
            job_id = _enqueue_launch_job(db)

            claim = client.post(
                "/api/v1/worker/jobs/claim",
                headers=_bearer(token),
                json={
                    "lease_seconds": 60,
                    "worker_name": _OTHER_WORKER,  # spoof attempt
                    "worker_id": _OTHER_WORKER,     # spoof attempt
                },
            )
            self.assertEqual(claim.status_code, 200, claim.text)
            # Attributed to the CREDENTIAL's worker, never the supplied one.
            self.assertEqual(claim.json()["claimed_by"], _WORKER)
            self.assertEqual(_job_claimed_by(db, job_id), _WORKER)

    def test_spoofed_worker_in_health_report_is_ignored(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db, name=_WORKER)
            _enroll_worker(db, name=_OTHER_WORKER)
            iid = _seed_instance(db, assigned=_WORKER, state="starting")
            # Supplying worker=w2 in the body must not stamp the report as w2 (and
            # must not trip the ownership guard, since it is ignored, not read).
            r = client.post(
                f"/api/v1/worker/instances/{iid}/health",
                headers=_bearer(token),
                json={
                    "observed_state": "healthy", "healthy": True, "generation": 1,
                    "observed_at": _now().isoformat(), "worker": _OTHER_WORKER,
                },
            )
            self.assertEqual(r.status_code, 204, r.text)
            with db.session_scope() as s:
                obs = SqlAlchemyInstanceRepository(s).latest_observation(iid)
            self.assertIsNotNone(obs)
            # Stamped with the CREDENTIAL's worker, never the supplied w2.
            self.assertEqual(obs.worker, _WORKER)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerHttpCredentialRejectionTests(unittest.TestCase):
    def test_missing_and_bad_credentials_are_401(self) -> None:
        with _client_and_db() as (client, db):
            _enqueue_launch_job(db)
            no_auth = client.post("/api/v1/worker/jobs/claim", json={})
            self.assertEqual(no_auth.status_code, 401, no_auth.text)
            bad = client.post(
                "/api/v1/worker/jobs/claim",
                headers=_bearer("ctfw1.not.real"),
                json={},
            )
            self.assertEqual(bad.status_code, 401, bad.text)
            self.assertEqual(bad.json()["error"]["code"], "unauthorized")

    def test_revoked_credential_is_401(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            WorkerEnrollmentService(db).revoke_worker(_WORKER, _now())
            r = client.post(
                "/api/v1/worker/jobs/claim", headers=_bearer(token), json={}
            )
            self.assertEqual(r.status_code, 401, r.text)

    def test_quarantined_credential_is_401(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).quarantine(_WORKER, _now(), "isolation")
            r = client.post(
                "/api/v1/worker/jobs/claim", headers=_bearer(token), json={}
            )
            self.assertEqual(r.status_code, 401, r.text)

    def test_draining_worker_cannot_claim_is_409(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            _enqueue_launch_job(db)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).drain(_WORKER, _now())
            r = client.post(
                "/api/v1/worker/jobs/claim", headers=_bearer(token), json={}
            )
            self.assertEqual(r.status_code, 409, r.text)
            self.assertEqual(r.json()["error"]["code"], "worker_draining")

    def test_stale_worker_cannot_claim_is_409(self) -> None:
        with _client_and_db() as (client, db):
            # Enrolled WITHOUT a fresh heartbeat -> liveness stale.
            token = _enroll_worker(db, fresh=False)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).heartbeat(
                    _WORKER, _now() - timedelta(hours=1)
                )
            _enqueue_launch_job(db)
            r = client.post(
                "/api/v1/worker/jobs/claim", headers=_bearer(token), json={}
            )
            self.assertEqual(r.status_code, 409, r.text)
            self.assertEqual(r.json()["error"]["code"], "worker_stale")

    def test_missing_scope_is_403(self) -> None:
        with _client_and_db() as (client, db):
            # A claim-only credential may not report instance facts.
            token = _enroll_worker(db, scopes=("jobs:claim",))
            iid = _seed_instance(db, assigned=_WORKER)
            r = client.post(
                f"/api/v1/worker/instances/{iid}/health",
                headers=_bearer(token),
                json={
                    "observed_state": "healthy", "healthy": True, "generation": 1,
                    "observed_at": _now().isoformat(),
                },
            )
            self.assertEqual(r.status_code, 403, r.text)
            self.assertEqual(r.json()["error"]["code"], "forbidden")


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerHttpLeaseAndOwnershipTests(unittest.TestCase):
    def test_wrong_lease_token_is_rejected(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            job_id = _enqueue_launch_job(db)
            claim = client.post(
                "/api/v1/worker/jobs/claim", headers=_bearer(token), json={}
            )
            self.assertEqual(claim.status_code, 200)
            # Complete with a lease token the worker never held -> 404 (stale fence).
            bad = client.post(
                f"/api/v1/worker/jobs/{job_id}/complete",
                headers=_bearer(token),
                json={"lease_token": str(uuid.uuid4()), "result": {}},
            )
            self.assertEqual(bad.status_code, 404, bad.text)
            # The job stays claimed (not completed) -- the fence held.
            self.assertNotEqual(_job_status(db, job_id), "succeeded")

    def test_complete_unknown_job_is_404(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            r = client.post(
                f"/api/v1/worker/jobs/{uuid.uuid4()}/complete",
                headers=_bearer(token),
                json={"lease_token": str(uuid.uuid4())},
            )
            self.assertEqual(r.status_code, 404, r.text)

    def test_report_on_unowned_instance_is_403(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db, name=_WORKER)
            _enroll_worker(db, name=_OTHER_WORKER)
            iid = _seed_instance(db, assigned=_OTHER_WORKER, state="starting")
            health = client.post(
                f"/api/v1/worker/instances/{iid}/health",
                headers=_bearer(token),
                json={
                    "observed_state": "healthy", "healthy": True, "generation": 1,
                    "observed_at": _now().isoformat(),
                },
            )
            self.assertEqual(health.status_code, 403, health.text)
            self.assertEqual(health.json()["error"]["code"], "forbidden_ownership")

            trans = client.post(
                f"/api/v1/worker/instances/{iid}/transition",
                headers=_bearer(token),
                json={"to_state": "healthy", "reason": "x"},
            )
            self.assertEqual(trans.status_code, 403, trans.text)

    def test_get_unowned_instance_is_403_and_no_leak(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db, name=_WORKER)
            _enroll_worker(db, name=_OTHER_WORKER)
            iid = _seed_instance(
                db, assigned=_OTHER_WORKER, with_secrets=True
            )
            r = client.get(
                f"/api/v1/worker/instances/{iid}", headers=_bearer(token)
            )
            self.assertEqual(r.status_code, 403, r.text)
            self.assertNotIn(_SEED_SECRET, r.text)
            self.assertNotIn(_CRED_SECRET, r.text)
            self.assertNotIn("registry.example", r.text)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerHttpAuthPlanesAreDisjointTests(unittest.TestCase):
    def test_human_token_cannot_call_worker_routes(self) -> None:
        with _client_and_db() as (client, db):
            _enqueue_launch_job(db)
            for token in (_ADMIN, _ORGANIZER, _PLAYER):
                for method, path, payload in (
                    ("post", "/api/v1/worker/auth", None),
                    ("post", "/api/v1/worker/jobs/claim", {}),
                ):
                    r = getattr(client, method)(
                        path, headers=_bearer(token), json=payload
                    )
                    self.assertEqual(
                        r.status_code, 401,
                        f"human {token} reached {path}: {r.status_code} {r.text}",
                    )

    def test_worker_token_cannot_call_human_routes(self) -> None:
        with _client_and_db() as (client, db):
            token = _enroll_worker(db)
            # A human resource route (list competitions) rejects the worker token.
            r = client.get("/api/v1/competitions", headers=_bearer(token))
            self.assertEqual(r.status_code, 401, r.text)
            # And a write route.
            r2 = client.post(
                "/api/v1/competitions",
                headers=_bearer(token),
                json={
                    "competition_id": _CID, "name": "x",
                    "start_time": "2026-06-01T09:00:00Z",
                    "end_time": "2026-06-03T09:00:00Z",
                },
            )
            self.assertEqual(r2.status_code, 401, r2.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
