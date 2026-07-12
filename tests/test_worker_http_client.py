"""Tests for :class:`HttpControlPlaneClient` against the worker gateway ([api]+[db]).

Drives the HTTP client through the real FastAPI app (via ``TestClient``'s ASGI
transport) over a real PostgreSQL, proving two things:

* ROUND-TRIP: the client (de)serializes the domain types (``JobLease`` / ``Instance``
  / ``HealthObservation`` / ``RuntimeResource`` / ``InstanceEndpoint``) to and from
  the wire so the worker run loop sees the SAME domain objects it would in-process.
* ERROR MAPPING: each HTTP error the gateway returns is mapped BACK to the SAME
  exception type the run loop expects, so ``run_once`` behaves identically to the
  Local path (401 -> WorkerAuthenticationError, 403 ownership ->
  InstanceOwnershipError, 403 scope -> ScopeError, 409 draining/stale ->
  WorkerDraining/StaleError, 404 -> None/LookupError).

Also a BEHAVIOR-EQUIVALENCE check for the core verbs: the same claim -> start ->
heartbeat -> complete sequence, driven once through the HTTP client and once
through :class:`LocalControlPlaneClient`, drives the job to the same terminal
state and attributes it to the credential's worker on both transports.

Skips cleanly without the ``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_worker_http_client
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

    from ctf_generator.application.execution.worker_instance_service import (
        InstanceOwnershipError,
        WorkerInstanceService,
    )
    from ctf_generator.application.execution.worker_job_service import (
        WorkerAuthenticationError,
        WorkerDrainingError,
        WorkerJobService,
        WorkerStaleError,
    )
    from ctf_generator.application.instances.service import InstanceLifecycleService
    from ctf_generator.application.jobs.service import JobService
    from ctf_generator.application.scheduling.service import SchedulingService
    from ctf_generator.application.worker_enrollment import (
        ScopeError,
        WorkerEnrollmentService,
    )
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.instances.models import (
        HealthObservation,
        Instance,
        InstanceEndpoint,
        RuntimeResource,
    )
    from ctf_generator.domain.work.models import Job, JobLease
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.instance_repository import (
        SqlAlchemyInstanceRepository,
    )
    from ctf_generator.infrastructure.database.job_queue_repository import (
        SqlAlchemyJobQueue,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
    )
    from ctf_generator.interfaces.api.app import create_app
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.workers.http_client import HttpControlPlaneClient
    from ctf_generator.workers.local_client import LocalControlPlaneClient

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

_WORKER = "w1"
_OTHER = "w2"
_CAPS = ("launch_instance",)
_CID = "cup"


def _now() -> datetime:
    return datetime.now(UTC)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_wc_{uuid.uuid4().hex[:12]}"
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
            yield db
        finally:
            db.dispose()


def _enroll(db, name=_WORKER, *, caps=_CAPS, fresh=True, scopes=None) -> str:
    enrollment = WorkerEnrollmentService(db)
    enrollment.register_worker(
        Worker(name, "docker-rootless", ("x86_64",), caps, 4, "1.0.0")
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


def _enqueue_launch(db) -> str:
    job = Job(
        job_id=str(uuid.uuid4()),
        job_type="launch_instance",
        idempotency_key=f"key-{uuid.uuid4().hex}",
        available_at=_now() - timedelta(seconds=5),
        required_capabilities=("launch_instance",),
        payload={"instance_id": "inst-x"},
    )
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).enqueue(job)
    return job.job_id


def _http_client(db, token: str) -> HttpControlPlaneClient:
    app = create_app(ApiSettings(), database=db)
    return HttpControlPlaneClient(token=token, client=TestClient(app))


def _seed_instance(db, *, assigned, state="starting") -> str:
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.competition_repository import (
        SqlAlchemyCompetitionRepository,
    )
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )

    now = _now()
    with db.session_scope() as s:
        first_time = SqlAlchemyCompetitionRepository(s).get(_CID) is None
        if first_time:
            SqlAlchemyCompetitionRepository(s).add(
                CompetitionConfig(
                    competition_id=_CID, name="Cup",
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
    if first_time:
        with db.session_scope() as s:
            SqlAlchemyChallengeVersionRepository(s).publish("sqli", 1, now)
    iid = str(uuid.uuid4())
    with db.session_scope() as s:
        SqlAlchemyInstanceRepository(s).add(
            Instance(
                instance_id=iid, competition_id=_CID, team_name="Red",
                definition_slug="sqli", version_no=1, state=state,
                desired_state="active", assigned_worker=assigned,
                image_ref="registry.example/sqli@sha256:abc",
                expires_at=now + timedelta(hours=1),
            ),
            now,
        )
    return iid


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class HttpClientRoundTripTests(unittest.TestCase):
    def test_authenticate_returns_live_token(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            client = _http_client(db, token)
            self.assertEqual(client.authenticate(_now()), token)

    def test_claim_returns_a_joblease_domain_object(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            job_id = _enqueue_launch(db)
            client = _http_client(db, token)
            lease = client.claim(token, 60, _now())
            self.assertIsInstance(lease, JobLease)
            self.assertIsInstance(lease.job, Job)
            self.assertEqual(lease.job.job_id, job_id)
            self.assertEqual(lease.job.job_type, "launch_instance")
            self.assertEqual(lease.job.payload["instance_id"], "inst-x")
            self.assertEqual(lease.job.claimed_by, _WORKER)
            self.assertTrue(lease.lease_token)

    def test_claim_none_when_no_job(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            client = _http_client(db, token)
            self.assertIsNone(client.claim(token, 60, _now()))

    def test_full_lease_lifecycle_over_http(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            job_id = _enqueue_launch(db)
            client = _http_client(db, token)
            lease = client.claim(token, 60, _now())
            client.start(token, job_id, lease.lease_token, _now())
            self.assertFalse(
                client.heartbeat(token, job_id, lease.lease_token, 60, _now())
            )
            client.complete(token, job_id, lease.lease_token, {"ok": True}, _now())
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyJobQueue(s).get(job_id).status, "succeeded")

    def test_get_instance_round_trips(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            iid = _seed_instance(db, assigned=_WORKER)
            client = _http_client(db, token)
            instance = client.get_instance(iid)
            self.assertIsInstance(instance, Instance)
            self.assertEqual(instance.instance_id, iid)
            self.assertEqual(instance.assigned_worker, _WORKER)
            self.assertEqual(instance.image_ref, "registry.example/sqli@sha256:abc")

    def test_get_missing_instance_is_none(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            client = _http_client(db, token)
            self.assertIsNone(client.get_instance(str(uuid.uuid4())))

    def test_report_health_endpoint_resource_transition(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            iid = _seed_instance(db, assigned=_WORKER, state="starting")
            client = _http_client(db, token)
            now = _now()
            client.report_health(
                HealthObservation(
                    instance_id=iid, observed_state="starting", healthy=False,
                    worker=_WORKER, generation=1, observed_at=now,
                ),
                now,
            )
            client.report_runtime_resource(
                RuntimeResource(iid, "container", "c-1", _WORKER, generation=1), now
            )
            client.report_endpoint(
                InstanceEndpoint(iid, "web", "10.0.0.2", 8080, "tcp",
                                 "tcp://10.0.0.2:8080", internal=True),
                now,
            )
            client.transition_instance(iid, "healthy", reason="up", now=now)
            with db.session_scope() as s:
                repo = SqlAlchemyInstanceRepository(s)
                self.assertEqual(repo.get(iid).state, "healthy")
                self.assertEqual(repo.latest_observation(iid).worker, _WORKER)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class HttpClientErrorMappingTests(unittest.TestCase):
    def test_bad_credential_maps_to_auth_error(self) -> None:
        with _migrated_database() as db:
            client = HttpControlPlaneClient(
                token="ctfw1.not.real",  # noqa: S106 - a deliberately invalid token
                client=TestClient(create_app(ApiSettings(), database=db)),
            )
            with self.assertRaises(WorkerAuthenticationError):
                client.authenticate(_now())
            with self.assertRaises(WorkerAuthenticationError):
                client.claim("ctfw1.not.real", 60, _now())

    def test_draining_maps_to_draining_error(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            _enqueue_launch(db)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).drain(_WORKER, _now())
            client = _http_client(db, token)
            with self.assertRaises(WorkerDrainingError):
                client.claim(token, 60, _now())

    def test_stale_maps_to_stale_error(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db, fresh=False)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).heartbeat(_WORKER, _now() - timedelta(hours=1))
            _enqueue_launch(db)
            client = _http_client(db, token)
            with self.assertRaises(WorkerStaleError):
                client.claim(token, 60, _now())

    def test_scope_maps_to_scope_error(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db, scopes=("jobs:claim",))
            iid = _seed_instance(db, assigned=_WORKER)
            client = _http_client(db, token)
            now = _now()
            with self.assertRaises(ScopeError):
                client.report_health(
                    HealthObservation(
                        instance_id=iid, observed_state="healthy", healthy=True,
                        worker=_WORKER, generation=1, observed_at=now,
                    ),
                    now,
                )

    def test_ownership_maps_to_ownership_error(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db, name=_WORKER)
            _enroll(db, name=_OTHER)
            iid = _seed_instance(db, assigned=_OTHER, state="starting")
            client = _http_client(db, token)
            now = _now()
            with self.assertRaises(InstanceOwnershipError):
                client.report_health(
                    HealthObservation(
                        instance_id=iid, observed_state="healthy", healthy=True,
                        worker=_WORKER, generation=1, observed_at=now,
                    ),
                    now,
                )

    def test_wrong_lease_token_maps_to_lookup_error(self) -> None:
        with _migrated_database() as db:
            token = _enroll(db)
            job_id = _enqueue_launch(db)
            client = _http_client(db, token)
            client.claim(token, 60, _now())
            with self.assertRaises(LookupError):
                client.complete(token, job_id, str(uuid.uuid4()), None, _now())


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class HttpVsLocalBehaviorEquivalenceTests(unittest.TestCase):
    """The core queue verbs drive the same terminal state and the same
    credential-derived attribution on both transports."""

    def _run_lifecycle(self, client, token, job_id) -> str | None:
        """Drive claim -> start -> heartbeat -> complete; return the lease's
        credential-derived ``claimed_by`` (captured at claim, before completion
        nulls the fence)."""
        now = _now()
        live = client.authenticate(now)
        lease = client.claim(live, 60, now)
        claimed_by = lease.job.claimed_by
        client.start(live, job_id, lease.lease_token, now)
        client.heartbeat(live, job_id, lease.lease_token, 60, now)
        client.complete(live, job_id, lease.lease_token, {"ok": True}, now)
        return claimed_by

    def test_core_verbs_are_equivalent(self) -> None:
        # HTTP transport.
        with _migrated_database() as db:
            token = _enroll(db)
            job_id = _enqueue_launch(db)
            http = _http_client(db, token)
            http_claimed = self._run_lifecycle(http, token, job_id)
            with db.session_scope() as s:
                http_status = SqlAlchemyJobQueue(s).get(job_id).status

        # Local (in-process) transport, same sequence.
        with _migrated_database() as db:
            token = _enroll(db)
            job_id = _enqueue_launch(db)
            scheduling = SchedulingService(db)
            jobs = JobService(db)
            lifecycle = InstanceLifecycleService(db, scheduling=scheduling, jobs=jobs)
            enrollment = WorkerEnrollmentService(db)
            local = LocalControlPlaneClient(
                jobs=WorkerJobService(db, enrollment),
                instances=WorkerInstanceService(lifecycle, enrollment),
                lifecycle=lifecycle, scheduling=scheduling,
                token=token, architecture="x86_64",
            )
            local_claimed = self._run_lifecycle(local, token, job_id)
            with db.session_scope() as s:
                local_status = SqlAlchemyJobQueue(s).get(job_id).status

        self.assertEqual(http_status, local_status)
        self.assertEqual(http_status, "succeeded")
        self.assertEqual(http_claimed, local_claimed)
        self.assertEqual(http_claimed, _WORKER)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
