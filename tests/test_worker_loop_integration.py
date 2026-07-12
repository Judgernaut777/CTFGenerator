"""End-to-end worker-loop integration test (docker + PostgreSQL gated).

Skips cleanly unless BOTH the db extra + a test PostgreSQL (CTFGEN_TEST_DATABASE_URL)
AND the ``docker`` CLI are available -- exactly like the other PG integration
suites. Exercises the full slice-2 path with real infrastructure:

    enqueue launch_instance (via request_instance) -> one worker loop iteration
    with LocalControlPlaneClient over a real DB session -> the DockerRuntimeBackend
    launches a real BENIGN container -> the worker reports healthy + a
    RuntimeResource -> the instance reaches a running (healthy) state; then a
    stop_instance job -> container removed + reservation released.

Every container/network created is force-cleaned in tearDown.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_worker_loop_integration
"""

from __future__ import annotations

import os
import subprocess
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator.application.execution.worker_job_service import WorkerJobService
    from ctf_generator.application.instances.service import InstanceLifecycleService
    from ctf_generator.application.jobs.service import JobService
    from ctf_generator.application.scheduling.service import SchedulingService
    from ctf_generator.application.worker_enrollment import WorkerEnrollmentService
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.execution.models import (
        CREDENTIAL_TOKEN_PREFIX,
    )
    from ctf_generator.domain.execution.models import Worker as WorkerIdentity
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.scheduling.models import (
        PLATFORM_SCOPE_KEY,
        ReservationItem,
        ResourceQuota,
        WorkerRequirements,
    )
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
    from ctf_generator.infrastructure.database.quota_repository import (
        SqlAlchemyQuotaPolicyRepository,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.team_repository import (
        SqlAlchemyTeamRepository,
    )
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
    )
    from ctf_generator.infrastructure.runtime.docker_backend import DockerRuntimeBackend
    from ctf_generator.workers.local_client import LocalControlPlaneClient
    from ctf_generator.workers.worker import Worker, WorkerConfig

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DOCKER = _IMPORT_ERROR is None and DockerRuntimeBackend().is_available()
_ACKED = frozenset({"rootless", "user_namespace", "apparmor"})

if _IMPORT_ERROR is not None:
    _SKIP_REASON = f"db extra not importable ({_IMPORT_ERROR})"
elif not _TEST_URL:
    _SKIP_REASON = "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
elif not _DOCKER:
    _SKIP_REASON = "docker CLI/daemon not available"
else:
    _SKIP_REASON = ""
_ENABLED = _SKIP_REASON == ""

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(hours=2)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_wl_{uuid.uuid4().hex[:12]}"
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


@contextmanager
def _migrated_database():
    with _isolated_database() as url:
        cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
        cfg.set_main_option("sqlalchemy.url", str(url))
        command.upgrade(cfg, "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield db
        finally:
            db.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerLoopIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._instance_ids: list[str] = []
        self._backend = DockerRuntimeBackend(
            require_rootless=False, acknowledged_gaps=_ACKED
        )

    def tearDown(self) -> None:
        for iid in self._instance_ids:
            try:
                self._backend.destroy(iid, None)
            except Exception:  # pragma: no cover
                pass

    def _seed(self, db) -> None:
        with db.session_scope() as s:
            SqlAlchemyCompetitionRepository(s).add(
                CompetitionConfig(
                    competition_id="cup", name="Cup",
                    start_time=_NOW - timedelta(hours=1),
                    end_time=_NOW + timedelta(hours=47),
                )
            )
            SqlAlchemyTeamRepository(s).add(Team("cup", "Red"))
            SqlAlchemyChallengeDefinitionRepository(s).add(
                ChallengeDefinition(family="web", slug="sql", title="SQL")
            )
            SqlAlchemyChallengeVersionRepository(s).add(
                ChallengeVersion(
                    definition_slug="sql", version_no=1, state="draft",
                    family_version="1.0", seed="s", spec_sha256="h1",
                    spec={"t": 1}, spec_version="1.0",
                )
            )
        with db.session_scope() as s:
            SqlAlchemyChallengeVersionRepository(s).publish("sql", 1, _NOW)
        with db.session_scope() as s:
            reg = SqlAlchemyWorkerRegistry(s)
            reg.add(
                WorkerIdentity(
                    "w1", "docker-rootless", ("aarch64", "x86_64"),
                    ("launch_instance", "stop_instance", "delete_runtime_resources"),
                    4, "1",
                )
            )
            reg.heartbeat("w1", _NOW)
        with db.session_scope() as s:
            SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
                ResourceQuota("platform", PLATFORM_SCOPE_KEY, "active_instances", 100)
            )

    def _wire(self, db):
        scheduling = SchedulingService(db)
        jobs = JobService(db)
        lifecycle = InstanceLifecycleService(db, scheduling=scheduling, jobs=jobs)
        enrollment = WorkerEnrollmentService(db)
        worker_jobs = WorkerJobService(db, enrollment)
        issued = enrollment.approve_worker("w1", _NOW)  # trusted already; reissues cred
        token = f"{CREDENTIAL_TOKEN_PREFIX}.{issued.credential_id}.{issued.secret}"
        client = LocalControlPlaneClient(
            jobs=worker_jobs, lifecycle=lifecycle, scheduling=scheduling, token=token
        )
        worker = Worker(
            WorkerConfig(worker_name="w1", lease_seconds=120),
            client, self._backend, command=("sleep", "3600"), clock=lambda: _NOW,
        )
        return scheduling, jobs, lifecycle, worker

    def test_launch_then_stop_end_to_end(self) -> None:
        with _migrated_database() as db:
            self._seed(db)
            scheduling, _jobs, lifecycle, worker = self._wire(db)
            iid = str(uuid.uuid4())
            self._instance_ids.append(iid)
            lifecycle.request_instance(
                instance_id=iid, competition_id="cup", team_name="Red",
                definition_slug="sql", version_no=1,
                requirements=WorkerRequirements(
                    architecture="aarch64",
                    required_capabilities=frozenset({"launch_instance"}),
                ),
                pooled_items=(
                    ReservationItem("platform", PLATFORM_SCOPE_KEY, "active_instances", 1),
                ),
                expires_at=_LATER, now=_NOW, image_ref="alpine:latest",
            )
            # One loop iteration claims + runs the launch job.
            self.assertTrue(worker.run_once())
            instance = lifecycle.get(iid)
            self.assertEqual(instance.state, "healthy")
            # A real container exists and a RuntimeResource was recorded.
            cid = subprocess.run(
                ["docker", "ps", "-q", "--filter", f"label=ctfgen.instance={iid}"],
                capture_output=True, text=True,
            ).stdout.strip()
            self.assertTrue(cid, "no running container after launch")
            with db.session_scope() as s:
                resources = SqlAlchemyInstanceRepository(s).list_runtime_resources(iid)
            kinds = sorted(r.kind for r in resources)
            self.assertIn("container", kinds)
            self.assertIn("network", kinds)

            # Now request a stop; one loop iteration removes it + releases hold.
            lifecycle.request_stop(iid, _NOW)
            self.assertTrue(worker.run_once())
            self.assertEqual(lifecycle.get(iid).state, "stopped")
            gone = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"label=ctfgen.instance={iid}"],
                capture_output=True, text=True,
            ).stdout.strip()
            self.assertEqual(gone, "", "container not removed after stop")
            self.assertEqual(scheduling.get_reservation(iid).state, "released")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
