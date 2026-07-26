"""Joined end-to-end over the NETWORKED worker transport (PostgreSQL + Docker gated).

The in-process joined spine (``test_joined_e2e_integration``) proves the wiring;
this proves the same publish -> build -> launch -> submit -> score spine driven by
a worker that talks to the control plane ONLY over the HTTP worker gateway. The
gateway is the REAL production ``create_worker_app`` listener (worker routes only,
the disjoint trust plane), served by uvicorn on a real loopback TCP socket, and the
worker drives it through a real ``httpx.Client`` -- an actual network round trip,
not an in-process ASGI shortcut. Every job-queue verb, the FULL (flag-bearing)
bundle fetch, the digest/stack reads, and every fact report cross that real socket.

    (operator, in-process) BuildService.trigger_build
    -> worker.run_once() claims the build job OVER HTTP, fetches the FULL bundle
       OVER HTTP, builds it with a real DockerRuntimeBackend, reports completion
       OVER HTTP -> challenge_build_images registry
    (operator) request_instance resolves the freshly-built image_ref
    -> worker.run_once() claims the launch job OVER HTTP, launches a real container
       from the built image, reports facts OVER HTTP -> instance healthy
    (contestant, in-process) SubmissionProcessingService with the seed-derived flag
    -> exactly one solve -> ScoreProjector -> scoreboard

Operator/contestant actions (trigger_build, request_instance, submit) are control-
plane calls, not worker actions, so they stay in-process; only the WORKER's half
goes over HTTP -- which is exactly the distributed seam under test.

Uses the ``binary_heap_exploit`` family (the one offline-buildable family) and the
same seed-derived-flag injection as the in-process joined test (imported from it).
Real wall-clock time throughout (the gateway stamps its own ``now``), mirroring
``test_worker_http_client``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_joined_e2e_http_integration
"""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
import unittest
import uuid
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta

try:
    import httpx
    import sqlalchemy as sa
    import uvicorn
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    # Reuse the offline-buildable spec + base-image gate from the in-process joined
    # test (pure, docker-free spec rendering; both need the same extras).
    from test_joined_e2e_integration import (
        _ACKED,
        _BASE_IMAGES,
        _FAMILY,
        _SEED,
        _base_images_present,
        _buildable_spec,
    )

    from ctf_generator.application.authoring.build_service import BuildService
    from ctf_generator.application.instances.service import InstanceLifecycleService
    from ctf_generator.application.jobs.service import JobService
    from ctf_generator.application.scheduling.service import SchedulingService
    from ctf_generator.application.scoring.projector import ScoreProjector
    from ctf_generator.application.scoring.scoreboard_service import ScoreboardService
    from ctf_generator.application.submissions.service import (
        SubmissionProcessingService,
    )
    from ctf_generator.application.worker_enrollment import WorkerEnrollmentService
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengePublication,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.execution.models import CREDENTIAL_TOKEN_PREFIX
    from ctf_generator.domain.execution.models import Worker as WorkerIdentity
    from ctf_generator.domain.identity.models import Team
    from ctf_generator.domain.ledger.processing import SubmissionRequest
    from ctf_generator.domain.scheduling.models import (
        PLATFORM_SCOPE_KEY,
        ReservationItem,
        ResourceQuota,
        WorkerRequirements,
    )
    from ctf_generator.infrastructure.database.challenge_build_image_repository import (
        SqlAlchemyChallengeBuildImageRepository,
    )
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_publication_repository import (
        SqlAlchemyChallengePublicationRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.competition_repository import (
        SqlAlchemyCompetitionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
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
    from ctf_generator.interfaces.api.app import create_worker_app
    from ctf_generator.interfaces.api.settings import ApiSettings
    from ctf_generator.workers.http_client import HttpControlPlaneClient
    from ctf_generator.workers.worker import Worker, WorkerConfig

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _docker_available() -> bool:
    if _IMPORT_ERROR is not None:
        return False
    return DockerRuntimeBackend().is_available()


if _IMPORT_ERROR is not None:
    _SKIP_REASON = f"db extra not importable ({_IMPORT_ERROR})"
elif not _TEST_URL:
    _SKIP_REASON = "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
elif not _docker_available():
    _SKIP_REASON = "docker CLI/daemon not available"
elif not _base_images_present():
    _SKIP_REASON = (
        "base images not present for the offline build "
        f"(need {' + '.join(_BASE_IMAGES)}; the build is --pull=false)"
    )
else:
    _SKIP_REASON = ""
_ENABLED = _SKIP_REASON == ""

_CID = "cup"
_SLUG = "heap-http-1"


def _now() -> datetime:
    return datetime.now(UTC)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


@contextmanager
def _serve(app, port: int):
    """Run ``app`` under uvicorn on 127.0.0.1:``port`` in a background thread for the
    life of the block, so the worker's HTTP calls are REAL loopback TCP round trips
    (not an in-process ASGI shortcut). ``lifespan="off"`` -- the app needs no
    startup/shutdown hooks; its DB collaborator is injected."""
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="gateway-uvicorn", daemon=True)
    thread.start()
    deadline = time.monotonic() + 30.0
    while not server.started:
        if time.monotonic() > deadline:  # pragma: no cover - startup wedged
            server.should_exit = True
            thread.join(timeout=5)
            raise RuntimeError("worker gateway did not start within 30s")
        time.sleep(0.02)
    try:
        yield
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_jh_{uuid.uuid4().hex[:12]}"
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
class NetworkedJoinedE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self._instance_ids: list[str] = []
        self._built_images: list[str] = []
        self._backend = DockerRuntimeBackend(
            require_rootless=False, acknowledged_gaps=_ACKED
        )

    def tearDown(self) -> None:
        for iid in self._instance_ids:
            try:
                self._backend.destroy(iid, None)
            except Exception:  # pragma: no cover
                pass
        for ref in self._built_images:
            subprocess.run(
                ["docker", "image", "rm", "--force", ref],
                capture_output=True, text=True,
            )

    def _seed(self, db, spec_dict: dict, spec_sha256: str, now: datetime) -> None:
        from ctf_generator import families

        fam_ver = families.get(_FAMILY).version
        with db.session_scope() as s:
            SqlAlchemyCompetitionRepository(s).add(
                CompetitionConfig(
                    competition_id=_CID, name="Cup",
                    start_time=now - timedelta(hours=1),
                    end_time=now + timedelta(hours=47),
                )
            )
            SqlAlchemyTeamRepository(s).add(Team(_CID, "Red"))
            SqlAlchemyChallengeDefinitionRepository(s).add(
                ChallengeDefinition(family=_FAMILY, slug=_SLUG, title="Heap Clobber")
            )
            SqlAlchemyChallengeVersionRepository(s).add(
                ChallengeVersion(
                    definition_slug=_SLUG, version_no=1, state="draft",
                    family_version=fam_ver, seed=_SEED,
                    spec_sha256=spec_sha256, spec=spec_dict, spec_version="1.0",
                )
            )
        with db.session_scope() as s:
            SqlAlchemyChallengeVersionRepository(s).publish(_SLUG, 1, now)
        with db.session_scope() as s:
            SqlAlchemyChallengePublicationRepository(s).add(
                ChallengePublication(
                    competition_id=_CID, definition_slug=_SLUG, version_no=1
                )
            )
        with db.session_scope() as s:
            reg = SqlAlchemyWorkerRegistry(s)
            reg.add(
                WorkerIdentity(
                    "w1", "docker-rootless", ("aarch64", "x86_64"),
                    ("build_challenge", "launch_instance", "stop_instance",
                     "delete_runtime_resources"),
                    4, "1",
                )
            )
            reg.heartbeat("w1", now)
        with db.session_scope() as s:
            SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
                ResourceQuota("platform", PLATFORM_SCOPE_KEY, "active_instances", 100)
            )

    def test_networked_build_launch_submit_score(self) -> None:
        now = _now()
        spec_dict, spec_sha256, flag = _buildable_spec()
        with _migrated_database() as db:
            self._seed(db, spec_dict, spec_sha256, now)
            # Control-plane (operator/contestant) services stay in-process.
            scheduling = SchedulingService(db)
            jobs = JobService(db)
            lifecycle = InstanceLifecycleService(db, scheduling=scheduling, jobs=jobs)
            enrollment = WorkerEnrollmentService(db)
            issued = enrollment.approve_worker("w1", now)  # default scopes incl artifacts:pull
            token = f"{CREDENTIAL_TOKEN_PREFIX}.{issued.credential_id}.{issued.secret}"

            # The worker's ONLY link to the control plane is the HTTP gateway --
            # the REAL disjoint worker-gateway listener (create_worker_app) served
            # over a loopback TCP socket, driven by a real httpx client. ExitStack
            # (via addCleanup) tears the server + client down even if an assertion
            # below fails.
            port = _free_port()
            stack = ExitStack()
            self.addCleanup(stack.close)
            stack.enter_context(
                _serve(create_worker_app(ApiSettings(), database=db), port)
            )
            client = stack.enter_context(
                httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30.0)
            )
            http = HttpControlPlaneClient(token=token, client=client)
            worker = Worker(
                WorkerConfig(worker_name="w1", lease_seconds=300),
                http, self._backend, command=("sleep", "3600"),
                build_backend=self._backend,
            )

            # -- 1. BUILD over HTTP ---------------------------------------------
            build_job, created = BuildService(db, jobs=jobs).trigger_build(
                _SLUG, 1, now
            )
            self.assertTrue(created)
            self.assertTrue(worker.run_once(), "worker did not claim the build job")
            with db.session_scope() as s:
                built_ref = SqlAlchemyChallengeBuildImageRepository(
                    s
                ).latest_image_ref_for_version(_SLUG, 1)
            self.assertIsNotNone(built_ref, "no built image recorded after build job")
            self._built_images.append(built_ref)
            self.assertEqual(
                subprocess.run(
                    ["docker", "image", "inspect", built_ref],
                    capture_output=True, text=True,
                ).returncode,
                0,
                "built image missing on host",
            )

            # -- 2. request the instance (operator; resolves the built image) ---
            iid = str(uuid.uuid4())
            self._instance_ids.append(iid)
            lifecycle.request_instance(
                instance_id=iid, competition_id=_CID, team_name="Red",
                definition_slug=_SLUG, version_no=1,
                requirements=WorkerRequirements(
                    architecture=self._backend.probe().architecture,
                    required_capabilities=frozenset({"launch_instance"}),
                ),
                pooled_items=(
                    ReservationItem("platform", PLATFORM_SCOPE_KEY, "active_instances", 1),
                ),
                expires_at=now + timedelta(hours=2), now=now,
            )
            self.assertEqual(lifecycle.get(iid).image_ref, built_ref)

            # -- 3. LAUNCH over HTTP --------------------------------------------
            self.assertTrue(worker.run_once(), "worker did not claim the launch job")
            self.assertEqual(lifecycle.get(iid).state, "healthy")
            running = subprocess.run(
                ["docker", "ps", "-q", "--filter", f"label=ctfgen.instance={iid}"],
                capture_output=True, text=True,
            ).stdout.split()
            self.assertEqual(len(running), 1, "expected exactly one running container")
            image_of = subprocess.run(
                ["docker", "inspect", "-f", "{{.Config.Image}}", running[0]],
                capture_output=True, text=True,
            ).stdout.strip()
            self.assertEqual(image_of, built_ref, "container not from the built image")

            # -- 4. contestant submits the correct (seed-derived) flag ----------
            outcome = SubmissionProcessingService(db).process_submission(
                SubmissionRequest(
                    submission_id=str(uuid.uuid4()),
                    competition_id=_CID, team_name="Red",
                    definition_slug=_SLUG, version_no=1,
                    submitted_at=now, candidate_flag=flag,
                )
            )
            self.assertTrue(outcome.accepted)
            self.assertTrue(outcome.first_solve)
            self.assertIsNotNone(outcome.solve)

            # -- 5. scoreboard reflects exactly one solve -----------------------
            ScoreProjector(db).run_until_drained()
            standings = ScoreboardService(db).standings(_CID)
            self.assertEqual(len(standings), 1)
            self.assertEqual(standings[0]["team_id"], "Red")
            self.assertEqual(standings[0]["solve_count"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
