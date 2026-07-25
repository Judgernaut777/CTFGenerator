"""Joined end-to-end integration test: publish -> build -> launch -> submit -> score.

The ONE unbroken spine the v1.0 release criteria calls out as UNVERIFIED while
``build_challenge`` was unbuilt: a published challenge version is BUILT into a
real Docker image by a worker (the ``build_challenge`` pipeline), that
freshly-built image is LAUNCHED as a real container for a contestant's instance,
and the contestant's correct flag SUBMISSION produces exactly one solve the
scoreboard reflects. No fakes: real PostgreSQL, real ``DockerRuntimeBackend``
build AND launch, the in-process ``LocalControlPlaneClient`` transport.

    publish  ->  BuildService.trigger_build  ->  worker.run_once() [BUILD]
             ->  challenge_build_images row (+ stack rows)
             ->  request_instance (resolves the freshly-built image_ref)
             ->  worker.run_once() [LAUNCH: a real container from the built image]
             ->  SubmissionProcessingService (the seed-derived flag)
             ->  exactly one solve  ->  ScoreProjector  ->  scoreboard

Family: ``binary_heap_exploit`` -- the one family whose rendered Dockerfile
builds OFFLINE (multi-stage ``gcc:12-bookworm`` -> ``debian:bookworm-slim``, a
local ``make``, no ``pip``/network), so the worker's default ``--network=none``
build succeeds. It renders a single-service ``docker-compose.yml``, so this also
exercises the compose-aware build + the N=1 stack launch end to end with a REAL
built image.

The flag is deterministic from the seed and baked into the image; the submission
verifier (``SpecFlagVerifier``) reads ``spec['flag']``, so the test renders once
to learn the seed-derived flag and injects it into the stored spec -- both notions
of "the flag" then agree, exactly as a real authoring flow's spec would carry it.

The launch overrides the entrypoint with a benign ``sleep`` (like
``test_worker_loop_integration``): what is under test is that the freshly-BUILT
image launches on a worker as the instance, not the challenge binary's own
runtime behaviour.

Gated on BOTH a test PostgreSQL (CTFGEN_TEST_DATABASE_URL) + docker, AND the two
base images being present locally (the build is ``--pull=false``); skips cleanly
otherwise. Every container/network/built image is cleaned up in tearDown.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_joined_e2e_integration
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator import families, generator
    from ctf_generator.application.authoring.build_service import BuildService
    from ctf_generator.application.catalog.challenge_service import spec_content_hash
    from ctf_generator.application.execution.worker_build_service import (
        WorkerBuildService,
    )
    from ctf_generator.application.execution.worker_instance_service import (
        WorkerInstanceService,
    )
    from ctf_generator.application.execution.worker_job_service import WorkerJobService
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
    from ctf_generator.spec_generator import default_spec, spec_to_dict
    from ctf_generator.workers.local_client import LocalControlPlaneClient
    from ctf_generator.workers.worker import Worker, WorkerConfig

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The offline build is --pull=false; both base images the binary family's
# multi-stage Dockerfile references must already be present locally.
_BASE_IMAGES = ("gcc:12-bookworm", "debian:bookworm-slim")
_ACKED = frozenset({"rootless", "user_namespace", "apparmor"})


def _docker_available() -> bool:
    if _IMPORT_ERROR is not None:
        return False
    return DockerRuntimeBackend().is_available()


def _base_images_present() -> bool:
    if _IMPORT_ERROR is not None:
        return False
    have = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
        capture_output=True, text=True,
    ).stdout.split()
    return all(img in have for img in _BASE_IMAGES)


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

_NOW = datetime(2026, 7, 25, 12, 0, tzinfo=UTC)
_LATER = _NOW + timedelta(hours=2)
_CID = "cup"
_SLUG = "heap-1"
_FAMILY = "binary_heap_exploit"
_SEED = "binseed-1"


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_je_{uuid.uuid4().hex[:12]}"
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


def _buildable_spec() -> tuple[dict, str, str]:
    """A REAL offline-buildable spec for the binary family, plus its content hash
    and the seed-derived flag baked into the rendered bundle. The flag is injected
    into the spec dict so ``SpecFlagVerifier`` (which reads ``spec['flag']``) agrees
    with the value the built image serves."""
    spec = default_spec(
        seed=_SEED, title="Heap Clobber", difficulty="easy", family=_FAMILY
    )
    spec_dict = spec_to_dict(spec)
    # Render once (pure text generation -- no docker) to learn the flag the built
    # image bakes in; the render is deterministic in the seed, preserved through
    # spec_to_dict/spec_from_dict, so this equals what the worker builds.
    with tempfile.TemporaryDirectory(prefix="ctfgen-joined-") as tmp:
        root = Path(tmp) / "b"
        generator.create_challenge(
            output_dir=root, seed=spec.seed, title=spec.title,
            difficulty=spec.difficulty, family=spec.family, force=True, spec=spec,
        )
        variant = json.loads((root / "private" / "variant.json").read_text())
    flag = variant["flag"]
    spec_dict["flag"] = flag  # read by SpecFlagVerifier; ignored by render
    return spec_dict, spec_content_hash(spec_dict), flag


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class JoinedEndToEndTests(unittest.TestCase):
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

    def _seed(self, db, spec_dict: dict, spec_sha256: str) -> None:
        fam_ver = families.get(_FAMILY).version
        with db.session_scope() as s:
            SqlAlchemyCompetitionRepository(s).add(
                CompetitionConfig(
                    competition_id=_CID, name="Cup",
                    start_time=_NOW - timedelta(hours=1),
                    end_time=_NOW + timedelta(hours=47),
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
            SqlAlchemyChallengeVersionRepository(s).publish(_SLUG, 1, _NOW)
        with db.session_scope() as s:
            # Attach the published version to the competition so the submission
            # path resolves the publication.
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
        worker_instances = WorkerInstanceService(lifecycle, enrollment)
        worker_builds = WorkerBuildService(db, enrollment)
        issued = enrollment.approve_worker("w1", _NOW)  # default scopes incl artifacts:pull
        token = f"{CREDENTIAL_TOKEN_PREFIX}.{issued.credential_id}.{issued.secret}"
        arch = self._backend.probe().architecture
        client = LocalControlPlaneClient(
            jobs=worker_jobs, instances=worker_instances, lifecycle=lifecycle,
            scheduling=scheduling, builds=worker_builds, token=token, architecture=arch,
        )
        # A benign command keeps the launched container deterministically alive:
        # under test is that the BUILT image launches on a worker, not the binary's
        # own runtime behaviour.
        worker = Worker(
            WorkerConfig(worker_name="w1", lease_seconds=300),
            client, self._backend, command=("sleep", "3600"),
            build_backend=self._backend, clock=lambda: _NOW,
        )
        return scheduling, jobs, lifecycle, worker

    def test_publish_build_launch_submit_score(self) -> None:
        spec_dict, spec_sha256, flag = _buildable_spec()
        self.assertTrue(flag.startswith("ctf{"), flag)  # rendered flag, lowercase
        with _migrated_database() as db:
            self._seed(db, spec_dict, spec_sha256)
            scheduling, jobs, lifecycle, worker = self._wire(db)

            # -- 1. trigger the build, then run ONE worker iteration to BUILD -----
            build_job, created = BuildService(db, jobs=jobs).trigger_build(
                _SLUG, 1, _NOW
            )
            self.assertTrue(created)
            self.assertEqual(build_job.job_type, "build_challenge")
            self.assertTrue(worker.run_once(), "worker did not claim the build job")

            # The freshly-built image is recorded in the registry and REALLY exists.
            with db.session_scope() as s:
                built_ref = SqlAlchemyChallengeBuildImageRepository(
                    s
                ).latest_image_ref_for_version(_SLUG, 1)
            self.assertIsNotNone(built_ref, "no built image recorded after build job")
            self.assertTrue(built_ref.startswith("ctfgen-build/"))
            self._built_images.append(built_ref)
            inspect = subprocess.run(
                ["docker", "image", "inspect", built_ref],
                capture_output=True, text=True,
            )
            self.assertEqual(inspect.returncode, 0, "built image missing on host")

            # -- 2. request the instance (NO image_ref -> resolves the built one) -
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
                expires_at=_LATER, now=_NOW,
            )
            # The instance carries the freshly-built image, resolved from the registry.
            self.assertEqual(lifecycle.get(iid).image_ref, built_ref)

            # -- 3. run ONE worker iteration to LAUNCH the built image ------------
            self.assertTrue(worker.run_once(), "worker did not claim the launch job")
            instance = lifecycle.get(iid)
            self.assertEqual(instance.state, "healthy")
            # A real container from the BUILT image is running under the instance label.
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
            with db.session_scope() as s:
                kinds = sorted(
                    r.kind
                    for r in SqlAlchemyInstanceRepository(s).list_runtime_resources(iid)
                )
            self.assertIn("container", kinds)
            self.assertIn("network", kinds)

            # -- 4. the contestant submits the CORRECT (seed-derived) flag -------
            outcome = SubmissionProcessingService(db).process_submission(
                SubmissionRequest(
                    submission_id=str(uuid.uuid4()),
                    competition_id=_CID, team_name="Red",
                    definition_slug=_SLUG, version_no=1,
                    submitted_at=_NOW, candidate_flag=flag,
                )
            )
            self.assertTrue(outcome.accepted)
            self.assertTrue(outcome.first_solve)
            self.assertIsNotNone(outcome.solve)

            # A WRONG flag on the same challenge is not a solve (spine still sound).
            wrong = SubmissionProcessingService(db).process_submission(
                SubmissionRequest(
                    submission_id=str(uuid.uuid4()),
                    competition_id=_CID, team_name="Red",
                    definition_slug=_SLUG, version_no=1,
                    submitted_at=_NOW, candidate_flag="ctf{not-the-flag}",
                )
            )
            self.assertFalse(wrong.accepted)
            self.assertIsNone(wrong.solve)

            # -- 5. the scoreboard reflects exactly one solve --------------------
            ScoreProjector(db).run_until_drained()
            standings = ScoreboardService(db).standings(_CID)
            self.assertEqual(len(standings), 1)
            self.assertEqual(standings[0]["team_id"], "Red")
            self.assertEqual(standings[0]["solve_count"], 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
