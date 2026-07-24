"""PostgreSQL integration test: build-job completion records the built image
(build_challenge slice 2).

Proves the complete-time side effects wired into ``WorkerJobService.complete``:
when a ``build_challenge`` job completes with a build result, the control plane
records (a) a ``worker_image_cache`` row keyed to the AUTHENTICATED worker (the
scheduler-affinity writer that previously had no producer) and (b) a
``challenge_build_images`` row keyed to the version (the launch-time image
lookup source). A non-build completion writes NEITHER row -- the verb stays
job-type-agnostic, gated only by the presence of a built ``image_ref``.

Docker-gated like the other repository suites; skips cleanly without the db
extra / ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest \\
      test_worker_build_completion_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator.application.execution.worker_job_service import (
        WorkerJobService,
    )
    from ctf_generator.application.worker_enrollment import WorkerEnrollmentService
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.work.models import Job
    from ctf_generator.infrastructure.database.challenge_build_image_repository import (
        SqlAlchemyChallengeBuildImageRepository,
    )
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.job_queue_repository import (
        SqlAlchemyJobQueue,
    )
    from ctf_generator.infrastructure.database.models import (
        ChallengeBuildImage as ChallengeBuildImageRow,
    )
    from ctf_generator.infrastructure.database.models import (
        Worker as WorkerRow,
    )
    from ctf_generator.infrastructure.database.models import (
        WorkerImageCache as WorkerImageCacheRow,
    )
    from ctf_generator.infrastructure.database.session import Database

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

_NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
_SLUG = "invoice-drift"
_BUILD_CAPS = ("build_challenge",)
_IMG = "ctfgen-build/invoice-drift:v1-abcdef0123456789"
_DIGEST = "sha256:" + "d" * 64
_BUNDLE = "e" * 64


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
            yield db
        finally:
            db.dispose()


def _enroll(db, enrollment, name, *, caps=_BUILD_CAPS) -> str:
    enrollment.register_worker(
        Worker(name, "docker-rootless", ("x86_64",), caps, 2, "1.0.0")
    )
    return enrollment.approve_worker(name, _NOW).token()


def _seed_version(db) -> None:
    with db.session_scope() as s:
        SqlAlchemyChallengeDefinitionRepository(s).add(
            ChallengeDefinition(family="web", slug=_SLUG, title="Invoice Drift")
        )
        SqlAlchemyChallengeVersionRepository(s).add(
            ChallengeVersion(
                definition_slug=_SLUG,
                version_no=1,
                state="draft",
                family_version="1.0",
                seed="seed-abc",
                spec_sha256="spec-hash-1",
                spec={"title": "Invoice Drift"},
                spec_version="1.0",
                mode="red",
                published_at=None,
            )
        )


def _enqueue_build_job(db) -> str:
    job = Job(
        job_id=str(uuid.uuid4()),
        job_type="build_challenge",
        idempotency_key=f"build:{_SLUG}:v1:{uuid.uuid4().hex}",
        available_at=_NOW,
        required_capabilities=("build_challenge",),
        payload={"definition_slug": _SLUG, "version_no": 1, "spec_sha256": "x"},
        # The AUTHORITATIVE build target (recorded at enqueue by BuildService):
        # the completion side effects key on THESE, never the worker's payload.
        definition_slug=_SLUG,
        version_no=1,
    )
    with db.session_scope() as s:
        SqlAlchemyJobQueue(s).enqueue(job)
    return job.job_id


def _run_to_completion(svc, token, result_json) -> None:
    """Claim -> start -> complete the single queued build job with a result."""
    svc.ping(token, _NOW)  # establish liveness (claim requires a fresh heartbeat)
    lease = svc.claim(token, 60, _NOW)
    assert lease is not None
    job_id = lease.job.job_id
    svc.start(token, job_id, lease.lease_token, _NOW)
    svc.complete(token, job_id, lease.lease_token, result_json, None, None, _NOW)


_BUILD_RESULT = {
    "definition_slug": _SLUG,
    "version_no": 1,
    "bundle_sha256": _BUNDLE,
    "image_ref": _IMG,
    "digest": _DIGEST,
}


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class BuildCompletionSideEffectTests(unittest.TestCase):
    def test_build_completion_writes_both_registries(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wbuild")
            svc = WorkerJobService(db, enrollment)
            _enqueue_build_job(db)
            _run_to_completion(svc, token, _BUILD_RESULT)

            with db.session_scope() as s:
                cache_rows = list(s.scalars(sa.select(WorkerImageCacheRow)))
                registry_rows = list(s.scalars(sa.select(ChallengeBuildImageRow)))
                worker_id = s.scalar(
                    sa.select(WorkerRow.id).where(WorkerRow.name == "wbuild")
                )

        # Affinity cache: exactly one row, keyed to the AUTHENTICATED worker.
        self.assertEqual(len(cache_rows), 1)
        self.assertEqual(cache_rows[0].worker_id, worker_id)
        self.assertEqual(cache_rows[0].image_ref, _IMG)
        # Version->image registry: exactly one row carrying the built image.
        self.assertEqual(len(registry_rows), 1)
        self.assertEqual(registry_rows[0].image_ref, _IMG)
        self.assertEqual(registry_rows[0].image_digest, _DIGEST)
        self.assertEqual(registry_rows[0].bundle_sha256, _BUNDLE)

    def test_worker_image_cache_keyed_to_the_authenticated_worker_not_payload(
        self,
    ) -> None:
        # A second identity exists; the cache row must key to the token owner,
        # never to any worker-supplied field in the result payload.
        with _migrated_database() as db:
            _seed_version(db)
            enrollment = WorkerEnrollmentService(db)
            _enroll(db, enrollment, "other-worker")
            token = _enroll(db, enrollment, "wbuild")
            svc = WorkerJobService(db, enrollment)
            _enqueue_build_job(db)
            # Even if the payload lies about identity, it is ignored.
            _run_to_completion(
                svc, token, {**_BUILD_RESULT, "worker_id": "other-worker"}
            )

            with db.session_scope() as s:
                cache = s.scalars(sa.select(WorkerImageCacheRow)).one()
                wbuild_id = s.scalar(
                    sa.select(WorkerRow.id).where(WorkerRow.name == "wbuild")
                )
        self.assertEqual(cache.worker_id, wbuild_id)

    def test_non_build_completion_writes_no_image_rows(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wbuild")
            svc = WorkerJobService(db, enrollment)
            _enqueue_build_job(db)
            # A completion result carrying no image_ref -> no side effects.
            _run_to_completion(svc, token, {"ok": True, "note": "no image here"})

            with db.session_scope() as s:
                cache = list(s.scalars(sa.select(WorkerImageCacheRow)))
                registry = list(s.scalars(sa.select(ChallengeBuildImageRow)))
        self.assertEqual(cache, [])
        self.assertEqual(registry, [])

    def test_registry_keyed_to_the_job_version_not_the_payload(self) -> None:
        # SECURITY: a worker that LIES in its result payload about which version
        # it built must not poison another challenge's version->image mapping.
        # The registry keys on the JOB's authoritative (slug, version), so the
        # image lands only under the job's target and the payload's claim is inert
        # (and does not even need to resolve -- no LookupError, no rollback).
        with _migrated_database() as db:
            _seed_version(db)
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wbuild")
            svc = WorkerJobService(db, enrollment)
            _enqueue_build_job(db)  # job targets (invoice-drift, 1)
            _run_to_completion(
                svc,
                token,
                {**_BUILD_RESULT, "definition_slug": "attacker-x", "version_no": 999},
            )
            with db.session_scope() as s:
                repo = SqlAlchemyChallengeBuildImageRepository(s)
                for_job = repo.latest_image_ref_for_version(_SLUG, 1)
                for_payload = repo.latest_image_ref_for_version("attacker-x", 999)
                rows = list(s.scalars(sa.select(ChallengeBuildImageRow)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(for_job, _IMG)  # keyed to the JOB's version
        self.assertIsNone(for_payload)  # NOT the payload's claimed version

    def test_malformed_build_payload_still_terminalizes_the_job(self) -> None:
        # AVAILABILITY: a malformed result payload must never veto its own job's
        # terminalization (that would re-lease the finished build forever). The
        # parser is lenient, and the registry keys on the job's own version.
        with _migrated_database() as db:
            _seed_version(db)
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wbuild")
            svc = WorkerJobService(db, enrollment)
            _enqueue_build_job(db)
            svc.ping(token, _NOW)
            lease = svc.claim(token, 60, _NOW)
            job_id = lease.job.job_id
            svc.start(token, job_id, lease.lease_token, _NOW)
            # image_ref valid, but version_no a string and no bundle/digest.
            svc.complete(
                token,
                job_id,
                lease.lease_token,
                {"image_ref": _IMG, "version_no": "not-an-int"},
                None,
                None,
                _NOW,
            )
            with db.session_scope() as s:
                status = SqlAlchemyJobQueue(s).get(job_id).status
                cache = list(s.scalars(sa.select(WorkerImageCacheRow)))
                registry = list(s.scalars(sa.select(ChallengeBuildImageRow)))
        self.assertEqual(status, "succeeded")  # terminalized despite the payload
        self.assertEqual(len(cache), 1)  # image_ref valid -> cache still written
        self.assertEqual(registry, [])  # no digest/bundle -> registry skipped

    def test_completion_without_digest_writes_cache_but_not_registry(self) -> None:
        with _migrated_database() as db:
            _seed_version(db)
            enrollment = WorkerEnrollmentService(db)
            token = _enroll(db, enrollment, "wbuild")
            svc = WorkerJobService(db, enrollment)
            _enqueue_build_job(db)
            no_digest = {k: v for k, v in _BUILD_RESULT.items() if k != "digest"}
            _run_to_completion(svc, token, no_digest)

            with db.session_scope() as s:
                cache = list(s.scalars(sa.select(WorkerImageCacheRow)))
                registry = list(s.scalars(sa.select(ChallengeBuildImageRow)))
        # Cache keys on image_ref alone -> written; registry keys on digest ->
        # skipped (a cache hit without a launchable registry mapping).
        self.assertEqual(len(cache), 1)
        self.assertEqual(registry, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
