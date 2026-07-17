"""Real-Docker integration test for the build_challenge worker pipeline
(docs/architecture/build-challenge-worker-pipeline.md).

Docker-gated (skips cleanly off-docker), following
``tests/test_build_isolation_integration.py``'s own convention exactly: probe
``DockerRuntimeBackend.is_available()`` and ``skipUnless``. Deliberately
NOT PostgreSQL-gated -- this drives the worker's REAL dispatch
(``Worker.run_once`` -> ``_do_build_challenge``) against a REAL
``DockerRuntimeBackend`` build backend, but a FAKE
``WorkerControlPlaneClient`` supplies the bundle bytes in-memory (no DB, no
control-plane HTTP surface needed to prove the Docker half of the pipeline).
The control-plane side (``WorkerBuildService`` / ``FullBundleService`` /
the worker-gateway route) is unit-testable without Docker and is exercised by
plain application-service tests elsewhere in this suite's convention; this
test's only job is to prove the worker-side fetch->verify->build wiring
against a REAL docker daemon end to end, exactly like
``test_build_isolation_integration.py`` proves ``build_image`` alone.

Builds a BENIGN, tiny ``alpine``-based bundle with ``--network=none`` (no
package installs -- see the design note's documented network-at-build-time
limitation) and asserts: the job completes with an ``image_ref``/``digest``
result, and the image REALLY exists on the host afterward.
"""

from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import unittest
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ctf_generator.domain.execution.runtime import BuildBundle
from ctf_generator.domain.work.models import Job, JobLease
from ctf_generator.infrastructure.runtime.docker_backend import DockerRuntimeBackend
from ctf_generator.workers.worker import Worker, WorkerConfig

_NOW = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)
_BACKEND = DockerRuntimeBackend()
_DOCKER = _BACKEND.is_available()
_SKIP = "docker CLI/daemon not available"


class _FakeRuntimeBackend:
    """A never-touched runtime backend (a build job reaches no launch verb)."""

    def reap_managed(self, worker=None):  # pragma: no cover - unused by build path
        return 0


@dataclass
class _FakeClient:
    bundle: BuildBundle
    claim_lease: JobLease | None
    token: str = "ctfw1.cred.secret"
    completed: list = field(default_factory=list)
    failed: list = field(default_factory=list)

    def authenticate(self, now):
        return self.token

    def claim(self, token, lease_seconds, now):
        lease, self.claim_lease = self.claim_lease, None
        return lease

    def start(self, token, job_id, lease_token, now):
        pass

    def heartbeat(self, token, job_id, lease_token, lease_seconds, now):
        return False

    def complete(self, token, job_id, lease_token, result, now):
        self.completed.append((job_id, result))

    def fail(self, token, job_id, lease_token, error_class, error_detail, retryable, now):
        self.failed.append((job_id, error_class, error_detail, retryable))

    def fetch_build_bundle(self, definition_slug, version_no, now):
        return self.bundle


def _tiny_bundle_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        dockerfile = b'FROM alpine:latest\nCMD ["sleep","86400"]\n'
        info = tarfile.TarInfo(name="Dockerfile")
        info.size = len(dockerfile)
        tar.addfile(info, io.BytesIO(dockerfile))
    return buf.getvalue()


@unittest.skipUnless(_DOCKER, _SKIP)
class BuildChallengeWorkerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._image_refs: list[str] = []

    def tearDown(self) -> None:
        for ref in self._image_refs:
            subprocess.run(
                ["docker", "image", "rm", "--force", ref],
                capture_output=True, text=True,
            )

    def test_build_challenge_job_builds_a_real_image(self) -> None:
        data = _tiny_bundle_tar()
        spec_sha256 = f"spec-{uuid.uuid4().hex}"
        bundle = BuildBundle(
            data=data,
            bundle_sha256=hashlib.sha256(data).hexdigest(),
            spec_sha256=spec_sha256,
        )
        payload = {
            "definition_slug": f"it-{uuid.uuid4().hex[:8]}",
            "version_no": 1,
            "spec_sha256": spec_sha256,
        }
        job = Job(
            job_id="job-build-it-1",
            job_type="build_challenge",
            idempotency_key=f"build-it:{uuid.uuid4().hex}",
            available_at=_NOW,
            required_capabilities=("build_challenge",),
            payload=payload,
        )
        lease = JobLease(job=job, lease_token="lease-it-1", lease_expires_at=_NOW)
        client = _FakeClient(bundle=bundle, claim_lease=lease)
        worker = Worker(
            WorkerConfig(worker_name="w-it", lease_seconds=60),
            client,
            _FakeRuntimeBackend(),  # type: ignore[arg-type]
            build_backend=_BACKEND,
            clock=lambda: _NOW,
        )

        worked = worker.run_once()

        self.assertTrue(worked)
        self.assertEqual(client.failed, [], client.failed)
        self.assertEqual(len(client.completed), 1)
        _job_id, result = client.completed[0]
        image_ref = result["image_ref"]
        self._image_refs.append(image_ref)
        self.assertTrue(result["digest"].startswith("sha256:"), result["digest"])

        # The image REALLY exists on the host.
        rc = subprocess.run(
            ["docker", "image", "inspect", image_ref],
            capture_output=True, text=True,
        ).returncode
        self.assertEqual(rc, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
