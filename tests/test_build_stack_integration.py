"""Real-Docker test for compose-aware multi-image build (build_challenge tail C).

Docker-gated. Builds a synthetic TWO-service alpine stack (real generated Python
families RUN pip install and need the mirror, so the docker-gated test uses alpine
exactly like the existing build-isolation test) and proves the worker builds one
image per service and reports a stack completion with a primary anchor. A
single-image bundle is proven to keep the original shape (no ``services``).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest

from ctf_generator.infrastructure.runtime.docker_backend import DockerRuntimeBackend
from ctf_generator.workers.worker import Worker, WorkerConfig

_DOCKER = DockerRuntimeBackend().is_available()
_SKIP = "docker CLI/daemon not available"
_BUNDLE_SHA = "a" * 64


def _worker() -> Worker:
    # Only the build backend is exercised by _build_from_bundle.
    return Worker(
        WorkerConfig(worker_name="w1", lease_seconds=60),
        client=None,  # type: ignore[arg-type]
        backend=None,  # type: ignore[arg-type]
        build_backend=DockerRuntimeBackend(),
    )


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


@unittest.skipUnless(_DOCKER, _SKIP)
class BuildStackIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tags: list[str] = []

    def tearDown(self) -> None:
        for tag in self._tags:
            subprocess.run(
                ["docker", "image", "rm", "--force", tag],
                capture_output=True, text=True,
            )

    def _stack_bundle(self) -> str:
        root = tempfile.mkdtemp(prefix="ctfgen-stack-")
        _write(
            os.path.join(root, "docker-compose.yml"),
            "services:\n"
            "  alpha:\n"
            "    build: ./services/alpha\n"
            '    expose: ["8000"]\n'
            "  beta:\n"
            "    build: ./services/beta\n"
            '    ports: ["8080:8080"]\n'
            "    depends_on: [alpha]\n",
        )
        _write(
            os.path.join(root, "services", "alpha", "Dockerfile"),
            'FROM alpine:latest\nRUN echo alpha > /svc\nCMD ["sleep","1"]\n',
        )
        _write(
            os.path.join(root, "services", "beta", "Dockerfile"),
            'FROM alpine:latest\nRUN echo beta > /svc\nCMD ["sleep","1"]\n',
        )
        return root

    def test_builds_one_image_per_service(self) -> None:
        from pathlib import Path

        result = _worker()._build_from_bundle(
            "demo-net", 1, _BUNDLE_SHA, Path(self._stack_bundle())
        )
        services = result["services"]
        self._tags += [s["image_ref"] for s in services]
        self.assertEqual({s["service"] for s in services}, {"alpha", "beta"})
        for s in services:
            self.assertTrue(s["image_ref"].startswith("ctfgen-build/"))
            self.assertTrue(s["digest"].startswith("sha256:"))
            # Each service's image really exists.
            rc = subprocess.run(
                ["docker", "image", "inspect", s["image_ref"]],
                capture_output=True, text=True,
            ).returncode
            self.assertEqual(rc, 0, s["image_ref"])
        # beta declares host ports -> it is the primary/ingress anchor.
        beta = next(s for s in services if s["service"] == "beta")
        self.assertTrue(beta["is_primary"])
        self.assertEqual(beta["depends_on"], ["alpha"])
        self.assertEqual(result["image_ref"], beta["image_ref"])
        self.assertEqual(result["digest"], beta["digest"])

    def test_single_image_bundle_has_no_services(self) -> None:
        from pathlib import Path

        root = tempfile.mkdtemp(prefix="ctfgen-single-")
        _write(
            os.path.join(root, "Dockerfile"),
            'FROM alpine:latest\nCMD ["sleep","1"]\n',
        )
        result = _worker()._build_from_bundle("demo", 1, _BUNDLE_SHA, Path(root))
        self._tags.append(result["image_ref"])
        self.assertNotIn("services", result)
        self.assertTrue(result["image_ref"].startswith("ctfgen-build/"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
