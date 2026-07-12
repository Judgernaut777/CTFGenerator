"""Real-Docker build-isolation tests for DockerRuntimeBackend.build_image.

Docker-gated (skips cleanly off-docker). Builds a BENIGN image from a minimal,
generator-shaped context with ``--network=none`` and proves the build produces a
content-addressed digest and that an oversized image is refused. No secrets/
build-args are ever passed.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
import uuid

from ctf_generator.infrastructure.runtime.docker_backend import (
    DockerRuntimeBackend,
    UnsupportedRuntimeError,
)

_BACKEND = DockerRuntimeBackend()
_DOCKER = _BACKEND.is_available()
_SKIP = "docker CLI/daemon not available"


@unittest.skipUnless(_DOCKER, _SKIP)
class BuildIsolationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tags: list[str] = []

    def tearDown(self) -> None:
        for tag in self._tags:
            subprocess.run(
                ["docker", "image", "rm", "--force", tag],
                capture_output=True, text=True,
            )

    def _context(self, dockerfile: str) -> str:
        d = tempfile.mkdtemp(prefix="ctfgen-build-")
        with open(os.path.join(d, "Dockerfile"), "w") as fh:
            fh.write(dockerfile)
        return d

    def test_build_no_network_produces_digest(self) -> None:
        # Base image is present locally, so a --network=none build succeeds.
        tag = f"ctfgen-build-test-{uuid.uuid4().hex[:8]}:latest"
        self._tags.append(tag)
        context = self._context('FROM alpine:latest\nCMD ["sleep","86400"]\n')
        digest = _BACKEND.build_image(context_dir=context, tag=tag, network=False)
        self.assertTrue(digest.startswith("sha256:"), digest)
        # The image really exists.
        rc = subprocess.run(
            ["docker", "image", "inspect", tag], capture_output=True, text=True
        ).returncode
        self.assertEqual(rc, 0)

    def test_oversized_image_is_refused_and_removed(self) -> None:
        tag = f"ctfgen-build-oversize-{uuid.uuid4().hex[:8]}:latest"
        self._tags.append(tag)
        context = self._context('FROM alpine:latest\nCMD ["sleep","86400"]\n')
        tiny = DockerRuntimeBackend(max_image_mb=1)  # alpine is > 1MB
        with self.assertRaises(UnsupportedRuntimeError):
            tiny.build_image(context_dir=context, tag=tag, network=False)
        # Refused build left no image behind.
        rc = subprocess.run(
            ["docker", "image", "inspect", tag], capture_output=True, text=True
        ).returncode
        self.assertNotEqual(rc, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
