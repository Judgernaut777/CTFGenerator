"""Real-Docker tests for the capability-gated build-time package mirror.

Docker-gated (skips cleanly off-docker). Proves the security keystone of the
mirror capability:

* a build opted into an operator-configured INTERNAL mirror network CAN reach a
  pre-warmed in-subnet mirror container (so a ``RUN`` that fetches succeeds),
* the DEFAULT ``--network=none`` build (no mirror, or not opted in) CANNOT reach
  it, and
* a NON-internal (or missing) mirror network is REFUSED, never silently
  downgraded to open egress.

Everything runs against ``alpine`` (already present; the whole point is that the
build fetches from the LOCAL mirror, not the internet), mirroring the existing
build-isolation integration test's convention.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
import uuid

from ctf_generator.infrastructure.runtime.docker_backend import (
    DockerCommandError,
    DockerRuntimeBackend,
    UnsupportedRuntimeError,
)

_DOCKER = DockerRuntimeBackend().is_available()
_SKIP = "docker CLI/daemon not available"


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check
    )


@unittest.skipUnless(_DOCKER, _SKIP)
class BuildMirrorIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._suffix = uuid.uuid4().hex[:8]
        self._internal_net = f"ctfgen-mirror-int-{self._suffix}"
        self._open_net = f"ctfgen-mirror-open-{self._suffix}"
        self._mirror_name = f"ctfgen-mirror-srv-{self._suffix}"
        self._tags: list[str] = []
        self._nets: list[str] = []
        # An INTERNAL mirror network + a busybox httpd serving one "package" file
        # on it. Internal => no route to the internet or the host.
        _docker("network", "create", "--internal", self._internal_net)
        self._nets.append(self._internal_net)
        # A tiny persistent HTTP/1.0 server via busybox nc: each connection execs
        # `cat /resp`, which sends a pre-built full response and closes. (alpine's
        # busybox has no httpd applet, but nc -l -e is reliable.)
        _docker(
            "run", "-d", "--name", self._mirror_name,
            "--network", self._internal_net,
            "alpine:latest",
            "sh", "-c",
            'printf "HTTP/1.0 200 OK\\r\\nContent-Length: 14\\r\\n'
            'Connection: close\\r\\n\\r\\nMIRROR-PKG-OK\\n" > /resp; '
            "while true; do nc -l -p 8000 -e /bin/cat /resp >/dev/null 2>&1; done",
        )

    def tearDown(self) -> None:
        _docker("rm", "-f", self._mirror_name, check=False)
        for tag in self._tags:
            _docker("image", "rm", "--force", tag, check=False)
        for net in self._nets:
            _docker("network", "rm", net, check=False)

    def _context(self) -> str:
        # A build that MUST fetch from the mirror to succeed: it fails unless the
        # in-subnet mirror is reachable during the RUN.
        d = tempfile.mkdtemp(prefix="ctfgen-mirror-ctx-")
        with open(os.path.join(d, "Dockerfile"), "w") as fh:
            fh.write(
                "FROM alpine:latest\n"
                f"RUN wget -q -T 10 -O /pkg.txt http://{self._mirror_name}:8000/pkg.txt "
                "&& grep -q MIRROR-PKG-OK /pkg.txt\n"
                'CMD ["sleep","1"]\n'
            )
        return d

    def _wait_mirror_ready(self) -> None:
        # Poll (from a peer container on the same net) until the nc server accepts.
        for _ in range(20):
            probe = _docker(
                "run", "--rm", "--network", self._internal_net, "alpine:latest",
                "sh", "-c",
                f"wget -q -T 2 -O - http://{self._mirror_name}:8000/pkg.txt",
                check=False,
            )
            if probe.returncode == 0 and "MIRROR-PKG-OK" in probe.stdout:
                return
        raise unittest.SkipTest("mirror server did not become ready")

    def _tag(self, label: str) -> str:
        tag = f"ctfgen-mirror-{label}-{self._suffix}:latest"
        self._tags.append(tag)
        return tag

    def test_build_with_internal_mirror_reaches_the_mirror(self) -> None:
        self._wait_mirror_ready()
        backend = DockerRuntimeBackend(build_mirror_network=self._internal_net)
        digest = backend.build_image(
            context_dir=self._context(), tag=self._tag("hit"), allow_mirror=True
        )
        self.assertTrue(digest.startswith("sha256:"), digest)

    def test_default_no_network_build_cannot_reach_the_mirror(self) -> None:
        # No mirror configured -> --network=none -> the fetch RUN fails at build
        # (a DockerCommandError -- an unreachable mirror, NOT our refusal path).
        backend = DockerRuntimeBackend()
        with self.assertRaises(DockerCommandError):
            backend.build_image(
                context_dir=self._context(), tag=self._tag("none"), allow_mirror=True
            )

    def test_not_opted_in_ignores_the_mirror(self) -> None:
        # Mirror configured but allow_mirror=False -> still --network=none -> fails.
        backend = DockerRuntimeBackend(build_mirror_network=self._internal_net)
        with self.assertRaises(DockerCommandError):
            backend.build_image(
                context_dir=self._context(), tag=self._tag("optout"),
                allow_mirror=False,
            )

    def test_non_internal_mirror_network_is_refused(self) -> None:
        # A NON-internal (open-egress) network must be refused, not attached.
        _docker("network", "create", self._open_net)  # not --internal
        self._nets.append(self._open_net)
        backend = DockerRuntimeBackend(build_mirror_network=self._open_net)
        with self.assertRaises(UnsupportedRuntimeError):
            backend.build_image(
                context_dir=self._context(), tag=self._tag("open"),
                allow_mirror=True,
            )

    def test_missing_mirror_network_is_refused(self) -> None:
        backend = DockerRuntimeBackend(
            build_mirror_network=f"ctfgen-nope-{self._suffix}"
        )
        with self.assertRaises(UnsupportedRuntimeError):
            backend.build_image(
                context_dir=self._context(), tag=self._tag("missing"),
                allow_mirror=True,
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
