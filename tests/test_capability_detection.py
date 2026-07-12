"""Host-gated capability-detection tests for the Docker runtime backend.

Skips cleanly when the ``docker`` CLI/daemon is unavailable. Asserts
:meth:`DockerRuntimeBackend.probe` returns sane host facts and that
:meth:`detect_capabilities` is HONEST about ADR-004: it yields a valid
:class:`RuntimeCapabilities` only on a rootless daemon, and RAISES on a rootful
one rather than certifying an unsupported runtime.
"""

from __future__ import annotations

import unittest

from ctf_generator.domain.execution.runtime import RuntimeCapabilities
from ctf_generator.infrastructure.runtime.docker_backend import (
    DockerRuntimeBackend,
    UnsupportedRuntimeError,
)

_BACKEND = DockerRuntimeBackend()
_DOCKER = _BACKEND.is_available()
_SKIP = "docker CLI/daemon not available"


@unittest.skipUnless(_DOCKER, _SKIP)
class CapabilityDetectionTests(unittest.TestCase):
    def test_probe_reports_sane_host_facts(self) -> None:
        probe = _BACKEND.probe()
        self.assertTrue(probe.server_version)
        self.assertIn(probe.architecture, ("x86_64", "aarch64"))
        self.assertIn(probe.cgroup_version, ("1", "2"))
        self.assertIsInstance(probe.rootless, bool)
        self.assertIsInstance(probe.seccomp_enabled, bool)

    def test_detect_capabilities_is_honest_about_rootless(self) -> None:
        probe = _BACKEND.probe()
        if probe.rootless:
            caps = _BACKEND.detect_capabilities()
            self.assertIsInstance(caps, RuntimeCapabilities)
            self.assertTrue(caps.rootless)
            self.assertEqual(caps.runtime_type, "docker-rootless")
            self.assertIn(probe.architecture, caps.supported_architectures)
        else:
            # Rootful daemon -> ADR-004 forbids certifying it; detection must
            # refuse rather than fabricate a RuntimeCapabilities. (This is the
            # branch exercised on THIS rootful host.)
            with self.assertRaises(UnsupportedRuntimeError):
                _BACKEND.detect_capabilities()

    def test_seccomp_is_enabled_on_this_host(self) -> None:
        # The whole isolation floor depends on seccomp; document the host's state.
        self.assertTrue(
            _BACKEND.probe().seccomp_enabled,
            "docker daemon reports seccomp disabled -- launches would be refused",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
