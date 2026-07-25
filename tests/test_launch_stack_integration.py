"""Real-Docker test for compose-aware multi-container launch (build_challenge C).

Docker-gated. Proves ``DockerRuntimeBackend.launch_stack`` starts N containers on
ONE isolated per-instance network, each reachable by its service name (inter-
service DNS), and that ``remove`` tears the whole stack + network down. Uses
``alpine`` directly as the image (the launch, not the build, is under test).

Requires the host-block firewall capability (like the other isolated-network
integration tests); skips cleanly where it is unavailable.
"""

from __future__ import annotations

import subprocess
import unittest
import uuid

from ctf_generator.domain.execution.runtime import StackContainerSpec, StackRequest
from ctf_generator.infrastructure.runtime.docker_backend import (
    INSTANCE_LABEL,
    DockerCommandError,
    DockerRuntimeBackend,
    DockerRuntimeError,
)
from ctf_generator.workers.worker import DEFAULT_POLICY

# A single-host verification deployment explicitly acknowledges the outer-layer
# gaps a rootful host runs without (mirrors test_docker_backend_integration.py).
_ACKED = frozenset({"rootless", "user_namespace", "apparmor"})
_BACKEND = DockerRuntimeBackend(require_rootless=False, acknowledged_gaps=_ACKED)
_ENABLED = _BACKEND.is_available() and _BACKEND.firewall_available()
_SKIP = "docker + host-block firewall required"


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True)


@unittest.skipUnless(_ENABLED, _SKIP)
class LaunchStackIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._instance = f"stk-{uuid.uuid4().hex[:12]}"

    def tearDown(self) -> None:
        _BACKEND.remove(self._instance, None)

    def _request(self) -> StackRequest:
        return StackRequest(
            instance_id=self._instance,
            team_key="cup:Red",
            policy=DEFAULT_POLICY,  # isolated network_mode
            containers=(
                StackContainerSpec(service_name="internal", image_ref="alpine:latest"),
                StackContainerSpec(
                    service_name="edge", image_ref="alpine:latest",
                    exposed_ports=(8000,),
                ),
            ),
        )

    def test_launches_all_services_on_one_network_with_dns(self) -> None:
        result = _BACKEND.launch_stack(self._request(), command=("sleep", "120"))
        containers = [
            r.external_ref for r in result.runtime_resources if r.kind == "container"
        ]
        networks = [
            r.external_ref for r in result.runtime_resources if r.kind == "network"
        ]
        self.assertEqual(len(containers), 2)
        self.assertEqual(len(networks), 1)
        self.assertEqual(result.observation.phase, "running")

        # Both service containers really run and share the instance label.
        labelled = _docker(
            "ps", "-q", "--filter", f"label={INSTANCE_LABEL}={self._instance}"
        ).stdout.split()
        self.assertEqual(len(labelled), 2)

        # Inter-service DNS: from one container, the sibling resolves by service
        # name on the shared network (the whole point of a stack).
        edge = next(
            cid for cid in labelled
            if "-edge" in _docker("inspect", "-f", "{{.Name}}", cid).stdout
        )
        ping = _docker("exec", edge, "ping", "-c", "1", "-W", "3", "internal")
        self.assertEqual(ping.returncode, 0, ping.stdout + ping.stderr)

    def test_remove_tears_down_the_whole_stack(self) -> None:
        _BACKEND.launch_stack(self._request(), command=("sleep", "120"))
        _BACKEND.remove(self._instance, None)
        remaining = _docker(
            "ps", "-aq", "--filter", f"label={INSTANCE_LABEL}={self._instance}"
        ).stdout.split()
        self.assertEqual(remaining, [])  # every service container swept

    def test_stack_containers_are_all_discoverable_by_label(self) -> None:
        # find_stack_containers must return EVERY service container (with its
        # service label), so the lifecycle verbs observe the whole stack.
        _BACKEND.launch_stack(self._request(), command=("sleep", "120"))
        pairs = _BACKEND.find_stack_containers(self._instance)
        self.assertEqual(len(pairs), 2)
        self.assertEqual(
            {svc for _cid, svc in pairs}, {"internal", "edge"}
        )

    def test_a_service_that_crashes_immediately_tears_down_the_stack(self) -> None:
        # A container whose process exits almost immediately still looks "running"
        # in the ~1ms window right after `docker run -d` (the run itself succeeds).
        # The launch's settle + re-observe must catch the exit, classify the launch
        # a FAILURE, and tear the WHOLE stack down -- never report it healthy.
        crashing = StackRequest(
            instance_id=self._instance,
            team_key="cup:Red",
            policy=DEFAULT_POLICY,
            containers=(
                StackContainerSpec(service_name="ok", image_ref="alpine:latest"),
                StackContainerSpec(service_name="boom", image_ref="alpine:latest"),
            ),
        )
        # `false` exits non-zero immediately -- `docker run -d` still returns 0
        # (the container was created), so this is caught ONLY by the settle pass,
        # which raises DockerRuntimeError (NOT a DockerCommandError -- the run
        # succeeded).
        with self.assertRaises(DockerRuntimeError):
            _BACKEND.launch_stack(crashing, command=("false",))
        remaining = _docker(
            "ps", "-aq", "--filter", f"label={INSTANCE_LABEL}={self._instance}"
        ).stdout.split()
        self.assertEqual(remaining, [])  # the whole stack was swept

    def test_partial_failure_leaks_nothing(self) -> None:
        # A second service with a bogus image fails mid-launch; the whole partial
        # stack (incl. the first, good container) must be removed.
        bad = StackRequest(
            instance_id=self._instance,
            team_key="cup:Red",
            policy=DEFAULT_POLICY,
            containers=(
                StackContainerSpec(service_name="ok", image_ref="alpine:latest"),
                StackContainerSpec(
                    service_name="nope",
                    image_ref="ctfgen-nonexistent-image-xyz:latest",
                ),
            ),
        )
        with self.assertRaises(DockerCommandError):
            _BACKEND.launch_stack(bad, command=("sleep", "120"))
        remaining = _docker(
            "ps", "-aq", "--filter", f"label={INSTANCE_LABEL}={self._instance}"
        ).stdout.split()
        self.assertEqual(remaining, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
