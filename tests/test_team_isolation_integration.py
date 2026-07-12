"""Real-Docker team-isolation tests (THE security core of slice 2).

Docker-gated (skips cleanly off-docker). Launches TWO benign instances on two
dedicated per-instance networks and PROVES, with real containers, the KEY
INVARIANTS from docs/security/runtime-isolation.md:

* one team's instance cannot reach another team's instance (no cross-network
  route);
* a challenge container cannot reach the host PostgreSQL (``ctfgen_pg_epic1``),
  the cloud instance-metadata endpoint (169.254.169.254), or the internet at
  large (so it cannot reach the control plane / worker credentials either).

All containers/networks created are force-cleaned in tearDown; a leak would fail
a later run, so the suite asserts a clean slate itself.
"""

from __future__ import annotations

import subprocess
import unittest
import uuid

from ctf_generator.domain.execution.runtime import ContainerPolicy, ContainerRequest
from ctf_generator.infrastructure.runtime.docker_backend import DockerRuntimeBackend

_BENIGN_IMAGE = "alpine:latest"
_SLEEP = ("sleep", "3600")
_ACKED = frozenset({"rootless", "user_namespace", "apparmor"})
_PG_CONTAINER = "ctfgen_pg_epic1"
_METADATA_IP = "169.254.169.254"

_PROBE_BACKEND = DockerRuntimeBackend()
_DOCKER = _PROBE_BACKEND.is_available()
_SKIP = "docker CLI/daemon not available"


def _reach(container_id: str, ip: str, port: int, *, wait: int = 3) -> bool:
    """True iff ``container_id`` can open a TCP connection to ``ip:port``."""
    rc = subprocess.run(
        ["docker", "exec", container_id, "nc", "-w", str(wait), "-z", ip, str(port)],
        capture_output=True, text=True,
    ).returncode
    return rc == 0


def _pg_ip() -> str | None:
    out = subprocess.run(
        ["docker", "inspect", "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", _PG_CONTAINER],
        capture_output=True, text=True,
    )
    ip = out.stdout.strip()
    return ip or None


@unittest.skipUnless(_DOCKER, _SKIP)
class TeamIsolationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._backend = DockerRuntimeBackend(
            require_rootless=False, acknowledged_gaps=_ACKED
        )
        self._instance_ids: list[str] = []

    def tearDown(self) -> None:
        for iid in self._instance_ids:
            try:
                self._backend.destroy(iid, None)
            except Exception:  # pragma: no cover
                pass
            ps = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"label=ctfgen.instance={iid}"],
                capture_output=True, text=True,
            ).stdout.strip()
            self.assertEqual(ps, "", f"leftover container for {iid}")

    def _launch(self) -> tuple[str, str, str]:
        """Launch one benign instance; return (instance_id, container_id, ip)."""
        iid = f"iso-{uuid.uuid4().hex[:12]}"
        self._instance_ids.append(iid)
        req = ContainerRequest(
            instance_id=iid, team_key=iid, image_ref=_BENIGN_IMAGE,
            policy=ContainerPolicy(memory_mb=64, cpu_millis=250, network_mode="isolated"),
        )
        result = self._backend.launch(req, command=_SLEEP)
        cid = result.observation.container_id
        net = self._backend._network_name(iid)  # noqa: SLF001 - test introspection
        ip = subprocess.run(
            ["docker", "inspect", "--format",
             f"{{{{(index .NetworkSettings.Networks \"{net}\").IPAddress}}}}", cid],
            capture_output=True, text=True,
        ).stdout.strip()
        return iid, cid, ip

    def test_two_instances_cannot_reach_each_other(self) -> None:
        _iid_a, cid_a, _ip_a = self._launch()
        _iid_b, _cid_b, ip_b = self._launch()
        self.assertTrue(ip_b, "container B has no IP on its network")
        # A is on its own dedicated network; B's IP is on a different subnet with
        # no route -> A cannot reach B on any port.
        self.assertFalse(
            _reach(cid_a, ip_b, 8080),
            "team isolation breached: A reached B",
        )
        self.assertFalse(_reach(cid_a, ip_b, 22))

    def test_instance_cannot_reach_host_postgres(self) -> None:
        pg_ip = _pg_ip()
        if not pg_ip:
            self.skipTest(f"{_PG_CONTAINER} not running / has no IP")
        _iid, cid, _ip = self._launch()
        self.assertFalse(
            _reach(cid, pg_ip, 5432),
            f"isolation breached: instance reached PostgreSQL at {pg_ip}:5432",
        )

    def test_instance_cannot_reach_cloud_metadata(self) -> None:
        _iid, cid, _ip = self._launch()
        self.assertFalse(
            _reach(cid, _METADATA_IP, 80),
            "isolation breached: instance reached cloud metadata endpoint",
        )

    def test_instance_cannot_reach_internet(self) -> None:
        # No arbitrary egress -> cannot reach the control plane / any external
        # service either.
        _iid, cid, _ip = self._launch()
        self.assertFalse(
            _reach(cid, "8.8.8.8", 53),
            "isolation breached: instance reached the public internet",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
