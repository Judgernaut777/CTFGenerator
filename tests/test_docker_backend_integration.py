"""Real-Docker integration tests for DockerRuntimeBackend (security core).

Docker-gated (skips cleanly off-docker). Launches a BENIGN image (``alpine`` with
a ``sleep`` command -- never generated challenge code) under a STRICT
ContainerPolicy and proves, via ``docker inspect``/``docker exec``, that every
hardening flag actually took effect on a real container, that a health check
passes, and that ``destroy`` leaves NO container or network behind.

Host-capability honesty: this host is rootful and has no AppArmor, so the backend
is constructed with an EXPLICIT ``acknowledged_gaps`` naming exactly those
outer-layer capabilities. The per-container hardening asserted here (non-root,
caps, seccomp, no-new-privileges, read-only, limits, per-instance network, no
host namespaces) is enforced identically on a rootless host; the rootless/userns
OUTER layer is an unverified live path on this host, documented in
docs/security/runtime-isolation.md. A default (secure) backend refusing to launch
on this rootful host is asserted too.
"""

from __future__ import annotations

import subprocess
import unittest
import uuid

from ctf_generator.domain.execution.runtime import ContainerPolicy, ContainerRequest
from ctf_generator.infrastructure.runtime.docker_backend import (
    DockerRuntimeBackend,
    UnsupportedRuntimeError,
)

_BENIGN_IMAGE = "alpine:latest"
_SLEEP = ("sleep", "3600")
_ACKED = frozenset({"rootless", "user_namespace", "apparmor"})

_PROBE_BACKEND = DockerRuntimeBackend()
_DOCKER = _PROBE_BACKEND.is_available()
_SKIP = "docker CLI/daemon not available"


def _dx(container_id: str, *cmd: str) -> str:
    return subprocess.run(
        ["docker", "exec", container_id, *cmd],
        capture_output=True,
        text=True,
    ).stdout.strip()


def _inspect(container_id: str, fmt: str) -> str:
    return subprocess.run(
        ["docker", "inspect", "--format", fmt, container_id],
        capture_output=True,
        text=True,
    ).stdout.strip()


@unittest.skipUnless(_DOCKER, _SKIP)
class DockerBackendIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._backend = DockerRuntimeBackend(
            require_rootless=False, acknowledged_gaps=_ACKED
        )
        self._instance_ids: list[str] = []

    def tearDown(self) -> None:
        # Force-clean every instance we created (containers + networks).
        for iid in self._instance_ids:
            try:
                self._backend.destroy(iid, None)
            except Exception:  # pragma: no cover
                pass
            self._assert_clean(iid)

    def _launch(self, policy: ContainerPolicy) -> tuple[str, str]:
        iid = f"it-{uuid.uuid4().hex[:12]}"
        self._instance_ids.append(iid)
        req = ContainerRequest(
            instance_id=iid, team_key="red", image_ref=_BENIGN_IMAGE, policy=policy
        )
        result = self._backend.launch(req, command=_SLEEP)
        return iid, result.observation.container_id

    def _assert_clean(self, iid: str) -> None:
        ps = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=ctfgen.instance={iid}"],
            capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(ps, "", f"leftover container for {iid}")
        nets = subprocess.run(
            ["docker", "network", "ls", "--filter",
             f"label=ctfgen.instance={iid}", "--format", "{{.Name}}"],
            capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(nets, "", f"leftover network for {iid}")

    # -- the strict-policy hardening proof -------------------------------------

    def test_strict_policy_hardening_takes_effect(self) -> None:
        policy = ContainerPolicy(
            memory_mb=64, cpu_millis=500, pids_limit=64, tmpfs_mb=16
        )
        iid, cid = self._launch(policy)
        self.assertTrue(cid)

        # non-root
        self.assertNotEqual(_dx(cid, "id", "-u"), "0")
        self.assertEqual(_dx(cid, "id", "-u"), "65534")
        # seccomp filter active (mode 2)
        self.assertIn("2", _dx(cid, "sh", "-c", "grep '^Seccomp:' /proc/self/status"))
        # all caps dropped -> effective capability set is empty
        capeff = _dx(cid, "sh", "-c", "grep CapEff /proc/self/status")
        self.assertTrue(capeff.endswith("0000000000000000"), capeff)
        # no-new-privileges
        self.assertIn("no-new-privileges", _inspect(cid, "{{.HostConfig.SecurityOpt}}"))
        # read-only rootfs
        self.assertEqual(_inspect(cid, "{{.HostConfig.ReadonlyRootfs}}"), "true")
        # memory + pids limits (64MiB, 64 pids)
        self.assertEqual(_inspect(cid, "{{.HostConfig.Memory}}"), str(64 * 1024 * 1024))
        self.assertEqual(_inspect(cid, "{{.HostConfig.PidsLimit}}"), "64")
        # all caps dropped at the docker level
        self.assertIn("ALL", _inspect(cid, "{{.HostConfig.CapDrop}}"))
        # NO host namespaces
        self.assertNotEqual(_inspect(cid, "{{.HostConfig.PidMode}}"), "host")
        self.assertNotEqual(_inspect(cid, "{{.HostConfig.IpcMode}}"), "host")
        self.assertNotEqual(_inspect(cid, "{{.HostConfig.NetworkMode}}"), "host")
        self.assertNotEqual(_inspect(cid, "{{.HostConfig.UTSMode}}"), "host")
        # NOT privileged
        self.assertEqual(_inspect(cid, "{{.HostConfig.Privileged}}"), "false")
        # dedicated per-instance network attached
        net = _inspect(cid, "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}")
        self.assertIn(f"ctfgen-net-{iid}", net)

    def test_writable_tmpfs_is_noexec(self) -> None:
        iid, cid = self._launch(ContainerPolicy(memory_mb=64, cpu_millis=250, tmpfs_mb=8))
        # The rootfs is read-only: a write outside /tmp fails.
        ro = subprocess.run(
            ["docker", "exec", cid, "sh", "-c", "echo x > /root_probe 2>&1 || echo READONLY"],
            capture_output=True, text=True,
        ).stdout
        self.assertIn("READONLY", ro)
        # /tmp is writable but mounted noexec: an executable there cannot run.
        noexec = subprocess.run(
            ["docker", "exec", cid, "sh", "-c",
             "cp /bin/busybox /tmp/x && chmod +x /tmp/x && /tmp/x true 2>&1 || echo NOEXEC"],
            capture_output=True, text=True,
        ).stdout
        self.assertIn("NOEXEC", noexec)

    def test_non_root_can_write_its_tmpfs(self) -> None:
        # Under --read-only the tmpfs is the container's ONLY writable path; it is
        # owned by the non-root uid so a uid-65534 process CAN write there.
        iid, cid = self._launch(ContainerPolicy(memory_mb=64, cpu_millis=250, tmpfs_mb=8))
        self.assertEqual(_dx(cid, "id", "-u"), "65534")
        wrote = subprocess.run(
            ["docker", "exec", cid, "sh", "-c",
             "echo hello > /tmp/probe && cat /tmp/probe"],
            capture_output=True, text=True,
        )
        self.assertEqual(wrote.returncode, 0, wrote.stderr)
        self.assertIn("hello", wrote.stdout)

    def test_reap_managed_is_scoped_to_this_worker(self) -> None:
        # A second worker's crash-recovery sweep must NOT touch the first worker's
        # live containers (they carry distinct ctfgen.worker labels).
        worker_a = DockerRuntimeBackend(
            require_rootless=False, acknowledged_gaps=_ACKED, worker_name="reap-a"
        )
        iid = f"it-{uuid.uuid4().hex[:12]}"
        self._instance_ids.append(iid)
        req = ContainerRequest(
            instance_id=iid, team_key="red", image_ref=_BENIGN_IMAGE,
            policy=ContainerPolicy(memory_mb=64, cpu_millis=250),
        )
        worker_a.launch(req, command=_SLEEP)
        # Worker B reaps its OWN managed containers -> must not reap A's.
        worker_b = DockerRuntimeBackend(
            require_rootless=False, acknowledged_gaps=_ACKED, worker_name="reap-b"
        )
        reaped_by_b = worker_b.reap_managed()
        self.assertEqual(reaped_by_b, 0, "worker B reaped a container it does not own")
        still_there = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"label=ctfgen.instance={iid}"],
            capture_output=True, text=True,
        ).stdout.strip()
        self.assertTrue(still_there, "worker B's reap wrongly removed worker A's container")
        # Worker A's own reap DOES remove it.
        self.assertEqual(worker_a.reap_managed(), 1)
        worker_a.destroy(iid, None)
        self._assert_clean(iid)

    def test_health_check_passes_for_running_container(self) -> None:
        iid, cid = self._launch(ContainerPolicy(memory_mb=64, cpu_millis=250))
        obs = self._backend.health_check(iid, cid)
        self.assertEqual(obs.phase, "running")

    def test_destroy_is_idempotent(self) -> None:
        iid, cid = self._launch(ContainerPolicy(memory_mb=64, cpu_millis=250))
        self._backend.destroy(iid, cid)
        self._assert_clean(iid)
        # Second destroy must not raise (safe if already gone).
        self._backend.destroy(iid, cid)
        self._assert_clean(iid)

    # -- refusal proofs --------------------------------------------------------

    def test_default_secure_backend_refuses_on_rootful_host(self) -> None:
        probe = _PROBE_BACKEND.probe()
        if probe.rootless:
            self.skipTest("host is rootless; the rootful-refusal path does not apply")
        secure = DockerRuntimeBackend()  # require_rootless=True, no acked gaps
        iid = f"it-{uuid.uuid4().hex[:12]}"
        req = ContainerRequest(
            instance_id=iid, team_key="red", image_ref=_BENIGN_IMAGE,
            policy=ContainerPolicy(memory_mb=64, cpu_millis=250),
        )
        with self.assertRaises(UnsupportedRuntimeError):
            secure.launch(req, command=_SLEEP)
        # Refused BEFORE creating anything.
        self._assert_clean(iid)

    def test_isolated_launch_refuses_without_firewall_and_leaks_nothing(self) -> None:
        # HARD FLOOR: an isolated launch REQUIRES an enforceable host-block
        # firewall. When firewall_available() is False the backend must refuse
        # BEFORE creating any container or per-instance network -- it never runs a
        # container that could reach the host. This subclass forces the unavailable
        # case; the refusal path is otherwise unreachable on a host whose firewall
        # control works (as this one's does).
        class _NoFirewallBackend(DockerRuntimeBackend):
            def firewall_available(self) -> bool:  # noqa: D401 - test override
                return False

        backend = _NoFirewallBackend(
            require_rootless=False, acknowledged_gaps=_ACKED
        )
        iid = f"it-{uuid.uuid4().hex[:12]}"
        self._instance_ids.append(iid)  # tearDown double-checks cleanliness
        req = ContainerRequest(
            instance_id=iid, team_key="red", image_ref=_BENIGN_IMAGE,
            policy=ContainerPolicy(
                memory_mb=64, cpu_millis=250, network_mode="isolated"
            ),
        )
        with self.assertRaises(UnsupportedRuntimeError):
            backend.launch(req, command=_SLEEP)
        # Refused BEFORE creating anything: no container AND no per-instance network.
        self._assert_clean(iid)

    def test_unacknowledged_gap_refuses(self) -> None:
        probe = _PROBE_BACKEND.probe()
        if probe.rootless:
            self.skipTest("host is rootless; no outer-layer gap to leave unacked")
        # Acknowledge only apparmor, leaving rootless/userns unacknowledged.
        partial = DockerRuntimeBackend(
            require_rootless=False, acknowledged_gaps=frozenset({"apparmor"})
        )
        iid = f"it-{uuid.uuid4().hex[:12]}"
        req = ContainerRequest(
            instance_id=iid, team_key="red", image_ref=_BENIGN_IMAGE,
            policy=ContainerPolicy(memory_mb=64, cpu_millis=250),
        )
        with self.assertRaises(UnsupportedRuntimeError):
            partial.launch(req, command=_SLEEP)
        self._assert_clean(iid)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
