"""Real-Docker team-isolation tests (THE security core of slice 2).

Docker-gated (skips cleanly off-docker). Every assertion here is REAL: a target
that must be reachable actually LISTENS, and every "cannot reach" assertion is
paired with a POSITIVE CONTROL proving the probe itself works -- so a broken
``nc``/``exec`` probe fails loudly instead of vacuously greening the suite.

Proven, with real containers, from docs/security/runtime-isolation.md:

* Cross-team: instance A (its own network) CANNOT reach instance B's OPEN port,
  while a helper on B's OWN network CAN (positive control).
* Host: an isolated container CANNOT reach a host-bound service on 0.0.0.0 via
  the bridge gateway -- the REPRODUCED escape (a ``--internal`` network alone
  does NOT block this), now closed by the host-block firewall. The host listener
  is proven genuinely up first, so the block is real, not "nothing was there".
* Metadata + internet: route-level egress denial (no default route off the
  per-instance network), so no cloud-metadata / control-plane / internet reach.
* ``egress`` mode is REFUSED (UnsupportedRuntimeError) until real egress
  restriction lands.

All containers/networks created (including throwaway probes) are force-cleaned.
"""

from __future__ import annotations

import socket
import subprocess
import threading
import unittest
import uuid

from ctf_generator.domain.execution.runtime import ContainerPolicy, ContainerRequest
from ctf_generator.infrastructure.runtime.docker_backend import (
    DockerRuntimeBackend,
    UnsupportedRuntimeError,
)

_BENIGN_IMAGE = "alpine:latest"
_SLEEP = ("sleep", "3600")
# A busybox listener: serve one byte per connection, restart so repeated -z
# probes keep succeeding.
_LISTEN_PORT = 8080
_LISTEN = ("sh", "-c", f"while true; do echo ok | nc -l -p {_LISTEN_PORT}; done")
_ACKED = frozenset({"rootless", "user_namespace", "apparmor"})
_METADATA_IP = "169.254.169.254"

_PROBE_BACKEND = DockerRuntimeBackend()
_DOCKER = _PROBE_BACKEND.is_available()
_SKIP = "docker CLI/daemon not available"
# The isolated launch REQUIRES an enforceable host-block firewall (a hard floor);
# if this host cannot enforce it, launch() correctly refuses, so the positive
# isolation cases here cannot run. That refusal (firewall_available() False ->
# UnsupportedRuntimeError with nothing created) is asserted by
# test_docker_backend_integration.DockerBackendIntegrationTests
# .test_isolated_launch_refuses_without_firewall_and_leaks_nothing; here we skip
# with a clear reason rather than error.
_FW = _DOCKER and DockerRuntimeBackend(
    require_rootless=False, acknowledged_gaps=_ACKED, worker_name="isotest"
).firewall_available()


def _reach(container_id: str, ip: str, port: int, *, wait: int = 3) -> bool:
    """True iff ``container_id`` can open a TCP connection to ``ip:port``."""
    rc = subprocess.run(
        ["docker", "exec", container_id, "nc", "-w", str(wait), "-z", ip, str(port)],
        capture_output=True, text=True,
    ).returncode
    return rc == 0


def _host_can_reach(ip: str, port: int, *, timeout: float = 3.0) -> bool:
    """True iff the TEST HOST itself can open a TCP connection to ``ip:port`` --
    used to guard an egress-denial assertion so it never becomes vacuous on an
    offline host (where the container would be unreachable regardless of the
    per-instance block)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


@unittest.skipUnless(_DOCKER, _SKIP)
@unittest.skipUnless(_FW, "host-block firewall unavailable; isolated launch refuses (see backend suite)")
class TeamIsolationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._backend = DockerRuntimeBackend(
            require_rootless=False, acknowledged_gaps=_ACKED, worker_name="isotest"
        )
        self._instance_ids: list[str] = []
        self._probe_names: list[str] = []

    def tearDown(self) -> None:
        for name in self._probe_names:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
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
            # destroy() removes the per-instance network too; enforce it here so a
            # leaked network (and its host-block) cannot pass unnoticed.
            nets = subprocess.run(
                ["docker", "network", "ls", "--filter",
                 f"label=ctfgen.instance={iid}", "--format", "{{.Name}}"],
                capture_output=True, text=True,
            ).stdout.strip()
            self.assertEqual(nets, "", f"leftover network for {iid}")

    def _launch(self, command=_SLEEP) -> tuple[str, str, str, str]:
        """Launch one benign instance; return (instance_id, container_id, ip, net)."""
        iid = f"iso-{uuid.uuid4().hex[:12]}"
        self._instance_ids.append(iid)
        req = ContainerRequest(
            instance_id=iid, team_key=iid, image_ref=_BENIGN_IMAGE,
            policy=ContainerPolicy(memory_mb=64, cpu_millis=250, network_mode="isolated"),
        )
        result = self._backend.launch(req, command=command)
        cid = result.observation.container_id
        net = self._backend._network_name(iid)  # noqa: SLF001 - test introspection
        ip = subprocess.run(
            ["docker", "inspect", "--format",
             f"{{{{(index .NetworkSettings.Networks \"{net}\").IPAddress}}}}", cid],
            capture_output=True, text=True,
        ).stdout.strip()
        return iid, cid, ip, net

    def _gateway(self, net: str) -> str:
        return subprocess.run(
            ["docker", "network", "inspect", "--format",
             "{{range .IPAM.Config}}{{.Gateway}}{{end}}", net],
            capture_output=True, text=True,
        ).stdout.strip()

    def _host_block_lines(self, binary: str, subnet: str) -> list[str]:
        """Every installed ctfgen host-block rule (by comment marker) whose spec
        mentions ``subnet``, read from the host INPUT + DOCKER-USER chains via the
        firewall helper container."""
        lines: list[str] = []
        for chain in ("INPUT", "DOCKER-USER"):
            out = subprocess.run(
                ["docker", "run", "--rm", "--net=host", "--cap-add=NET_ADMIN",
                 self._backend._firewall_image, binary, "-S", chain],  # noqa: SLF001
                capture_output=True, text=True,
            ).stdout
            lines += [
                ln for ln in out.splitlines()
                if "ctfgen-hostblock" in ln and subnet in ln
            ]
        return lines

    def _probe_from_network(self, net: str, ip: str, port: int) -> bool:
        """Run a throwaway container ON ``net`` and report whether it can reach
        ``ip:port`` (the POSITIVE CONTROL for co-located reachability)."""
        name = f"probe-{uuid.uuid4().hex[:10]}"
        self._probe_names.append(name)
        rc = subprocess.run(
            ["docker", "run", "--rm", "--name", name, "--network", net,
             _BENIGN_IMAGE, "nc", "-w", "3", "-z", ip, str(port)],
            capture_output=True, text=True,
        ).returncode
        return rc == 0

    # -- cross-team ------------------------------------------------------------

    def test_cross_team_isolation_with_positive_control(self) -> None:
        _iid_a, cid_a, _ip_a, _net_a = self._launch(_SLEEP)
        _iid_b, _cid_b, ip_b, net_b = self._launch(_LISTEN)
        self.assertTrue(ip_b, "container B has no IP on its network")
        # POSITIVE CONTROL: a helper on B's OWN network CAN reach B's open port,
        # so the port is genuinely listening and the probe genuinely works.
        self.assertTrue(
            self._probe_from_network(net_b, ip_b, _LISTEN_PORT),
            "positive control failed: B's open port unreachable even on its own net",
        )
        # ISOLATION: A (its own dedicated network) cannot reach B's OPEN port.
        self.assertFalse(
            _reach(cid_a, ip_b, _LISTEN_PORT),
            "team isolation breached: A reached B's open port",
        )

    def test_reach_probe_returns_true_for_open_colocated_target(self) -> None:
        # An explicit positive control so an nc/exec regression cannot silently
        # green the negative isolation assertions elsewhere.
        _iid, _cid, ip, net = self._launch(_LISTEN)
        self.assertTrue(
            self._probe_from_network(net, ip, _LISTEN_PORT),
            "_reach-style probe returned False for a genuinely-open co-located target",
        )

    def test_reach_exec_probe_returns_true_for_open_colocated_target(self) -> None:
        # POSITIVE CONTROL on the SAME probe path as every negative assertion:
        # ``_reach`` (docker EXEC ... nc), not ``_probe_from_network`` (docker RUN
        # ... nc). An exec-probe regression (PATH / -z under exec) would false-green
        # all the negatives; this proves _reach returns True for a genuinely
        # reachable target reached over that exact exec path. The peer is a second
        # RUNNING container co-located on the listener's OWN network (intra-network
        # traffic is permitted; only container->host is blocked).
        _iid, _cid, ip, net = self._launch(_LISTEN)
        self.assertTrue(ip, "listener has no IP on its network")
        peer = f"probe-{uuid.uuid4().hex[:10]}"
        self._probe_names.append(peer)
        run = subprocess.run(
            ["docker", "run", "-d", "--name", peer, "--network", net,
             _BENIGN_IMAGE, *_SLEEP],
            capture_output=True, text=True,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(
            _reach(peer, ip, _LISTEN_PORT),
            "exec probe (_reach) returned False for a genuinely reachable "
            "co-located target -- the exec probe path is broken",
        )

    # -- host reachability (the REPRODUCED escape) -----------------------------

    def test_isolated_container_cannot_reach_host_bound_service(self) -> None:
        # Stand up a throwaway HOST-bound listener on 0.0.0.0:<ephemeral> serving a
        # "secret" -- the exact shape of the reviewer's reproduced escape.
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 0))  # noqa: S104 - binding all interfaces IS the escape
        port = srv.getsockname()[1]
        srv.listen(5)
        stop = threading.Event()

        def _serve() -> None:
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                    conn.sendall(b"SECRET\n")
                    conn.close()
                except OSError:
                    break

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        try:
            # POSITIVE CONTROL: the host itself can connect, so the listener is
            # genuinely up -- the block below is real, not "nothing was there".
            with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
                self.assertEqual(c.recv(16), b"SECRET\n")

            _iid, cid, _ip, net = self._launch(_SLEEP)
            gateway = self._gateway(net)
            self.assertTrue(gateway, "no gateway on the per-instance network")
            # The REPRODUCED escape, now BLOCKED: the container cannot reach the
            # host via the bridge gateway...
            self.assertFalse(
                _reach(cid, gateway, port),
                f"HOST ESCAPE: isolated container reached host {gateway}:{port}",
            )
            # ...nor via the docker0 host IP (a different host interface).
            self.assertFalse(
                _reach(cid, "172.17.0.1", port),
                f"HOST ESCAPE: isolated container reached host 172.17.0.1:{port}",
            )
        finally:
            stop.set()
            srv.close()

    # -- metadata + internet (route-level egress denial) -----------------------

    def test_metadata_and_internet_egress_is_denied(self) -> None:
        _iid, cid, _ip, _net = self._launch(_SLEEP)
        # THE load-bearing proof: 8.8.8.8:53 is a REAL, live public service that
        # WOULD answer if egress were open, so the container's inability to reach it
        # proves an actual route-level block (--internal + the DOCKER-USER off-subnet
        # DROP), not "nothing was there". GUARD it: if the HOST itself cannot reach
        # 8.8.8.8:53 (offline CI) the assertion would be vacuous, so skip with a
        # clear reason rather than green silently.
        if not _host_can_reach("8.8.8.8", 53):
            self.skipTest(
                "host cannot reach 8.8.8.8:53 (offline); the egress-denial "
                "assertion would be vacuous"
            )
        self.assertFalse(
            _reach(cid, "8.8.8.8", 53),
            "egress denial breached: instance reached the public internet (8.8.8.8:53)",
        )
        # Defence-in-depth only, NOT relied on as proof here: the cloud
        # instance-metadata endpoint. On this non-cloud host nothing answers
        # 169.254.169.254 at all, so this assertion is VACUOUS locally and is a
        # meaningful check only on a cloud host (where it serves credentials). It is
        # kept as a documented cloud-only guard, not as evidence of the block.
        self.assertFalse(
            _reach(cid, _METADATA_IP, 80),
            "isolation breached: instance reached cloud metadata endpoint",
        )

    # -- fail-safe host-block teardown (out-of-band network removal) ------------

    def test_out_of_band_network_removal_leaves_no_orphan_host_block(self) -> None:
        # The normal teardown reads a network's subnet from the LIVE network to
        # drop its host-block. If a per-instance network is removed OUT-OF-BAND
        # (``docker network rm`` bypassing the backend) the subnet becomes
        # unreadable, so a subnet-matched teardown can no longer find the rule and
        # it strands. reap_managed()'s comment-marker sweep must reclaim it. (The
        # stranded rule is fail-SAFE -- it over-blocks a recycled subnet, never
        # opens a hole -- but a leaked rule is still hygiene debt.)
        iid, cid, _ip, net = self._launch(_SLEEP)
        subnet = self._backend._network_subnet(net)  # noqa: SLF001
        self.assertTrue(subnet, "no subnet on the per-instance network")
        binary = self._backend._detect_firewall_backend()  # noqa: SLF001
        self.assertIsNotNone(binary, "no working firewall backend")
        # The host-block rule is present while the network is live.
        self.assertTrue(
            self._host_block_lines(binary, subnet),
            "host-block rule missing while the network is live",
        )
        # Remove the network OUT-OF-BAND: force-remove the container (the only
        # endpoint) then the network directly, bypassing the backend teardown.
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
        rm = subprocess.run(
            ["docker", "network", "rm", net], capture_output=True, text=True
        )
        self.assertEqual(rm.returncode, 0, rm.stderr)
        # The rule is now STRANDED (network + subnet gone) -- the leak we close.
        self.assertTrue(
            self._host_block_lines(binary, subnet),
            "expected the host-block rule to strand after out-of-band removal",
        )
        # The comment-marker orphan sweep in reap_managed reclaims it.
        self._backend.reap_managed()
        self.assertEqual(
            self._host_block_lines(binary, subnet), [],
            "orphan ctfgen host-block rule leaked after reap_managed",
        )

    # -- egress mode is refused until real restriction lands -------------------

    def test_egress_mode_is_refused(self) -> None:
        iid = f"iso-{uuid.uuid4().hex[:12]}"
        req = ContainerRequest(
            instance_id=iid, team_key=iid, image_ref=_BENIGN_IMAGE,
            policy=ContainerPolicy(memory_mb=64, cpu_millis=250, network_mode="egress"),
        )
        with self.assertRaises(UnsupportedRuntimeError):
            self._backend.launch(req, command=_SLEEP)
        # Refused BEFORE creating anything.
        ps = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=ctfgen.instance={iid}"],
            capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(ps, "", "egress refusal must not create a container")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
