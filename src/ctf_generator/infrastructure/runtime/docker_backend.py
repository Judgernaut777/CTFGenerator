"""Concrete Docker runtime backend (M8 slice 2, WORKER-SIDE).

Implements the domain :class:`~ctf_generator.domain.execution.runtime.RuntimeBackend`
Protocol by driving the ``docker`` CLI through :mod:`subprocess` with argument
LISTS (never a shell string, never string-interpolated caller input). It is the
one place in the tree that runs challenge containers; it holds no control-plane
credentials and imports nothing from ``application``/``interfaces``.

Security posture translated to flags on every launch (see
:func:`policy_to_run_flags`):

* ``--user <non-root uid>``            (``run_as_non_root``)
* ``--cap-drop=ALL``                   (``drop_all_capabilities``)
* ``--security-opt no-new-privileges`` (``no_new_privileges``)
* ``--security-opt seccomp=<profile>`` -- a **hard floor**: if the daemon has
  seccomp disabled the launch is REFUSED (never silently run unconfined).
* ``--read-only`` + a size-capped ``--tmpfs`` for the one writable path
  (``read_only_rootfs`` / ``tmpfs_mb``)
* ``--memory`` / ``--memory-swap`` (swap disabled) / ``--cpus`` / ``--pids-limit``
* a DEDICATED per-instance network (``--internal`` for ``none``/``isolated``),
  and NEVER ``--pid=host`` / ``--ipc=host`` / ``--uts=host`` / ``--network=host``
  / ``--privileged``.

Host-capability honesty (ADR-004 requires a *rootless* runtime): this host may be
rootful, may lack a daemon user-namespace remap, and may lack AppArmor. Rather
than pretend, the adapter:

* refuses (``UnsupportedRuntimeError``) any hardening it genuinely cannot apply
  (e.g. seccomp disabled), and
* by default (``require_rootless=True`` / no ``acknowledged_gaps``) REFUSES to
  launch at all on a rootful daemon -- the secure production default. A
  single-host / verification deployment may pass an EXPLICIT, logged
  ``acknowledged_gaps`` set naming exactly the outer-layer capabilities the host
  lacks (``rootless`` / ``user_namespace`` / ``apparmor``); those gaps are
  surfaced on every launch result and documented in
  ``docs/security/runtime-isolation.md`` as unverified live paths. There is no
  silent relaxation: an unacknowledged gap always raises.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shlex
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field

from ctf_generator.domain.execution.runtime import (
    ContainerPolicy,
    ContainerRequest,
    RuntimeCapabilities,
    RuntimeEndpoint,
    RuntimeObservation,
    RuntimeResourceRef,
)

_LOG = logging.getLogger("ctf_generator.worker.runtime")

# Non-root uid/gid the workload runs as when the image would otherwise default to
# root. 65534 is the conventional ``nobody`` uid present in most base images.
DEFAULT_NON_ROOT_UID = 65534

# Labels stamped on every managed object so a crash-recovery sweep can find and
# reap our containers/networks without touching anything else on the host.
MANAGED_LABEL = "ctfgen.managed"
INSTANCE_LABEL = "ctfgen.instance"
# The owning worker name -- a reaper/recovery sweep is scoped to THIS worker's
# label so a multi-worker host never reaps another worker's live containers.
WORKER_LABEL = "ctfgen.worker"

# The firewall helper image: a minimal image carrying an ``iptables`` binary,
# run with ``--net=host --cap-add=NET_ADMIN`` to install the host-block rules in
# the host network namespace. It is built on demand from the embedded Dockerfile
# below (the base image must be pullable once). The host-block is a HARD FLOOR:
# if this control cannot be established, launch REFUSES (never runs with the
# host reachable). The image ships both iptables backends so the correct one for
# the host's docker rules (legacy vs nft) is auto-selected at detection time.
FIREWALL_IMAGE = "ctfgen-netfw:v1"
_FIREWALL_DOCKERFILE = (
    "FROM debian:stable-slim\n"
    "RUN apt-get update "
    "&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
    "iptables "
    "&& rm -rf /var/lib/apt/lists/*\n"
)
# iptables binaries probed, in order, to find the one that manipulates the same
# ruleset docker uses on this host (a DROP in the wrong backend would not block).
_FIREWALL_BINARIES = ("iptables-legacy", "iptables-nft", "iptables")
# A reserved, never-routed probe source used to prove we can add+delete a host
# INPUT rule before we trust the firewall control (RFC 6598-adjacent test net).
_FIREWALL_PROBE_SUBNET = "192.0.2.0/32"  # TEST-NET-1, never real traffic

# An iptables comment stamped on every host-block DROP rule we install. It is the
# DURABLE marker that lets a teardown/recovery sweep find and reclaim a leaked
# host-block rule by identity, even when the per-instance network it protected was
# removed OUT-OF-BAND (``docker network rm`` bypassing the backend) and its subnet
# can no longer be read from a live network. Reclaiming a stranded rule is
# fail-SAFE hygiene (a stranded DROP over-blocks a recycled subnet, it never opens
# a hole); the sweep only removes rules whose subnet no longer matches ANY existing
# ctfgen-managed network, so a rule still guarding a live network is preserved.
_HOSTBLOCK_COMMENT = "ctfgen-hostblock"

# The outer-layer hardenings a non-rootless host cannot provide. Each may be
# EXPLICITLY acknowledged (never silently); seccomp is deliberately absent -- it
# is a hard floor that can never be acknowledged away.
ACKNOWLEDGEABLE_GAPS = frozenset({"rootless", "user_namespace", "apparmor"})

_SLUG_RE = re.compile(r"[^a-z0-9-]+")


class DockerRuntimeError(RuntimeError):
    """A docker operation failed unexpectedly."""


class DockerCommandError(DockerRuntimeError):
    """A ``docker`` invocation exited non-zero. Carries the sanitized argv (never
    env/secrets) and captured stderr for diagnosis."""

    def __init__(self, argv: Sequence[str], returncode: int, stderr: str) -> None:
        self.argv = tuple(argv)
        self.returncode = returncode
        self.stderr = stderr.strip()
        super().__init__(
            f"docker {' '.join(argv[1:3])}... exited {returncode}: {self.stderr[:400]}"
        )


class UnsupportedRuntimeError(DockerRuntimeError):
    """A hardening the :class:`ContainerPolicy` requires cannot be applied on
    this host. Raised BEFORE anything is launched -- the adapter never silently
    runs a less-isolated container."""


def _slug(value: str, *, maxlen: int = 40) -> str:
    """Reduce an arbitrary identifier to a docker-safe ``[a-z0-9-]`` token. Used
    only for object NAMES/labels; identity is still carried verbatim in labels."""
    out = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return (out or "x")[:maxlen]


@dataclass(frozen=True)
class DockerHostProbe:
    """Raw, un-gated facts read from ``docker info`` / ``docker version``. Unlike
    :class:`RuntimeCapabilities` this NEVER refuses to represent a rootful host --
    it reports the truth so callers can gate honestly."""

    server_version: str
    architecture: str
    rootless: bool
    userns_remap: bool
    cgroup_version: str
    seccomp_enabled: bool
    apparmor_available: bool
    selinux_available: bool

    @property
    def supports_user_namespaces(self) -> bool:
        return self.rootless or self.userns_remap

    def missing_gaps(self, policy: ContainerPolicy) -> frozenset[str]:
        """The set of outer-layer hardenings this host cannot fully provide for
        ``policy`` (a subset of :data:`ACKNOWLEDGEABLE_GAPS`). Seccomp is NOT here
        -- a disabled seccomp is a hard refusal handled in
        :func:`policy_to_run_flags`."""
        gaps: set[str] = set()
        if not self.rootless:
            gaps.add("rootless")
        if policy.user_namespace and not self.supports_user_namespaces:
            gaps.add("user_namespace")
        if not self.apparmor_available and _apparmor_is_default(policy):
            gaps.add("apparmor")
        return frozenset(gaps)


@dataclass(frozen=True)
class LaunchResult:
    """The concrete adapter's launch return: the Protocol
    :class:`RuntimeObservation` view PLUS the per-instance runtime resources the
    worker persists (so a leak of a network/container is reap-able) and the
    acknowledged capability gaps in force for this launch (surfaced, never
    hidden). A caller wanting only the Protocol shape reads ``.observation``."""

    observation: RuntimeObservation
    runtime_resources: tuple[RuntimeResourceRef, ...] = ()
    endpoints: tuple[RuntimeEndpoint, ...] = ()
    acknowledged_gaps: frozenset[str] = field(default_factory=frozenset)


def _apparmor_is_default(policy: ContainerPolicy) -> bool:
    return policy.apparmor_profile.strip().lower() in ("runtime-default", "docker-default")


def policy_to_run_flags(
    policy: ContainerPolicy,
    probe: DockerHostProbe,
    *,
    non_root_uid: int = DEFAULT_NON_ROOT_UID,
) -> list[str]:
    """Translate a :class:`ContainerPolicy` into ``docker run`` flags for the
    given host. PURE (no subprocess), so it is unit-testable without docker.

    Raises :class:`UnsupportedRuntimeError` for a hardening that is a HARD floor
    and cannot be met (seccomp disabled, or a *named* non-default seccomp/apparmor
    profile the host cannot supply). Outer-layer gaps (rootless / user_namespace /
    apparmor-default-on-a-host-without-apparmor) are NOT raised here -- they are
    reported by :meth:`DockerHostProbe.missing_gaps` and gated by the caller.
    """
    flags: list[str] = [
        # Non-root + no-new-privileges + all caps dropped.
        "--user",
        f"{non_root_uid}:{non_root_uid}",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        # Read-only rootfs; the sole writable path is a size-capped, non-exec,
        # non-suid, non-dev tmpfs (defence in depth against dropping an executable
        # payload into a writable mount).
        "--read-only",
        "--tmpfs",
        # A docker --tmpfs mount spec (a container path), not a host temp file.
        # OWNED by the non-root uid/gid the workload runs as: under --read-only
        # this is the container's ONLY writable path, so a root:root tmpfs would
        # leave a uid-65534 process with nowhere to write. noexec/nosuid/nodev is
        # defence in depth against dropping an executable payload here.
        f"/tmp:rw,size={policy.tmpfs_mb}m,mode=1770,uid={non_root_uid},"  # noqa: S108
        f"gid={non_root_uid},noexec,nosuid,nodev",
        # Resource envelope. --memory-swap == --memory disables swap (no swap
        # escape past the memory cap). --cpus from milli-cpus. --pids-limit caps
        # fork-bombs.
        "--memory",
        f"{policy.memory_mb}m",
        "--memory-swap",
        f"{policy.memory_mb}m",
        "--cpus",
        f"{policy.cpu_millis / 1000:.3f}",
        "--pids-limit",
        str(policy.pids_limit),
    ]

    # -- seccomp: a HARD floor -------------------------------------------------
    if not probe.seccomp_enabled:
        raise UnsupportedRuntimeError(
            "policy requires a seccomp profile but the docker daemon reports "
            "seccomp is disabled; refusing to launch unconfined"
        )
    seccomp_name = policy.seccomp_profile.strip().lower()
    if seccomp_name in ("runtime-default", "docker-default"):
        # The daemon's builtin default profile applies automatically; asserting it
        # is active is done at runtime via /proc/self/status Seccomp==2.
        pass
    else:
        # A named custom profile must resolve to a file this host can supply.
        # Slice 2 ships no custom profile registry, so a named profile is refused
        # rather than silently downgraded to the default.
        raise UnsupportedRuntimeError(
            f"seccomp profile {policy.seccomp_profile!r} is not available on this "
            "host (no custom seccomp profile registry in slice 2)"
        )

    # -- apparmor: applied where supported, else a gated outer layer -----------
    if _apparmor_is_default(policy):
        if probe.apparmor_available:
            flags += ["--security-opt", "apparmor=docker-default"]
        # else: host has no AppArmor -> gap reported by missing_gaps(), gated.
    else:
        if not probe.apparmor_available:
            raise UnsupportedRuntimeError(
                f"apparmor profile {policy.apparmor_profile!r} requested but this "
                "host has no AppArmor"
            )
        flags += ["--security-opt", f"apparmor={policy.apparmor_profile}"]

    # Host-namespace sharing is forbidden by the policy VO; we simply never emit
    # --pid=host/--ipc=host/--uts=host/--network=host, and additionally pin
    # private ipc for defence in depth.
    flags += ["--ipc", "private"]
    return flags


class DockerRuntimeBackend:
    """A :class:`RuntimeBackend` driving the ``docker`` CLI.

    ``require_rootless`` (default True) is the secure production posture: a
    rootful daemon yields no valid :class:`RuntimeCapabilities` and a launch is
    refused. ``acknowledged_gaps`` is an EXPLICIT, operator-set allowance of the
    outer-layer capabilities a single-host/verification deployment knowingly
    runs without; any unacknowledged gap still raises. seccomp can never be
    acknowledged away.
    """

    def __init__(
        self,
        *,
        docker_path: str | None = None,
        non_root_uid: int = DEFAULT_NON_ROOT_UID,
        require_rootless: bool = True,
        acknowledged_gaps: frozenset[str] = frozenset(),
        run_timeout_seconds: int = 120,
        build_timeout_seconds: int = 600,
        max_image_mb: int = 2048,
        worker_name: str = "ctfgen",
        firewall_image: str = FIREWALL_IMAGE,
    ) -> None:
        bad = acknowledged_gaps - ACKNOWLEDGEABLE_GAPS
        if bad:
            raise ValueError(
                f"unknown acknowledged_gaps {sorted(bad)}; allowed "
                f"{sorted(ACKNOWLEDGEABLE_GAPS)}"
            )
        self._docker = docker_path or shutil.which("docker") or "docker"
        self._non_root_uid = non_root_uid
        self._require_rootless = require_rootless
        self._acknowledged = frozenset(acknowledged_gaps)
        self._run_timeout = run_timeout_seconds
        self._build_timeout = build_timeout_seconds
        self._max_image_mb = max_image_mb
        self._worker_name = worker_name
        self._firewall_image = firewall_image
        # Lazily-detected iptables binary that manipulates docker's ruleset on
        # this host (None once probed and found unavailable). The host-block is a
        # HARD FLOOR -- never acknowledged away.
        self._fw_binary: str | None = None
        self._fw_probed = False
        self._fw_image_ready = False

    # -- subprocess plumbing ---------------------------------------------------

    def _run(
        self, args: Sequence[str], *, timeout: int | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        """Run ``docker <args>`` with an argv list (never a shell). Raises
        :class:`DockerCommandError` on non-zero when ``check``. Never logs env or
        payloads; argv is safe (no secrets pass through the runtime driver)."""
        argv = [self._docker, *args]
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, no shell, trusted binary
                argv,
                capture_output=True,
                text=True,
                timeout=timeout if timeout is not None else self._run_timeout,
                check=False,
            )
        except FileNotFoundError as exc:  # pragma: no cover - env dependent
            raise DockerRuntimeError(f"docker binary not found: {self._docker}") from exc
        except subprocess.TimeoutExpired as exc:
            raise DockerRuntimeError(
                f"docker {' '.join(args[:2])} timed out after {exc.timeout}s"
            ) from exc
        if check and proc.returncode != 0:
            raise DockerCommandError(argv, proc.returncode, proc.stderr)
        return proc

    def is_available(self) -> bool:
        """Whether the docker CLI + daemon are reachable (a probe gate for tests)."""
        try:
            self._run(["version", "--format", "{{.Server.Version}}"], timeout=15)
            return True
        except DockerRuntimeError:
            return False

    # -- capability detection --------------------------------------------------

    def probe(self) -> DockerHostProbe:
        """Read raw host facts from ``docker info``/``version`` (never refuses to
        represent a rootful host)."""
        info = json.loads(
            self._run(["info", "--format", "{{json .}}"], timeout=30).stdout
        )
        version = json.loads(
            self._run(["version", "--format", "{{json .}}"], timeout=15).stdout
        )
        security = info.get("SecurityOptions") or []
        sec_text = " ".join(security).lower()
        rootless = any("rootless" in s.lower() for s in security)
        server = version.get("Server") or {}
        arch = server.get("Arch") or info.get("Architecture") or "unknown"
        return DockerHostProbe(
            server_version=info.get("ServerVersion", "unknown"),
            architecture=_normalize_arch(arch),
            rootless=rootless,
            userns_remap=_userns_active(info),
            cgroup_version=str(info.get("CgroupVersion", "unknown")),
            seccomp_enabled="seccomp" in sec_text,
            apparmor_available="apparmor" in sec_text,
            selinux_available="selinux" in sec_text,
        )

    def detect_capabilities(self) -> RuntimeCapabilities:
        """Probe the host and report what it can HONESTLY enforce as a
        :class:`RuntimeCapabilities`. Because that value object refuses to
        represent a non-rootless runtime (ADR-004), this RAISES
        :class:`UnsupportedRuntimeError` on a rootful daemon rather than
        certifying it -- the honest result on a host that is not a supported
        production runtime. Use :meth:`probe` for the un-gated facts."""
        probe = self.probe()
        if not probe.rootless:
            raise UnsupportedRuntimeError(
                "docker daemon is rootful; ADR-004 requires a rootless runtime, so "
                "this host yields no valid RuntimeCapabilities (see probe() for the "
                "raw facts)"
            )
        info = json.loads(
            self._run(["info", "--format", "{{json .}}"], timeout=30).stdout
        )
        mem_bytes = int(info.get("MemTotal") or 0)
        max_mb = max(1, mem_bytes // (1024 * 1024)) if mem_bytes else 512
        return RuntimeCapabilities(
            runtime_type="docker-rootless",
            rootless=True,
            supported_architectures=(probe.architecture,),
            supports_user_namespaces=probe.supports_user_namespaces,
            supports_seccomp=probe.seccomp_enabled,
            supports_readonly_rootfs=True,
            max_memory_mb=max_mb,
        )

    # -- gap gating ------------------------------------------------------------

    def _gate(self, policy: ContainerPolicy, probe: DockerHostProbe) -> frozenset[str]:
        """Compute the outer-layer gaps for this launch and enforce the
        acknowledgment contract. Returns the acknowledged gaps in force (for
        surfacing on the result); raises if any gap is unacknowledged or the host
        is rootful under ``require_rootless``."""
        gaps = probe.missing_gaps(policy)
        if self._require_rootless and "rootless" in gaps:
            raise UnsupportedRuntimeError(
                "docker daemon is rootful and require_rootless=True; refusing to "
                "launch (set an explicit acknowledged_gaps for a single-host "
                "verification deployment, and see docs/security/runtime-isolation.md)"
            )
        unacked = gaps - self._acknowledged
        if unacked:
            raise UnsupportedRuntimeError(
                f"policy requires hardenings this host cannot provide {sorted(unacked)} "
                f"and they are not in acknowledged_gaps {sorted(self._acknowledged)}; "
                "refusing to launch a less-isolated container"
            )
        return gaps

    # -- host-block firewall (a HARD FLOOR for isolated networks) ---------------
    #
    # A docker ``--internal`` per-instance network still lets a container reach
    # HOST-bound services: the bridge gateway IS the host, and container->gateway
    # traffic is delivered to the host's INPUT chain (not FORWARD), which
    # ``--internal`` does not block. We therefore install an explicit
    # ``INPUT -s <instance-subnet> -j DROP`` (blocks the container reaching ANY
    # host IP, gateway included) plus a best-effort ``DOCKER-USER`` forward DROP
    # (defence in depth for metadata/other-subnet reachability) BEFORE the
    # container is started -- so there is no window in which hostile code can
    # reach the host. If this control cannot be established the launch is
    # REFUSED; the host-block is never "acknowledged away".

    def _ensure_firewall_image(self) -> bool:
        """Ensure the firewall helper image exists (build it once from the
        embedded Dockerfile if absent). Returns True iff the image is present."""
        if self._fw_image_ready:
            return True
        present = self._run(
            ["image", "inspect", "--format", "{{.Id}}", self._firewall_image],
            check=False,
        )
        if present.returncode == 0 and present.stdout.strip():
            self._fw_image_ready = True
            return True
        # Build from stdin so no scratch dir is needed. Network IS required (apt).
        try:
            argv = [self._docker, "build", "--tag", self._firewall_image, "-"]
            proc = subprocess.run(  # noqa: S603 - argv list, no shell, trusted binary
                argv,
                input=_FIREWALL_DOCKERFILE,
                capture_output=True,
                text=True,
                timeout=self._build_timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if proc.returncode != 0:
            _LOG.warning("firewall helper image build failed rc=%s", proc.returncode)
            return False
        self._fw_image_ready = True
        return True

    def _fw_exec(
        self, binary: str, ip_args: Sequence[str], *, check: bool
    ) -> subprocess.CompletedProcess[str]:
        """Run one iptables verb in the HOST network namespace via the helper
        container (``--net=host --cap-add=NET_ADMIN``)."""
        return self._run(
            [
                "run",
                "--rm",
                "--net=host",
                "--cap-add=NET_ADMIN",
                self._firewall_image,
                binary,
                *ip_args,
            ],
            check=check,
            timeout=60,
        )

    def _detect_firewall_backend(self) -> str | None:
        """Find the iptables binary that manipulates docker's ruleset on this
        host by proving we can ADD then DELETE a host ``INPUT`` DROP rule for a
        reserved test subnet. Cached; returns None if no backend works (=> the
        host-block cannot be enforced => launch will refuse)."""
        if self._fw_probed:
            return self._fw_binary
        self._fw_probed = True
        self._fw_binary = None
        if not self._ensure_firewall_image():
            return None
        probe = ["INPUT", "-s", _FIREWALL_PROBE_SUBNET, "-j", "DROP"]
        for binary in _FIREWALL_BINARIES:
            added = self._fw_exec(binary, ["-I", *probe], check=False)
            if added.returncode != 0:
                continue
            # It added -- prove we can also remove it (and clean up the probe).
            removed = self._fw_exec(binary, ["-D", *probe], check=False)
            if removed.returncode == 0:
                self._fw_binary = binary
                return binary
            # Could add but not delete: unusable (would leak). Best-effort clean.
            self._fw_exec(binary, ["-D", *probe], check=False)
        return None

    def firewall_available(self) -> bool:
        """Whether the host-block firewall control can be enforced on this host."""
        return self._detect_firewall_backend() is not None

    def _host_block_rules(self, subnet: str) -> tuple[tuple[str, list[str]], ...]:
        # Every rule carries the ctfgen-hostblock comment so a leaked rule can be
        # reclaimed by identity even after its network is gone (see _sweep_orphan_
        # host_blocks). The comment is a no-op match -- it does not change what the
        # rule drops.
        tag = ["-m", "comment", "--comment", _HOSTBLOCK_COMMENT]
        return (
            # Critical: container -> any host IP (the gateway IS the host, and its
            # IP is in-subnet) arrives on the host INPUT chain, which docker's
            # --internal (a FORWARD control) never blocks. Drop ALL traffic from
            # the subnet to the host.
            ("required", ["INPUT", "-s", subnet, *tag, "-j", "DROP"]),
            # Defence in depth: drop forwarded traffic LEAVING the subnet
            # (metadata / other subnets / internet) while permitting intra-subnet
            # container-to-container traffic (``! -d subnet``) so legitimate
            # multi-container instances still talk. Without the ``! -d`` guard a
            # bridge-nf host would also drop same-instance peer traffic.
            (
                "best_effort",
                ["DOCKER-USER", "-s", subnet, "!", "-d", subnet, *tag, "-j", "DROP"],
            ),
        )

    def _install_host_block(self, subnet: str) -> None:
        """Install the host-block DROP rules for ``subnet`` (idempotent via a
        ``-C`` existence check). Refuses (raises) if the REQUIRED INPUT rule
        cannot be installed -- the caller must not launch with the host reachable."""
        binary = self._detect_firewall_backend()
        if binary is None:
            raise UnsupportedRuntimeError(
                "host-block firewall control is unavailable on this host "
                "(no working iptables backend / NET_ADMIN); refusing to launch an "
                "isolated container that could reach the host"
            )
        for level, rule in self._host_block_rules(subnet):
            present = self._fw_exec(binary, ["-C", *rule], check=False)
            if present.returncode == 0:
                continue
            added = self._fw_exec(binary, ["-I", *rule], check=False)
            if added.returncode != 0:
                if level == "required":
                    raise UnsupportedRuntimeError(
                        f"failed to install required host-block INPUT DROP for "
                        f"{subnet}; refusing to launch (rc={added.returncode})"
                    )
                _LOG.warning(
                    "best-effort host-block rule %s not installed", rule[0]
                )

    def _remove_host_block(self, subnet: str) -> None:
        """Remove the host-block DROP rules for ``subnet`` (idempotent: a missing
        rule is not an error). A leaked rule is fail-SAFE (blocks more, never
        less) but we remove it so a recycled subnet starts clean."""
        binary = self._fw_binary or self._detect_firewall_backend()
        if binary is None:
            return
        for _level, rule in self._host_block_rules(subnet):
            # Delete repeatedly in case a rule was inserted more than once.
            for _ in range(4):
                out = self._fw_exec(binary, ["-D", *rule], check=False)
                if out.returncode != 0:
                    break

    def _managed_network_subnets(self) -> set[str]:
        """Subnets of every ctfgen-managed network that CURRENTLY exists (across
        all workers). A host-block guarding any of these is live and must be
        preserved by :meth:`_sweep_orphan_host_blocks`."""
        names = self._run(
            [
                "network",
                "ls",
                "--filter",
                f"label={MANAGED_LABEL}=true",
                "--format",
                "{{.Name}}",
            ],
            check=False,
        ).stdout.split()
        subnets: set[str] = set()
        for name in names:
            subnet = self._network_subnet(name)
            if subnet:
                subnets.add(subnet)
        return subnets

    def _sweep_orphan_host_blocks(self) -> None:
        """Reclaim leaked host-block DROP rules by their ctfgen-hostblock comment,
        independent of whether the network they guarded still exists. This closes
        the leak where a per-instance network removed OUT-OF-BAND (``docker network
        rm`` bypassing the backend) strands its INPUT/DOCKER-USER rule -- the normal
        teardown reads the subnet from the LIVE network, so once the network is gone
        the rule can no longer be matched by subnet.

        A rule is removed ONLY when its ``-s`` subnet matches NO existing ctfgen
        network, so a rule still guarding a live network (possibly another worker's)
        is never dropped -- removing a live network's block would open a hole, which
        this must never do."""
        binary = self._fw_binary or self._detect_firewall_backend()
        if binary is None:
            return
        live = self._managed_network_subnets()
        for chain in ("INPUT", "DOCKER-USER"):
            listed = self._fw_exec(binary, ["-S", chain], check=False)
            if listed.returncode != 0:
                continue
            for line in listed.stdout.splitlines():
                if _HOSTBLOCK_COMMENT not in line:
                    continue
                parts = shlex.split(line)
                if len(parts) < 2 or parts[0] != "-A":
                    continue
                subnet = _rule_source(parts)
                if subnet is not None and subnet in live:
                    continue  # still guards a live network -- keep it
                # Convert the "-A <chain> ..." listing into a "-D <chain> ..." delete.
                self._fw_exec(binary, ["-D", *parts[1:]], check=False)

    def _network_subnet(self, network_name: str) -> str | None:
        out = self._run(
            [
                "network",
                "inspect",
                "--format",
                "{{range .IPAM.Config}}{{.Subnet}}{{end}}",
                network_name,
            ],
            check=False,
        )
        subnet = out.stdout.strip()
        return subnet or None

    # -- build -----------------------------------------------------------------

    def build_image(
        self,
        *,
        context_dir: str,
        tag: str,
        dockerfile: str | None = None,
        network: bool = False,
    ) -> str:
        """Build an image from ``context_dir`` and return its content-addressed
        digest (``sha256:...``). Build isolation (WORKER-only; the control plane
        never builds):

        * ``--network=none`` by default -- a build must not reach the network
          (the base image must already be present locally). Pass ``network=True``
          only for a build that legitimately fetches, on an egress-restricted
          builder.
        * ``--force-rm`` discards intermediate containers; ``--pull=false`` keeps
          the build from silently re-fetching a mutable base.
        * NO ``--build-arg`` / secrets are accepted here -- provider keys, flags,
          and session tokens are never present in the build environment (and
          never logged).
        * a build TIMEOUT bounds a hung build, and the resulting image is checked
          against ``max_image_mb`` (an oversized image is removed and refused).

        Rootless BuildKit is used when the daemon reports rootless; otherwise the
        classic builder runs with these isolation flags (a documented fallback on
        a rootful host -- see docs/security/runtime-isolation.md).
        """
        args = ["build", "--force-rm", "--pull=false", "--tag", tag]
        if not network:
            args += ["--network", "none"]
        if dockerfile:
            args += ["--file", dockerfile]
        args.append(context_dir)
        self._run(args, timeout=self._build_timeout)

        size_bytes = int(
            self._run(
                ["image", "inspect", "--format", "{{.Size}}", tag], check=False
            ).stdout.strip()
            or 0
        )
        if size_bytes > self._max_image_mb * 1024 * 1024:
            self._run(["image", "rm", "--force", tag], check=False)
            raise UnsupportedRuntimeError(
                f"built image {tag!r} is {size_bytes // (1024 * 1024)}MB, over the "
                f"{self._max_image_mb}MB ceiling; removed and refused"
            )
        digest = self._run(
            ["image", "inspect", "--format", "{{.Id}}", tag], check=False
        ).stdout.strip()
        return digest

    # -- network ---------------------------------------------------------------

    def _name_hash(self, instance_id: str) -> str:
        """A short collision-resistant suffix from the FULL instance_id, so two
        instances whose slugs collide after truncation still get distinct object
        names."""
        return hashlib.sha256(instance_id.encode("utf-8")).hexdigest()[:10]

    def _network_name(self, instance_id: str) -> str:
        return f"ctfgen-net-{_slug(instance_id, maxlen=36)}-{self._name_hash(instance_id)}"

    def _container_name(self, instance_id: str) -> str:
        return f"ctfgen-inst-{_slug(instance_id, maxlen=36)}-{self._name_hash(instance_id)}"

    def _ensure_network(self, request: ContainerRequest) -> tuple[str, str]:
        """Create the DEDICATED per-instance ``--internal`` network (idempotent)
        and install the host-block firewall for its subnet. Returns
        ``(network_name, network_id)``.

        For ``isolated`` the network is ``--internal`` (no route off the network:
        no cross-instance path, no host/DB/metadata reachability) AND a host-block
        DROP is installed for its subnet BEFORE the container starts (docker's
        ``--internal`` alone does NOT block container->host, so this is required
        to keep the container off the host). On reuse the existing network's
        ``Internal`` flag and instance label are verified -- a mismatch is
        recreated so a posture drift cannot silently weaken isolation. ``egress``
        is refused upstream, so this only ever builds an internal network."""
        name = self._network_name(request.instance_id)
        existing = self._run(
            ["network", "ls", "--filter", f"name=^{name}$", "--format", "{{.ID}}"],
            check=False,
        ).stdout.strip()
        if existing and self._network_posture_ok(name, request.instance_id):
            # Re-assert the host-block (idempotent) in case a prior run leaked it.
            subnet = self._network_subnet(name)
            if subnet:
                self._install_host_block(subnet)
            return name, existing
        if existing:
            # Posture drift (wrong Internal flag / label) -> recreate clean.
            _LOG.warning("recreating network %s: isolation posture mismatch", name)
            self._remove_network(name)
        args = [
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--label",
            f"{MANAGED_LABEL}=true",
            "--label",
            f"{INSTANCE_LABEL}={request.instance_id}",
            "--label",
            f"{WORKER_LABEL}={self._worker_name}",
            name,
        ]
        net_id = self._run(args).stdout.strip()
        subnet = self._network_subnet(name)
        if not subnet:
            self._remove_network(name)
            raise DockerRuntimeError(
                f"could not read subnet for network {name}; refusing to launch "
                "without a host-block"
            )
        try:
            self._install_host_block(subnet)
        except UnsupportedRuntimeError:
            # Roll back the network so a refused launch leaks nothing.
            self._remove_network(name)
            raise
        return name, net_id

    def _network_posture_ok(self, network_name: str, instance_id: str) -> bool:
        out = self._run(
            [
                "network",
                "inspect",
                "--format",
                "{{.Internal}}|{{index .Labels \"" + INSTANCE_LABEL + "\"}}",
                network_name,
            ],
            check=False,
        )
        if out.returncode != 0:
            return False
        internal, _, label = out.stdout.strip().partition("|")
        return internal.lower() == "true" and label == instance_id

    # -- launch ----------------------------------------------------------------

    def launch(
        self, request: ContainerRequest, *, command: Sequence[str] | None = None
    ) -> LaunchResult:
        """Create the per-instance network and start ONE policy-constrained
        container. ``command`` overrides the image entrypoint (production images
        carry their own long-running CMD; tests pass a benign ``sleep``). Returns
        a :class:`LaunchResult` (Protocol observation + resources to persist +
        the acknowledged gaps in force). Refuses via :class:`UnsupportedRuntimeError`
        BEFORE creating anything if a required hardening cannot be met."""
        mode = request.policy.network_mode
        if mode == "egress":
            # Egress-restriction (default-deny + destination allowlist +
            # unconditional metadata/host DROP) is a larger build not landed yet.
            # A plain NAT bridge would reach the internet, the host, and (on
            # cloud) the metadata endpoint despite claiming "egress-restricted".
            # Refuse loudly rather than ship a mode that lies about its posture.
            raise UnsupportedRuntimeError(
                "network_mode 'egress' is not implemented -- egress restriction "
                "(filtering proxy / destination allowlist + metadata+host DROP) "
                "is unsafe to fake; refusing (see docs/security/runtime-isolation.md)"
            )
        probe = self.probe()
        acked = self._gate(request.policy, probe)
        # Compute flags up front so a hard-floor refusal happens before any docker
        # object is created.
        hardening = policy_to_run_flags(
            request.policy, probe, non_root_uid=self._non_root_uid
        )
        # The host-block firewall is a HARD FLOOR for an isolated network: if the
        # host cannot enforce it, refuse BEFORE creating anything (never launch a
        # container that can reach the host). ``none`` needs no network at all.
        if mode == "isolated" and not self.firewall_available():
            raise UnsupportedRuntimeError(
                "an isolated network requires an enforceable host-block firewall "
                "but this host has none (no working iptables backend / NET_ADMIN); "
                "refusing to launch"
            )

        resources_list: list[RuntimeResourceRef] = []
        network_name: str | None = None
        if mode == "none":
            # docker's built-in 'none' net has no interfaces at all -> the
            # container cannot reach anything; the bespoke per-instance network is
            # unused, so it is skipped entirely (no network RuntimeResource).
            network_ref = "none"
        else:
            network_name, network_id = self._ensure_network(request)
            network_ref = network_name
            resources_list.append(RuntimeResourceRef("network", network_id))

        container_name = self._container_name(request.instance_id)
        args: list[str] = [
            "run",
            "-d",
            "--name",
            container_name,
            "--network",
            network_ref,
            "--label",
            f"{MANAGED_LABEL}=true",
            "--label",
            f"{INSTANCE_LABEL}={request.instance_id}",
            "--label",
            f"{WORKER_LABEL}={self._worker_name}",
            "--restart",
            "no",
        ]
        args += hardening
        # Isolated/none instances are reachable only inside their network (ingress
        # via the reverse proxy is M9); they never publish a host port.
        for port in request.exposed_ports:
            args += ["--expose", str(port)]
        for key, value in request.labels:
            args += ["--label", f"{key}={value}"]
        args.append(request.image_ref)
        if command:
            args += list(command)

        try:
            container_id = self._run(args).stdout.strip()
        except DockerCommandError:
            # Roll back the network + host-block we just created so a failed launch
            # leaks nothing.
            if network_name is not None:
                self._remove_network(network_name)
            raise

        resources = (
            RuntimeResourceRef("container", container_id),
            *resources_list,
        )
        endpoints = self._endpoints(request, container_id, network_name, publish=False)
        observation = self.observe(request.instance_id, container_id)
        _LOG.info(
            "launched instance=%s container=%s network=%s gaps=%s",
            _slug(request.instance_id),
            container_id[:12],
            network_name,
            sorted(acked),
        )
        return LaunchResult(
            observation=observation,
            runtime_resources=resources,
            endpoints=endpoints,
            acknowledged_gaps=acked,
        )

    def _endpoints(
        self,
        request: ContainerRequest,
        container_id: str,
        network_name: str | None,
        publish: bool,
    ) -> tuple[RuntimeEndpoint, ...]:
        # publish is always False now (no host-port publishing; ingress is M9's
        # reverse proxy). A ``none``-network container has no reachable address.
        eps: list[RuntimeEndpoint] = []
        if network_name is None:
            return ()
        ip = self._container_ip(container_id, network_name)
        for port in request.exposed_ports:
            if ip:
                eps.append(
                    RuntimeEndpoint(container_port=port, host=ip, host_port=port)
                )
        return tuple(eps)

    def _container_ip(self, container_id: str, network_name: str) -> str | None:
        out = self._run(
            [
                "inspect",
                "--format",
                f"{{{{(index .NetworkSettings.Networks \"{network_name}\").IPAddress}}}}",
                container_id,
            ],
            check=False,
        ).stdout.strip()
        return out or None

    # -- lifecycle ops ---------------------------------------------------------

    def stop(self, instance_id: str, container_id: str, *, timeout: int = 10) -> None:
        """Stop a running container (idempotent -- a gone container is not an
        error)."""
        self._run(
            ["stop", "--time", str(timeout), container_id], check=False, timeout=timeout + 30
        )

    def restart(self, instance_id: str, container_id: str, *, timeout: int = 10) -> None:
        self._run(
            ["restart", "--time", str(timeout), container_id],
            check=False,
            timeout=timeout + 30,
        )

    def observe(
        self, instance_id: str, container_id: str | None
    ) -> RuntimeObservation:
        """Report the observed state of one instance's container as a domain
        :class:`RuntimeObservation`."""
        if not container_id:
            return RuntimeObservation(instance_id, None, "absent")
        out = self._run(
            ["inspect", "--format", "{{json .State}}", container_id],
            check=False,
        )
        if out.returncode != 0:
            return RuntimeObservation(instance_id, None, "absent", detail="not found")
        state = json.loads(out.stdout or "{}")
        running = "true" if state.get("Running") else "false"
        status = str(state.get("Status", ""))
        # ``Health`` is only present when the image declares a HEALTHCHECK.
        health = str((state.get("Health") or {}).get("Status", ""))
        phase = _map_phase(running, status, health)
        return RuntimeObservation(
            instance_id, container_id, phase, detail=f"status={status} health={health}"
        )

    def health_check(self, instance_id: str, container_id: str) -> RuntimeObservation:
        """A liveness probe: the container is healthy when it is running (and, if
        the image declares a HEALTHCHECK, when that reports healthy)."""
        return self.observe(instance_id, container_id)

    def collect_logs(self, instance_id: str, container_id: str, *, tail: int = 2000) -> str:
        """Capture the container's logs and return them (the worker persists them
        to a storage ref; raw logs may carry challenge output so they are never
        logged here)."""
        out = self._run(
            ["logs", "--tail", str(tail), container_id], check=False, timeout=30
        )
        return out.stdout + out.stderr

    def remove(self, instance_id: str, container_id: str | None) -> None:
        """FORCE-remove the container, then its per-instance network (and its
        host-block firewall rules) and any anonymous volumes. Idempotent: safe to
        call twice, safe if already gone -- so a re-run after a partial failure
        converges to clean."""
        if container_id:
            self._run(["rm", "--force", "--volumes", container_id], check=False)
        # Also sweep by label in case the container id was lost but objects leaked.
        self._remove_by_label(instance_id)
        self._remove_network(self._network_name(instance_id))

    def destroy(self, instance_id: str, container_id: str | None = None) -> None:
        """Alias for :meth:`remove` (the design's ``destroy`` verb)."""
        self.remove(instance_id, container_id)

    def find_container(self, instance_id: str) -> str | None:
        """Return the id of THIS worker's container for ``instance_id`` (scoped by
        the worker label so a multi-worker host never returns a peer's container),
        or None. Keeps the ``docker ps`` verb inside the backend."""
        out = self._run(
            [
                "ps",
                "-aq",
                "--filter",
                f"label={INSTANCE_LABEL}={instance_id}",
                "--filter",
                f"label={WORKER_LABEL}={self._worker_name}",
            ],
            check=False,
        ).stdout.split()
        return out[0] if out else None

    def reap_managed(self, worker: str | None = None) -> int:
        """Force-remove every ctfgen-managed container owned by ``worker``
        (defaults to THIS backend's worker), and their per-instance networks +
        host-blocks. Scoped by the worker label so a crash-recovery sweep on a
        multi-worker host never touches another worker's live containers. Returns
        the count reaped."""
        owner = worker or self._worker_name
        ids = self._run(
            [
                "ps",
                "-aq",
                "--filter",
                f"label={MANAGED_LABEL}=true",
                "--filter",
                f"label={WORKER_LABEL}={owner}",
            ],
            check=False,
        ).stdout.split()
        for cid in ids:
            self._run(["rm", "--force", "--volumes", cid], check=False)
        # Sweep this worker's leaked per-instance networks (and their host-blocks).
        nets = self._run(
            [
                "network",
                "ls",
                "--filter",
                f"label={MANAGED_LABEL}=true",
                "--filter",
                f"label={WORKER_LABEL}={owner}",
                "--format",
                "{{.Name}}",
            ],
            check=False,
        ).stdout.split()
        for name in nets:
            self._remove_network(name)
        # Reclaim any host-block rule stranded by a network removed out-of-band
        # (its subnet is no longer readable, so the per-network teardown above
        # cannot have matched it). Fail-safe: only orphan rules are removed.
        self._sweep_orphan_host_blocks()
        return len(ids)

    def _remove_by_label(self, instance_id: str) -> None:
        ids = self._run(
            [
                "ps",
                "-aq",
                "--filter",
                f"label={INSTANCE_LABEL}={instance_id}",
                "--filter",
                f"label={WORKER_LABEL}={self._worker_name}",
            ],
            check=False,
        ).stdout.split()
        for cid in ids:
            self._run(["rm", "--force", "--volumes", cid], check=False)

    def _remove_network(self, network_name: str) -> None:
        # Tear down the host-block for this network's subnet BEFORE removing the
        # network (once the network is gone its subnet is unknown). Idempotent.
        subnet = self._network_subnet(network_name)
        if subnet:
            self._remove_host_block(subnet)
        self._run(["network", "rm", network_name], check=False)


# -- module helpers -----------------------------------------------------------


def _rule_source(parts: Sequence[str]) -> str | None:
    """The value following ``-s`` in an ``iptables -S`` rule token list, or None."""
    for idx, arg in enumerate(parts):
        if arg == "-s" and idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _normalize_arch(arch: str) -> str:
    a = arch.strip().lower()
    return {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(a, a or "unknown")


def _userns_active(info: dict) -> bool:
    opts = info.get("SecurityOptions") or []
    return any("name=userns" in o.lower() for o in opts)


def _map_phase(running: str, status: str, health: str) -> str:
    if running.lower() == "true":
        h = health.lower()
        if h == "unhealthy":
            return "unhealthy"
        # When the image declares a HEALTHCHECK, a running-but-not-yet-healthy
        # container ('starting' or an empty status before the first probe) is
        # still coming up: report 'starting', not 'running'. Only a genuine
        # 'healthy' (or an image with NO healthcheck at all) is 'running'.
        if h in ("starting", ""):
            return "running" if not health else "starting"
        return "running"
    if status.lower() in ("created", "restarting"):
        return "starting"
    if status.lower() == "exited":
        return "exited"
    return "unknown"
