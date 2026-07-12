"""Runtime-backend contract & secure container policy (M8, INTERFACE ONLY).

This module DEFINES -- it does not implement -- the seam between the execution
plane and a container runtime. The concrete rootless adapter and the standalone
worker executable are slice 2; here we fix the interface (a
:class:`RuntimeBackend` Protocol), the secure-by-construction policy value
object (:class:`ContainerPolicy`), and the capability-detection type
(:class:`RuntimeCapabilities`) so slice 2 cannot weaken them to avoid the
real-container verification.

Security invariants encoded here (never relaxable through this API):

* The control plane never executes challenge code and never mounts a container
  socket -- so nothing in this module touches ``docker``/``subprocess``; it is a
  pure Protocol + value types the worker programs against with scoped
  credentials.
* Every launched container is rootless, non-root, no-new-privileges, with a
  read-only root filesystem, all Linux capabilities dropped, and per-team
  network isolation. :class:`ContainerPolicy` refuses to represent a weaker
  posture -- a privileged / writable-rootfs / cap-granting policy is
  unconstructible.
* Payloads/labels/env references carry references only -- never flags, tokens,
  or credentials (the flag is injected by the worker from a scoped secret at
  launch, out of band of the control-plane record).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Per-team network isolation postures. ``none`` = no network at all; ``isolated``
# = a per-instance private network with no cross-instance reachability (the
# default for interactive challenges); ``egress`` = isolated plus controlled
# outbound (only for the rare family that declares ``requires_internet``).
VALID_NETWORK_MODES = frozenset({"none", "isolated", "egress"})

# Container runtimes the execution plane supports (rootless only; mirrors
# ``domain.execution.models.VALID_RUNTIME_TYPES``).
VALID_RUNTIME_TYPES = frozenset(
    {"docker-rootless", "podman-rootless", "buildkit-rootless"}
)

# Phases a worker can report for an observed container.
VALID_OBSERVED_PHASES = frozenset(
    {"absent", "starting", "running", "unhealthy", "exited", "unknown"}
)


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_positive(value: int, field_name: str) -> None:
    if not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be an int >= 1, got {value!r}")


@dataclass(frozen=True)
class ContainerPolicy:
    """The secure container posture the worker MUST apply to every instance.

    Secure by construction: the hardening flags are fixed ``True`` and
    ``privileged`` is fixed ``False`` -- attempting to build a weaker policy
    raises. Only the resource envelope (memory / cpu / pids / tmpfs), the
    network posture, and the profile names are caller-tunable, and each is
    bounds-checked. A worker adapter that ignores these fields is a slice-2 bug
    the real-container conformance test catches; the *contract* is fixed here.
    """

    memory_mb: int
    cpu_millis: int
    pids_limit: int = 256
    tmpfs_mb: int = 64
    network_mode: str = "isolated"
    seccomp_profile: str = "runtime-default"
    apparmor_profile: str = "runtime-default"
    # Hardening switches -- fixed at their only secure value; present as fields so
    # a reviewer sees the full posture in one object and a test can assert it.
    read_only_rootfs: bool = True
    drop_all_capabilities: bool = True
    no_new_privileges: bool = True
    run_as_non_root: bool = True
    user_namespace: bool = True
    privileged: bool = False

    def __post_init__(self) -> None:
        _require_positive(self.memory_mb, "memory_mb")
        _require_positive(self.cpu_millis, "cpu_millis")
        _require_positive(self.pids_limit, "pids_limit")
        if not isinstance(self.tmpfs_mb, int) or self.tmpfs_mb < 0:
            raise ValueError(f"tmpfs_mb must be an int >= 0, got {self.tmpfs_mb!r}")
        if self.network_mode not in VALID_NETWORK_MODES:
            raise ValueError(
                f"network_mode must be one of {sorted(VALID_NETWORK_MODES)}, "
                f"got {self.network_mode!r}"
            )
        _require_nonempty(self.seccomp_profile, "seccomp_profile")
        _require_nonempty(self.apparmor_profile, "apparmor_profile")
        # The security floor: none of these may be relaxed through this VO.
        if self.privileged:
            raise ValueError("privileged containers are forbidden by policy")
        for flag_name in (
            "read_only_rootfs",
            "drop_all_capabilities",
            "no_new_privileges",
            "run_as_non_root",
            "user_namespace",
        ):
            if getattr(self, flag_name) is not True:
                raise ValueError(f"{flag_name} may not be disabled by policy")


@dataclass(frozen=True)
class RuntimeCapabilities:
    """What a runtime backend reports it can honestly provide (the
    capability-detection result a worker self-reports at enrollment / probe
    time). The scheduler never trusts a worker beyond what a probe like this
    confirms."""

    runtime_type: str
    rootless: bool
    supported_architectures: tuple[str, ...]
    supports_user_namespaces: bool
    supports_seccomp: bool
    supports_readonly_rootfs: bool
    max_memory_mb: int

    def __post_init__(self) -> None:
        if self.runtime_type not in VALID_RUNTIME_TYPES:
            raise ValueError(
                f"runtime_type must be one of {sorted(VALID_RUNTIME_TYPES)}, "
                f"got {self.runtime_type!r}"
            )
        if not self.rootless:
            raise ValueError("only rootless runtimes are supported (ADR-004)")
        if not isinstance(self.supported_architectures, tuple) or not self.supported_architectures:
            raise ValueError("supported_architectures must be a non-empty tuple")
        for arch in self.supported_architectures:
            _require_nonempty(arch, "supported_architectures entry")
        _require_positive(self.max_memory_mb, "max_memory_mb")

    def satisfies(self, policy: ContainerPolicy) -> bool:
        """Whether a runtime with these capabilities can enforce ``policy`` --
        the guard the worker checks before accepting a launch (a runtime lacking
        seccomp or user namespaces must refuse a policy that requires them)."""
        if policy.user_namespace and not self.supports_user_namespaces:
            return False
        if policy.read_only_rootfs and not self.supports_readonly_rootfs:
            return False
        if not self.supports_seccomp:
            return False
        return policy.memory_mb <= self.max_memory_mb


@dataclass(frozen=True)
class ContainerRequest:
    """A single instance launch request handed to the runtime backend. Carries
    references only: ``image_ref`` (a build-artifact / registry reference),
    the per-instance ``instance_id`` and owning ``team_key`` (for per-team
    network naming/isolation), the :class:`ContainerPolicy`, the ports to
    expose, and opaque ``labels`` for reconciliation. No secrets."""

    instance_id: str
    team_key: str
    image_ref: str
    policy: ContainerPolicy
    exposed_ports: tuple[int, ...] = ()
    labels: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty(self.instance_id, "instance_id")
        _require_nonempty(self.team_key, "team_key")
        _require_nonempty(self.image_ref, "image_ref")
        if not isinstance(self.policy, ContainerPolicy):
            raise ValueError("policy must be a ContainerPolicy")
        for port in self.exposed_ports:
            if not isinstance(port, int) or not (1 <= port <= 65535):
                raise ValueError(f"exposed_ports entries must be 1..65535, got {port!r}")


@dataclass(frozen=True)
class RuntimeEndpoint:
    """A reachable address a launched container publishes (host:port for one
    exposed container port)."""

    container_port: int
    host: str
    host_port: int

    def __post_init__(self) -> None:
        for port_name, port in (
            ("container_port", self.container_port),
            ("host_port", self.host_port),
        ):
            if not isinstance(port, int) or not (1 <= port <= 65535):
                raise ValueError(f"{port_name} must be 1..65535, got {port!r}")
        _require_nonempty(self.host, "host")


@dataclass(frozen=True)
class RuntimeObservation:
    """What the backend reports observing about one container: its runtime id,
    liveness/health phase, and published endpoints. This is the observed-state
    input the reconciler folds against desired state (a worker reports it; the
    control plane never inspects a container itself)."""

    instance_id: str
    container_id: str | None
    phase: str  # one of VALID_OBSERVED_PHASES
    endpoints: tuple[RuntimeEndpoint, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.instance_id, "instance_id")
        if self.container_id is not None:
            _require_nonempty(self.container_id, "container_id")
        if self.phase not in VALID_OBSERVED_PHASES:
            raise ValueError(
                f"phase must be one of {sorted(VALID_OBSERVED_PHASES)}, "
                f"got {self.phase!r}"
            )


@runtime_checkable
class RuntimeBackend(Protocol):
    """The container-runtime seam a worker's concrete adapter implements in
    slice 2. Interface only: no method here has an implementation, and no
    control-plane code ever calls it (the control plane persists desired state
    and enqueues jobs; the worker owns the socket). Implementations must apply
    the :class:`ContainerPolicy` verbatim and must never run privileged."""

    def detect_capabilities(self) -> RuntimeCapabilities:
        """Probe the local runtime and report what it can honestly enforce."""
        ...

    def launch(self, request: ContainerRequest) -> RuntimeObservation:
        """Create and start one policy-constrained container; report it."""
        ...

    def stop(self, instance_id: str, container_id: str) -> None:
        """Stop a running container (idempotent)."""
        ...

    def remove(self, instance_id: str, container_id: str) -> None:
        """Remove a container and its per-instance runtime resources (network,
        volumes) -- idempotent, so a re-run after a partial failure converges."""
        ...

    def observe(self, instance_id: str, container_id: str | None) -> RuntimeObservation:
        """Report the current observed state of one instance's container."""
        ...

    def collect_logs(self, instance_id: str, container_id: str) -> str:
        """Capture the container's logs to a storage reference and return the
        reference (never the raw logs, which may contain challenge output)."""
        ...
