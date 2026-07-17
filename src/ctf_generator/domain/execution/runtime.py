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

from collections.abc import Sequence
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
    # Host-namespace prohibition -- sharing the host PID/IPC/UTS namespace with a
    # challenge container defeats the isolation floor, so each is fixed False and
    # part of the contract slice 2 must honor (validated exactly like
    # ``privileged``: unconstructible when True).
    host_pid_namespace: bool = False
    host_ipc_namespace: bool = False
    host_uts_namespace: bool = False

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
        # ``seccomp_profile`` / ``apparmor_profile`` are profile NAMES the worker
        # applies, with a secure floor: a profile that *disables* confinement is
        # unrepresentable. (Stronger still would be an allowlist -- e.g.
        # ``{'runtime-default'}`` plus explicitly-registered names -- which slice
        # 2 may tighten to; the floor below is the minimum this VO enforces.)
        if self.seccomp_profile.strip().lower() == "unconfined":
            raise ValueError(
                "seccomp_profile 'unconfined' is forbidden by policy"
            )
        if self.apparmor_profile.strip().lower() in ("unconfined", "disable"):
            raise ValueError(
                "apparmor_profile must not disable confinement "
                f"(got {self.apparmor_profile!r})"
            )
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
        for ns_flag in (
            "host_pid_namespace",
            "host_ipc_namespace",
            "host_uts_namespace",
        ):
            if getattr(self, ns_flag) is not False:
                raise ValueError(
                    f"{ns_flag} is forbidden by policy (no host-namespace sharing)"
                )


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
class RuntimeResourceRef:
    """A runtime object a launch created that the worker must record (and
    eventually reap) for an instance: ``kind`` is a
    ``VALID_RUNTIME_RESOURCE_KINDS`` token (``container`` / ``network`` / ...) and
    ``external_ref`` the runtime id. Carried in a :class:`RuntimeLaunch` so a leak
    of a live container/network is reap-able. References only -- never a secret."""

    kind: str
    external_ref: str

    def __post_init__(self) -> None:
        _require_nonempty(self.kind, "kind")
        _require_nonempty(self.external_ref, "external_ref")


@runtime_checkable
class RuntimeLaunch(Protocol):
    """The structural result of :meth:`RuntimeBackend.launch`: the observed
    container state PLUS the runtime resources to persist, the endpoints it
    published, and the capability gaps acknowledged for this launch (surfaced,
    never hidden). Defined here so the worker types against the domain seam, not
    the concrete adapter's return class."""

    @property
    def observation(self) -> RuntimeObservation: ...

    @property
    def runtime_resources(self) -> tuple[RuntimeResourceRef, ...]: ...

    @property
    def endpoints(self) -> tuple[RuntimeEndpoint, ...]: ...

    @property
    def acknowledged_gaps(self) -> frozenset[str]: ...


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

    def launch(
        self, request: ContainerRequest, *, command: Sequence[str] | None = ...
    ) -> RuntimeLaunch:
        """Create and start one policy-constrained container; return a
        :class:`RuntimeLaunch` (observation + runtime resources + endpoints +
        acknowledged gaps). Refuses (``UnsupportedRuntimeError``) BEFORE creating
        anything if a required hardening -- seccomp or the isolated-network
        host-block -- cannot be enforced on this host."""
        ...

    def stop(self, instance_id: str, container_id: str) -> None:
        """Stop a running container (idempotent)."""
        ...

    def restart(self, instance_id: str, container_id: str) -> None:
        """Restart a running container in place (idempotent)."""
        ...

    def remove(self, instance_id: str, container_id: str | None) -> None:
        """Remove a container and its per-instance runtime resources (network,
        volumes, host-block firewall) -- idempotent, so a re-run after a partial
        failure converges."""
        ...

    def observe(self, instance_id: str, container_id: str | None) -> RuntimeObservation:
        """Report the current observed state of one instance's container."""
        ...

    def health_check(self, instance_id: str, container_id: str) -> RuntimeObservation:
        """A liveness/health probe for one instance's container."""
        ...

    def collect_logs(self, instance_id: str, container_id: str) -> str:
        """Capture the container's logs to a storage reference and return the
        reference (never the raw logs, which may contain challenge output)."""
        ...

    def find_container(self, instance_id: str) -> str | None:
        """Return THIS worker's container id for ``instance_id`` (scoped to the
        worker so a multi-worker host never returns a peer's container), or None.
        Keeps runtime-query verbs inside the adapter."""
        ...

    def reap_managed(self, worker: str | None = ...) -> int:
        """Force-remove every managed container this worker owns (crash-recovery
        sweep), scoped by the worker label so peers' live containers are untouched.
        Returns the count reaped."""
        ...


@dataclass(frozen=True)
class BuildBundle:
    """The FULL (buildable, private-inclusive) bundle bytes for one challenge
    version, fetched by a worker through the control-plane client -- NEVER
    directly from the DB or control-plane filesystem (``docs/architecture/
    build-challenge-worker-pipeline.md``).

    ``bundle_sha256`` is the content address of ``data`` computed by the
    control plane at fetch time and carried alongside the bytes. ``spec_sha256``
    is the version's spec hash read fresh from the DB at fetch time. Together
    they support the worker's two-part verification BEFORE any byte is trusted:
    recompute ``sha256(data)`` against ``bundle_sha256`` (catches in-transit
    corruption/tampering), and compare ``spec_sha256`` against the job
    payload's own ``spec_sha256`` recorded at enqueue time (catches the version
    drifting between enqueue and fetch). ``data`` may embed the challenge's
    flag/solution material -- it must NEVER be logged."""

    data: bytes
    bundle_sha256: str
    spec_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.data, (bytes, bytearray)):
            raise ValueError("data must be bytes")
        _require_nonempty(self.bundle_sha256, "bundle_sha256")
        _require_nonempty(self.spec_sha256, "spec_sha256")


@runtime_checkable
class BuildBackend(Protocol):
    """The image-BUILD seam a worker's concrete adapter implements for the
    ``build_challenge`` job (never reachable from the control plane -- ADR-001).

    Interface only: no method here has an implementation, and this module
    imports no docker/subprocess code. ``DockerRuntimeBackend`` already
    satisfies this Protocol STRUCTURALLY (its existing ``build_image`` /
    ``is_available`` methods match this shape) -- no new adapter class is
    required; see ``docs/architecture/build-challenge-worker-pipeline.md``."""

    def build_image(self, *, context_dir: str, tag: str, network: bool = ...) -> str:
        """Build an image from ``context_dir`` and return its content-addressed
        digest (``sha256:...``). MUST default to no network access during the
        build (the generated Dockerfile is hostile input) and MUST refuse
        (never silently accept) an oversized result rather than leave it
        behind."""
        ...

    def is_available(self) -> bool:
        """Whether this backend's build runtime is reachable (a capability
        probe, mirroring ``RuntimeBackend.detect_capabilities``'s spirit)."""
        ...
