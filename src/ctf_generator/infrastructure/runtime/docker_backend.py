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

import json
import logging
import re
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
)

_LOG = logging.getLogger("ctf_generator.worker.runtime")

# Non-root uid/gid the workload runs as when the image would otherwise default to
# root. 65534 is the conventional ``nobody`` uid present in most base images.
DEFAULT_NON_ROOT_UID = 65534

# Labels stamped on every managed object so a crash-recovery sweep can find and
# reap our containers/networks without touching anything else on the host.
MANAGED_LABEL = "ctfgen.managed"
INSTANCE_LABEL = "ctfgen.instance"

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
class RuntimeResourceRef:
    """A runtime object the worker must record (and eventually reap) for an
    instance: ``kind`` is a ``VALID_RUNTIME_RESOURCE_KINDS`` token, ``external_ref``
    the docker id."""

    kind: str
    external_ref: str


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
        f"/tmp:rw,size={policy.tmpfs_mb}m,mode=1770,noexec,nosuid,nodev",  # noqa: S108
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

    def _network_name(self, instance_id: str) -> str:
        return f"ctfgen-net-{_slug(instance_id, maxlen=48)}"

    def _container_name(self, instance_id: str) -> str:
        return f"ctfgen-inst-{_slug(instance_id, maxlen=48)}"

    def _ensure_network(self, request: ContainerRequest) -> tuple[str, str]:
        """Create the DEDICATED per-instance network (idempotent). Returns
        ``(network_name, network_id)``. ``none``/``isolated`` -> ``--internal``
        (no route off the network: no cross-instance path, no host/DB/metadata
        reachability); ``egress`` -> a dedicated bridge that permits controlled
        outbound (still its own network, so no cross-instance path)."""
        name = self._network_name(request.instance_id)
        existing = self._run(
            ["network", "ls", "--filter", f"name=^{name}$", "--format", "{{.ID}}"],
            check=False,
        ).stdout.strip()
        if existing:
            return name, existing
        args = [
            "network",
            "create",
            "--driver",
            "bridge",
            "--label",
            f"{MANAGED_LABEL}=true",
            "--label",
            f"{INSTANCE_LABEL}={request.instance_id}",
        ]
        if request.policy.network_mode in ("none", "isolated"):
            args.append("--internal")
        args.append(name)
        net_id = self._run(args).stdout.strip()
        return name, net_id

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
        probe = self.probe()
        acked = self._gate(request.policy, probe)
        # Compute flags up front so a hard-floor refusal happens before any docker
        # object is created.
        hardening = policy_to_run_flags(
            request.policy, probe, non_root_uid=self._non_root_uid
        )

        network_name, network_id = self._ensure_network(request)
        container_name = self._container_name(request.instance_id)

        args: list[str] = [
            "run",
            "-d",
            "--name",
            container_name,
            "--network",
            network_name if request.policy.network_mode != "none" else "none",
            "--label",
            f"{MANAGED_LABEL}=true",
            "--label",
            f"{INSTANCE_LABEL}={request.instance_id}",
            "--restart",
            "no",
        ]
        args += hardening
        # Controlled ingress: only egress-mode instances publish a host port, bound
        # to loopback; isolated/none instances are reachable only inside their
        # network (ingress via the reverse proxy is M9).
        publish = request.policy.network_mode == "egress"
        for port in request.exposed_ports:
            if publish:
                args += ["-p", f"127.0.0.1::{port}"]
            else:
                args += ["--expose", str(port)]
        for key, value in request.labels:
            args += ["--label", f"{key}={value}"]
        args.append(request.image_ref)
        if command:
            args += list(command)

        try:
            container_id = self._run(args).stdout.strip()
        except DockerCommandError:
            # Roll back the network we just created so a failed launch leaks
            # nothing.
            self._remove_network(network_name)
            raise

        resources = (
            RuntimeResourceRef("container", container_id),
            RuntimeResourceRef("network", network_id),
        )
        endpoints = self._endpoints(request, container_id, network_name, publish)
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
        network_name: str,
        publish: bool,
    ) -> tuple[RuntimeEndpoint, ...]:
        eps: list[RuntimeEndpoint] = []
        if publish:
            for port in request.exposed_ports:
                mapping = self._run(
                    ["port", container_id, str(port)], check=False
                ).stdout.strip()
                # e.g. "127.0.0.1:49153"
                if ":" in mapping:
                    host, host_port = mapping.rsplit(":", 1)
                    with _suppress_value():
                        eps.append(
                            RuntimeEndpoint(
                                container_port=port,
                                host=host or "127.0.0.1",
                                host_port=int(host_port),
                            )
                        )
        else:
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

    def reset(
        self, request: ContainerRequest, container_id: str, *, command: Sequence[str] | None = None
    ) -> LaunchResult:
        """Destroy the current container/network and relaunch fresh (a reset bumps
        the instance generation upstream; the runtime side is a clean rebuild)."""
        self.remove(request.instance_id, container_id)
        return self.launch(request, command=command)

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
        """FORCE-remove the container, then its per-instance network and any
        anonymous volumes. Idempotent: safe to call twice, safe if already gone --
        so a re-run after a partial failure converges to clean."""
        if container_id:
            self._run(["rm", "--force", "--volumes", container_id], check=False)
        # Also sweep by label in case the container id was lost but objects leaked.
        self._remove_by_label(instance_id)
        self._remove_network(self._network_name(instance_id))

    def destroy(self, instance_id: str, container_id: str | None = None) -> None:
        """Alias for :meth:`remove` (the design's ``destroy`` verb)."""
        self.remove(instance_id, container_id)

    def _remove_by_label(self, instance_id: str) -> None:
        ids = self._run(
            [
                "ps",
                "-aq",
                "--filter",
                f"label={INSTANCE_LABEL}={instance_id}",
            ],
            check=False,
        ).stdout.split()
        for cid in ids:
            self._run(["rm", "--force", "--volumes", cid], check=False)

    def _remove_network(self, network_name: str) -> None:
        self._run(["network", "rm", network_name], check=False)


# -- module helpers -----------------------------------------------------------


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
        if health and health.lower() == "unhealthy":
            return "unhealthy"
        return "running"
    if status.lower() in ("created", "restarting"):
        return "starting"
    if status.lower() == "exited":
        return "exited"
    return "unknown"


class _suppress_value:
    """Swallow a ValueError from constructing a RuntimeEndpoint with a bad port
    (a transient inspect race yields no useful endpoint rather than a crash)."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, ValueError)
