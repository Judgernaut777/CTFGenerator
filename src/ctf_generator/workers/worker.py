"""The Execution-Plane worker executable (M8 slice 2, WORKER-SIDE).

A worker is the ONLY process that runs challenge containers. It talks to the
control plane through exactly one seam -- :class:`WorkerControlPlaneClient` -- so
the transport can change (an in-process :class:`LocalControlPlaneClient` for the
single-host / test path now; a networked HTTP client in M9) with ZERO changes to
the run loop.

Security boundary (docs/security/runtime-isolation.md, ADR-001):

* The run loop imports the concrete
  :class:`~ctf_generator.infrastructure.runtime.docker_backend.DockerRuntimeBackend`
  -- a worker legitimately drives a runtime. It holds NO control-plane DB
  credential and NO session-signing key in its real, networked deployment; its
  only artifact is the opaque scoped bearer token.
* :class:`LocalControlPlaneClient` is the DOCUMENTED single-host exception: it
  reaches the services in-process over a local DB session. A networked worker
  MUST use the M9 HTTP client instead (deferred).
* Flags/tokens/worker-credentials are never logged.

The loop honours the SLICE-2 launch contract: a ``launch_instance`` job for an
instance whose ``assigned_worker`` is ``None`` is re-placed + re-reserved through
the control plane BEFORE the container is started.
"""

from __future__ import annotations

import logging
import signal
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from ctf_generator.domain.execution.runtime import (
    ContainerPolicy,
    ContainerRequest,
)
from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
    RuntimeResource,
)
from ctf_generator.domain.work.models import JobLease
from ctf_generator.infrastructure.runtime.docker_backend import (
    DockerRuntimeBackend,
    LaunchResult,
    UnsupportedRuntimeError,
)

_LOG = logging.getLogger("ctf_generator.worker")

# Default per-instance secure envelope used when a job carries no explicit policy.
# The policy SOURCE (a family manifest's resource requirements) is a broader
# concern deferred beyond slice 2; every field here is already at its secure
# floor via ContainerPolicy's construction guards.
DEFAULT_POLICY = ContainerPolicy(memory_mb=256, cpu_millis=500, network_mode="isolated")

# Job types this worker dispatches to the runtime backend.
LAUNCH_JOBS = frozenset({"launch_instance"})
STOP_JOBS = frozenset({"stop_instance"})
DELETE_JOBS = frozenset({"delete_runtime_resources", "expire_instance"})
RESTART_JOBS = frozenset({"restart_instance"})
RESET_JOBS = frozenset({"reset_instance"})
HEALTH_JOBS = frozenset({"run_health_check"})
LOG_JOBS = frozenset({"collect_logs"})

DISPATCHABLE_JOBS = (
    LAUNCH_JOBS
    | STOP_JOBS
    | DELETE_JOBS
    | RESTART_JOBS
    | RESET_JOBS
    | HEALTH_JOBS
    | LOG_JOBS
)


def _now() -> datetime:
    return datetime.now(UTC)


class WorkerControlPlaneClient(Protocol):
    """The worker's sole link to the control plane. An implementation mediates
    credential auth, the job-queue verbs, and the instance-fact reports. The run
    loop programs against THIS -- never against a concrete service or transport."""

    def authenticate(self, now: datetime) -> str:
        """Return a live scoped bearer token (refreshing/rotating as needed)."""
        ...

    def claim(self, token: str, lease_seconds: int, now: datetime) -> JobLease | None:
        ...

    def start(self, token: str, job_id: str, lease_token: str, now: datetime) -> None:
        """``claimed`` -> ``running`` before the worker begins the work."""
        ...

    def heartbeat(
        self, token: str, job_id: str, lease_token: str, lease_seconds: int, now: datetime
    ) -> bool:
        ...

    def complete(
        self, token: str, job_id: str, lease_token: str, result: dict | None, now: datetime
    ) -> None:
        ...

    def fail(
        self,
        token: str,
        job_id: str,
        lease_token: str,
        error_class: str,
        error_detail: str | None,
        retryable: bool,
        now: datetime,
    ) -> None:
        ...

    def get_instance(self, instance_id: str) -> Instance | None:
        ...

    def replace_instance(self, instance_id: str, now: datetime) -> Instance:
        """Re-place + re-reserve an instance whose ``assigned_worker`` is ``None``
        (the slice-2 launch contract) and return the re-placed instance."""
        ...

    def report_health(self, observation: HealthObservation) -> None:
        ...

    def report_runtime_resource(self, resource: RuntimeResource) -> None:
        ...

    def transition_instance(
        self, instance_id: str, to_state: str, *, reason: str, now: datetime
    ) -> None:
        ...


@dataclass
class WorkerConfig:
    """Static worker configuration."""

    worker_name: str
    lease_seconds: int = 60
    poll_interval_seconds: float = 1.0
    claim_capabilities: tuple[str, ...] = ()


@dataclass
class _DispatchOutcome:
    result: dict | None = None
    resources: tuple[RuntimeResource, ...] = ()


class Worker:
    """The run loop: authenticate -> claim -> dispatch to the runtime -> report
    facts + complete/fail -> repeat, with SIGTERM drain and restart recovery."""

    def __init__(
        self,
        config: WorkerConfig,
        client: WorkerControlPlaneClient,
        backend: DockerRuntimeBackend,
        *,
        policy: ContainerPolicy = DEFAULT_POLICY,
        command: Sequence[str] | None = None,
        clock=_now,
    ) -> None:
        self._config = config
        self._client = client
        self._backend = backend
        self._policy = policy
        self._command = tuple(command) if command else None
        self._clock = clock
        self._draining = False

    # -- lifecycle -------------------------------------------------------------

    def request_drain(self, *_args) -> None:
        """Enter graceful drain: stop claiming NEW work; in-flight leases finish."""
        _LOG.info("worker %s draining", self._config.worker_name)
        self._draining = True

    def install_signal_handlers(self) -> None:  # pragma: no cover - signal wiring
        signal.signal(signal.SIGTERM, self.request_drain)
        signal.signal(signal.SIGINT, self.request_drain)

    def recover_abandoned(self) -> int:
        """At restart, force-remove any leftover ctfgen-managed containers this
        worker owns from a prior crash (idempotent). Returns the count reaped."""
        reaped = 0
        try:
            ids = self._backend._run(  # noqa: SLF001 - worker owns its backend
                ["ps", "-aq", "--filter", "label=ctfgen.managed=true"], check=False
            ).stdout.split()
            for cid in ids:
                self._backend._run(["rm", "--force", "--volumes", cid], check=False)  # noqa: SLF001
                reaped += 1
        except Exception:  # pragma: no cover - best-effort cleanup
            _LOG.warning("abandoned-container recovery failed", exc_info=True)
        return reaped

    # -- run loop --------------------------------------------------------------

    def run_forever(self, *, max_iterations: int | None = None) -> None:  # pragma: no cover
        self.recover_abandoned()
        iterations = 0
        while True:
            if max_iterations is not None and iterations >= max_iterations:
                return
            worked = self.run_once()
            iterations += 1
            if self._draining and not worked:
                _LOG.info("worker %s drained; exiting", self._config.worker_name)
                return
            if not worked:
                time.sleep(self._config.poll_interval_seconds)

    def run_once(self) -> bool:
        """One iteration: claim (unless draining) + dispatch one job. Returns True
        iff a job was processed."""
        now = self._clock()
        token = self._client.authenticate(now)
        if self._draining:
            return False
        lease = self._client.claim(token, self._config.lease_seconds, now)
        if lease is None:
            return False
        self._process(token, lease)
        return True

    def _process(self, token: str, lease: JobLease) -> None:
        job = lease.job
        now = self._clock()
        # claimed -> running (lease-fenced) before any runtime work begins.
        self._client.start(token, job.job_id, lease.lease_token, now)
        try:
            outcome = self._dispatch(job.job_type, dict(job.payload), now)
        except UnsupportedRuntimeError as exc:
            # A hardening cannot be applied on this host: NON-retryable (a retry on
            # the same host fails identically). Fail loud, never launch degraded.
            _LOG.error("job %s refused: unsupported runtime", job.job_id)
            self._client.fail(
                token, job.job_id, lease.lease_token, "unsupported_runtime",
                str(exc), False, self._clock(),
            )
            return
        except Exception as exc:  # noqa: BLE001 - report any failure as retryable
            _LOG.exception("job %s failed", job.job_id)
            self._client.fail(
                token, job.job_id, lease.lease_token, type(exc).__name__,
                str(exc), True, self._clock(),
            )
            return
        for resource in outcome.resources:
            self._client.report_runtime_resource(resource)
        self._client.complete(
            token, job.job_id, lease.lease_token, outcome.result, self._clock()
        )

    # -- dispatch table --------------------------------------------------------

    def _dispatch(self, job_type: str, payload: dict, now: datetime) -> _DispatchOutcome:
        instance_id = payload.get("instance_id")
        if not isinstance(instance_id, str) or not instance_id:
            raise ValueError(f"{job_type} payload missing instance_id")
        if job_type in LAUNCH_JOBS:
            return self._do_launch(instance_id, now)
        if job_type in RESET_JOBS:
            return self._do_reset(instance_id, now)
        if job_type in RESTART_JOBS:
            return self._do_restart(instance_id, now)
        if job_type in STOP_JOBS:
            return self._do_stop(instance_id, now)
        if job_type in DELETE_JOBS:
            return self._do_delete(instance_id, now)
        if job_type in HEALTH_JOBS:
            return self._do_health(instance_id, now)
        if job_type in LOG_JOBS:
            return self._do_logs(instance_id, now)
        raise ValueError(f"worker cannot dispatch job_type {job_type!r}")

    # -- runtime actions -------------------------------------------------------

    def _require_instance(self, instance_id: str) -> Instance:
        instance = self._client.get_instance(instance_id)
        if instance is None:
            raise LookupError(f"instance not found: {instance_id!r}")
        return instance

    def _build_request(self, instance: Instance) -> ContainerRequest:
        if not instance.image_ref:
            raise ValueError(
                f"instance {instance.instance_id!r} has no image_ref to launch"
            )
        team_key = f"{instance.competition_id}:{instance.team_name}"
        return ContainerRequest(
            instance_id=instance.instance_id,
            team_key=team_key,
            image_ref=instance.image_ref,
            policy=self._policy,
        )

    def _record_launch(
        self, instance: Instance, launched: LaunchResult, now: datetime
    ) -> tuple[RuntimeResource, ...]:
        resources = tuple(
            RuntimeResource(
                instance_id=instance.instance_id,
                kind=ref.kind,
                external_ref=ref.external_ref,
                worker=self._config.worker_name,
                generation=instance.generation,
            )
            for ref in launched.runtime_resources
        )
        healthy = launched.observation.phase == "running"
        self._client.report_health(
            HealthObservation(
                instance_id=instance.instance_id,
                observed_state="healthy" if healthy else "starting",
                healthy=healthy,
                worker=self._config.worker_name,
                generation=instance.generation,
                observed_at=now,
            )
        )
        return resources

    def _do_launch(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        instance = self._require_instance(instance_id)
        # SLICE-2 launch contract: an unassigned instance must be re-placed +
        # re-reserved through the control plane before we start a container.
        if instance.assigned_worker is None:
            instance = self._client.replace_instance(instance_id, now)
        request = self._build_request(instance)
        launched = self._backend.launch(request, command=self._command)
        resources = self._record_launch(instance, launched, now)
        # Drive the observed lifecycle forward (worker observed the container up).
        self._client.transition_instance(
            instance_id, "starting", reason="container started", now=now
        )
        if launched.observation.phase == "running":
            self._client.transition_instance(
                instance_id, "healthy", reason="health check passed", now=now
            )
        return _DispatchOutcome(
            result={
                "container_id": launched.observation.container_id,
                "phase": launched.observation.phase,
            },
            resources=resources,
        )

    def _do_reset(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        # A reset is a clean rebuild: tear down the old runtime objects, relaunch.
        self._backend.remove(instance_id, None)
        return self._do_launch(instance_id, now)

    def _do_restart(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        instance = self._require_instance(instance_id)
        cid = self._current_container(instance_id)
        if cid:
            self._backend.restart(instance_id, cid)
        obs = self._backend.observe(instance_id, cid)
        self._client.report_health(
            HealthObservation(
                instance_id=instance_id,
                observed_state="healthy" if obs.phase == "running" else "degraded",
                healthy=obs.phase == "running",
                worker=self._config.worker_name,
                generation=instance.generation,
                observed_at=now,
            )
        )
        return _DispatchOutcome(result={"phase": obs.phase})

    def _do_stop(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        instance = self._require_instance(instance_id)
        cid = self._current_container(instance_id)
        if cid:
            self._backend.stop(instance_id, cid)
        self._backend.remove(instance_id, cid)
        self._client.report_health(
            HealthObservation(
                instance_id=instance_id,
                observed_state="absent",
                healthy=False,
                worker=self._config.worker_name,
                generation=instance.generation,
                observed_at=now,
            )
        )
        self._client.transition_instance(
            instance_id, "stopping", reason="stop requested", now=now
        )
        self._client.transition_instance(
            instance_id, "stopped", reason="container removed", now=now
        )
        return _DispatchOutcome(result={"phase": "absent"})

    def _do_delete(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        cid = self._current_container(instance_id)
        self._backend.remove(instance_id, cid)
        return _DispatchOutcome(result={"removed": True})

    def _do_health(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        instance = self._require_instance(instance_id)
        cid = self._current_container(instance_id)
        obs = self._backend.health_check(instance_id, cid) if cid else None
        healthy = bool(obs and obs.phase == "running")
        self._client.report_health(
            HealthObservation(
                instance_id=instance_id,
                observed_state="healthy" if healthy else "absent",
                healthy=healthy,
                worker=self._config.worker_name,
                generation=instance.generation,
                observed_at=now,
            )
        )
        return _DispatchOutcome(result={"healthy": healthy})

    def _do_logs(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        cid = self._current_container(instance_id)
        if not cid:
            return _DispatchOutcome(result={"log_lines": 0})
        logs = self._backend.collect_logs(instance_id, cid)
        # Raw logs may carry challenge output; return only a length, never content.
        return _DispatchOutcome(result={"log_lines": len(logs.splitlines())})

    def _current_container(self, instance_id: str) -> str | None:
        out = self._backend._run(  # noqa: SLF001 - worker owns its backend
            [
                "ps",
                "-aq",
                "--filter",
                f"label=ctfgen.instance={instance_id}",
            ],
            check=False,
        ).stdout.split()
        return out[0] if out else None


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - entrypoint
    """Console entrypoint (``ctfgen-worker``). The networked deployment wiring
    (config, HTTP client) lands in M9; today this refuses to run without an
    explicit single-host configuration rather than guessing, so it never
    accidentally starts holding control-plane DB credentials.
    """
    logging.basicConfig(level=logging.INFO)
    _LOG.error(
        "ctfgen-worker: the networked worker transport is deferred to M9. Use "
        "LocalControlPlaneClient in-process for the single-host/test path (see "
        "ctf_generator.workers.local_client)."
    )
    return 2
