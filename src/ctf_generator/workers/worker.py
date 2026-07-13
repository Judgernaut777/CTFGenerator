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
import os
import re
import signal
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # typing-only: importing these at runtime would pull the
    # effectful eval engine onto the worker's import graph (see EvalJobRunner).
    from ctf_generator.agent_eval import AdversarialDeltaReport, AgentEvalReport

from ctf_generator.domain.execution.runtime import (
    ContainerPolicy,
    ContainerRequest,
    RuntimeBackend,
    RuntimeLaunch,
)
from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
    InstanceEndpoint,
    RuntimeResource,
)
from ctf_generator.domain.work.models import JobLease
from ctf_generator.infrastructure.runtime.docker_backend import (
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
# The agent-evaluation job (M15b). Unlike every other dispatchable job it is
# NOT instance-scoped: its payload carries (eval_run_id, definition_slug,
# version_no, profile, adversarial) and NO instance_id -- so _dispatch branches
# it BEFORE the instance_id extraction.
EVAL_JOBS = frozenset({"run_agent_evaluation"})

DISPATCHABLE_JOBS = (
    LAUNCH_JOBS
    | STOP_JOBS
    | DELETE_JOBS
    | RESTART_JOBS
    | RESET_JOBS
    | HEALTH_JOBS
    | LOG_JOBS
    | EVAL_JOBS
)

# The agent transcript an eval reports back (AgentEvalReport.notes) can quote a
# discovered ``ctf{...}`` flag or an SDK error carrying a provider key. The worker
# is the FIRST secret-free guard (record_result re-sanitizes defensively): every
# note it forwards is redacted here, and only the ALLOWLISTED advisory scalars
# (solved/steps/success_dropped/step_delta) plus redacted notes ever enter the
# result -- never a flag, base_url, candidate answer, or credential. Kept local so
# worker.py never imports the effectful agent_eval module (which owns FLAG_PATTERN).
_EVAL_SECRET_PATTERNS = (
    re.compile(r"(?i)(?:ctf|flag|key|secret|pass|pwd)\{[^}]{0,400}\}"),
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{8,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{8,}=*"),
    re.compile(r"(?i)authorization[:=]\s*\S+"),
)
_EVAL_REDACTED = "[redacted]"
# Cap the forwarded transcript so an adversarial challenge cannot bloat the
# operator-visible job/result row.
_MAX_EVAL_NOTES = 40


def _redact_eval_text(text: str) -> str:
    for pattern in _EVAL_SECRET_PATTERNS:
        text = pattern.sub(_EVAL_REDACTED, text)
    return text


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

    def report_health(self, observation: HealthObservation, now: datetime) -> None:
        """Report a health observation (authenticated + ownership-checked)."""
        ...

    def report_runtime_resource(self, resource: RuntimeResource, now: datetime) -> None:
        """Record a runtime resource (authenticated + ownership-checked)."""
        ...

    def report_endpoint(self, endpoint: InstanceEndpoint, now: datetime) -> None:
        """Record a published endpoint (authenticated + ownership-checked)."""
        ...

    def transition_instance(
        self, instance_id: str, to_state: str, *, reason: str, now: datetime
    ) -> None:
        ...


class EvalJobRunner(Protocol):
    """The effectful arm of a ``run_agent_evaluation`` job, injected as a seam.

    An implementation RENDERS the full bundle for a published version and RUNS
    ``agent_eval`` against it (Docker on the worker host). It is injected so the
    worker dispatch is unit-testable WITHOUT Docker (a deterministic fake returns
    a scripted report); the default single-host implementation lives in
    :mod:`ctf_generator.workers.eval_runner` and imports ``agent_eval`` lazily.

    Returns the raw effectful report (an ``AgentEvalReport`` for a plain profile,
    an ``AdversarialDeltaReport`` when ``adversarial``); the worker -- never the
    runner -- projects that into the SECRET-FREE advisory result. A distributed
    runner (separate-host bundle delivery + challenge image build) depends on the
    UNBUILT ``build_challenge`` pipeline and is deferred; see the module docstring
    of :mod:`ctf_generator.workers.eval_runner`."""

    def run(
        self,
        *,
        definition_slug: str,
        version_no: int,
        profile: str,
        adversarial: bool,
        now: datetime,
    ) -> AgentEvalReport | AdversarialDeltaReport: ...


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


class Worker:
    """The run loop: authenticate -> claim -> dispatch to the runtime -> report
    facts + complete/fail -> repeat, with SIGTERM drain and restart recovery.

    ``backend`` is typed against the domain :class:`RuntimeBackend` Protocol, not
    the concrete docker adapter -- the loop never reaches into docker-CLI verbs
    (it uses ``find_container`` / ``reap_managed``), so a different runtime
    implementation is a drop-in."""

    def __init__(
        self,
        config: WorkerConfig,
        client: WorkerControlPlaneClient,
        backend: RuntimeBackend,
        *,
        policy: ContainerPolicy = DEFAULT_POLICY,
        command: Sequence[str] | None = None,
        eval_runner: EvalJobRunner | None = None,
        clock=_now,
    ) -> None:
        self._config = config
        self._client = client
        self._backend = backend
        self._policy = policy
        self._command = tuple(command) if command else None
        # The single-host caller injects a concrete EvalJobRunner (it shares the
        # host + DB with the control plane); a networked worker leaves it None
        # until the distributed build_challenge pipeline exists.
        self._eval_runner = eval_runner
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
        """At restart, force-remove any leftover managed containers THIS worker
        owns from a prior crash (idempotent). Scoped to this worker's label via
        the backend's ``reap_managed`` so a multi-worker host never kills a peer
        worker's live containers. Returns the count reaped."""
        try:
            # No arg -> the backend reaps exactly the label IT stamps
            # (ctfgen.worker=<this backend's worker name>), so labels always match.
            return self._backend.reap_managed()
        except Exception:  # pragma: no cover - best-effort cleanup  # noqa: BLE001
            _LOG.warning("abandoned-container recovery failed", exc_info=True)
            return 0

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
            # A hardening (seccomp / the isolated-network host-block) cannot be
            # applied on this host: NON-retryable (a retry on the same host fails
            # identically). Fail loud, never launch degraded. Classified
            # 'infrastructure' -- the queue's error vocabulary; the specific cause
            # travels in error_detail.
            _LOG.error("job %s refused: unsupported runtime", job.job_id)
            self._client.fail(
                token, job.job_id, lease.lease_token, "infrastructure",
                f"unsupported_runtime: {exc}", False, self._clock(),
            )
            return
        except Exception as exc:  # noqa: BLE001 - report any failure as retryable
            # Any other dispatch failure is retryable and classified 'internal'
            # (a valid queue error class -- the exception type is in error_detail;
            # passing type(exc).__name__ as the class would be rejected).
            _LOG.exception("job %s failed", job.job_id)
            self._client.fail(
                token, job.job_id, lease.lease_token, "internal",
                f"{type(exc).__name__}: {exc}", True, self._clock(),
            )
            return
        # Renew the lease right before completing so a slow launch cannot lose its
        # lease mid-flight and have the job double-executed by a reaper. (Runtime
        # facts/resources are reported inside the dispatch, immediately after a
        # successful backend.launch, not batched here.)
        self._client.heartbeat(
            token, job.job_id, lease.lease_token, self._config.lease_seconds, self._clock()
        )
        self._client.complete(
            token, job.job_id, lease.lease_token, outcome.result, self._clock()
        )

    # -- dispatch table --------------------------------------------------------

    def _dispatch(self, job_type: str, payload: dict, now: datetime) -> _DispatchOutcome:
        # The eval job is NOT instance-scoped -- it MUST branch before the
        # instance_id extraction below, which would otherwise raise "missing
        # instance_id" for a valid eval payload.
        if job_type in EVAL_JOBS:
            return self._do_agent_eval(payload, now)
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

    def _report_launched_facts(
        self, instance: Instance, launched: RuntimeLaunch, now: datetime
    ) -> None:
        """Report the container/network resources, endpoints, and health for a
        just-launched instance IMMEDIATELY after ``backend.launch`` -- before any
        lifecycle transition -- so a live container/network can never escape
        tracking. Raises on the first report failure (the caller compensates)."""
        for ref in launched.runtime_resources:
            self._client.report_runtime_resource(
                RuntimeResource(
                    instance_id=instance.instance_id,
                    kind=ref.kind,
                    external_ref=ref.external_ref,
                    worker=self._config.worker_name,
                    generation=instance.generation,
                ),
                now,
            )
        for ep in launched.endpoints:
            self._client.report_endpoint(
                InstanceEndpoint(
                    instance_id=instance.instance_id,
                    name=f"port-{ep.container_port}",
                    host=ep.host,
                    port=ep.host_port,
                    protocol="tcp",
                    url=f"tcp://{ep.host}:{ep.host_port}",
                    # Isolated instances are reachable only inside their network;
                    # contestant ingress is via the M9 reverse proxy, not here.
                    internal=True,
                ),
                now,
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
            ),
            now,
        )

    def _do_launch(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        instance = self._require_instance(instance_id)
        # SLICE-2 launch contract: an unassigned instance must be re-placed +
        # re-reserved through the control plane before we start a container.
        if instance.assigned_worker is None:
            instance = self._client.replace_instance(instance_id, now)
        # After (re)placement the instance MUST be assigned to THIS worker before
        # we start a container -- else a report/transition would be ownership-
        # rejected and we would leak a live container. Fail retryable if not.
        if instance.assigned_worker != self._config.worker_name:
            raise RuntimeError(
                f"instance {instance_id!r} is assigned "
                f"{instance.assigned_worker!r}, not this worker "
                f"{self._config.worker_name!r}; refusing to launch"
            )
        request = self._build_request(instance)
        launched = self._backend.launch(request, command=self._command)
        container_id = launched.observation.container_id
        try:
            # Persist the runtime resources + endpoints + health IMMEDIATELY, then
            # drive the observed lifecycle. If ANY post-launch step fails, remove
            # the container so no orphaned live container escapes tracking.
            self._report_launched_facts(instance, launched, now)
            self._client.transition_instance(
                instance_id, "starting", reason="container started", now=now
            )
            if launched.observation.phase == "running":
                self._client.transition_instance(
                    instance_id, "healthy", reason="health check passed", now=now
                )
        except Exception:
            _LOG.error("post-launch step failed for %s; compensating (remove)", instance_id)
            self._backend.remove(instance_id, container_id)
            raise
        return _DispatchOutcome(
            result={
                "container_id": container_id,
                "phase": launched.observation.phase,
            },
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
            ),
            now,
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
            ),
            now,
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
            ),
            now,
        )
        return _DispatchOutcome(result={"healthy": healthy})

    def _do_logs(self, instance_id: str, now: datetime) -> _DispatchOutcome:
        cid = self._current_container(instance_id)
        if not cid:
            return _DispatchOutcome(result={"log_lines": 0})
        logs = self._backend.collect_logs(instance_id, cid)
        # Raw logs may carry challenge output; return only a length, never content.
        return _DispatchOutcome(result={"log_lines": len(logs.splitlines())})

    # -- agent evaluation (M15b, NOT instance-scoped) --------------------------

    def _do_agent_eval(self, payload: dict, now: datetime) -> _DispatchOutcome:
        """Run one agent evaluation for a published version and return its
        SECRET-FREE advisory result.

        The effectful work (render the FULL bundle, build+run it via Docker,
        drive the agent) sits behind the injected :class:`EvalJobRunner` seam, so
        this dispatch is unit-testable without Docker. The result carries ONLY the
        allowlisted advisory subset + REDACTED notes keyed by ``eval_run_id`` --
        never a flag, base_url/token, candidate answer, or provider key (the
        control-plane projector re-sanitizes via ``record_result``).

        A failed/unsupported eval is reported as an ADVISORY failure RESULT
        (``error``, sanitized) rather than crashing the job: a measurement that
        could not be taken is a recorded eval outcome, not an infrastructure
        failure of the queue verb."""
        eval_run_id = payload.get("eval_run_id")
        if not isinstance(eval_run_id, str) or not eval_run_id:
            raise ValueError("run_agent_evaluation payload missing eval_run_id")
        definition_slug = payload.get("definition_slug")
        version_no = payload.get("version_no")
        profile = payload.get("profile")
        adversarial = bool(payload.get("adversarial", False))
        if not isinstance(definition_slug, str) or not definition_slug:
            raise ValueError("run_agent_evaluation payload missing definition_slug")
        if not isinstance(version_no, int):
            raise ValueError("run_agent_evaluation payload missing version_no")
        if not isinstance(profile, str) or not profile:
            raise ValueError("run_agent_evaluation payload missing profile")

        if self._eval_runner is None:
            # A networked worker holds no single-host runner: a fully DISTRIBUTED
            # eval needs the worker to fetch the FULL bundle + build the challenge
            # image via the UNBUILT build_challenge pipeline. Until then, report a
            # sanitized ADVISORY failure so the EvalRun resolves instead of
            # wedging pending. (The single-host caller injects the runner.)
            return _DispatchOutcome(
                result={
                    "eval_run_id": eval_run_id,
                    "error": (
                        "eval runner not configured on this worker: a distributed "
                        "eval requires the build_challenge pipeline (deferred); the "
                        "single-host runner must be injected"
                    ),
                }
            )

        try:
            report = self._eval_runner.run(
                definition_slug=definition_slug,
                version_no=version_no,
                profile=profile,
                adversarial=adversarial,
                now=now,
            )
        except Exception as exc:  # noqa: BLE001 - a failed eval is an advisory result
            _LOG.warning("agent eval failed for run %s", eval_run_id, exc_info=True)
            return _DispatchOutcome(
                result={
                    "eval_run_id": eval_run_id,
                    "error": _redact_eval_text(f"{type(exc).__name__}: {exc}"),
                }
            )

        return _DispatchOutcome(
            result=self._eval_result(eval_run_id, adversarial, report)
        )

    @staticmethod
    def _eval_result(
        eval_run_id: str, adversarial: bool, report
    ) -> dict:
        """Project a raw eval report into the allowlisted, secret-free result.

        For a plain profile the report is an ``AgentEvalReport``
        (solved/steps/notes). For an adversarial run it is an
        ``AdversarialDeltaReport``: ``solved``/``steps`` reflect the BASELINE
        (undefended "can it be solved at all") leg and ``success_dropped`` /
        ``step_delta`` are the advisory live-defense signal. Every forwarded note
        is redacted; nothing else from the report crosses into the result."""
        if adversarial:
            baseline = report.baseline
            raw_notes = list(report.notes)
            result: dict = {
                "eval_run_id": eval_run_id,
                "solved": bool(baseline.solved),
                "steps": int(baseline.steps),
                "success_dropped": bool(report.success_dropped),
                "step_delta": int(report.step_delta),
            }
        else:
            raw_notes = list(report.notes)
            result = {
                "eval_run_id": eval_run_id,
                "solved": bool(report.solved),
                "steps": int(report.steps),
            }
        result["notes"] = [
            _redact_eval_text(str(note)) for note in raw_notes[:_MAX_EVAL_NOTES]
        ]
        return result

    def _current_container(self, instance_id: str) -> str | None:
        # Via the Protocol -- keeps docker-CLI verbs inside the adapter and scopes
        # the lookup to THIS worker's containers.
        return self._backend.find_container(instance_id)


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - entrypoint
    """Console entrypoint (``ctfgen-worker``): run the NETWORKED worker.

    Transport is config-driven via the environment, keeping the run loop itself
    transport-agnostic (it only ever sees the :class:`WorkerControlPlaneClient`
    Protocol):

    * ``CTFGEN_WORKER_TRANSPORT``          -- ``http`` (default). The single-host
      in-process :class:`LocalControlPlaneClient` is a PROGRAMMATIC path (it needs a
      DB session and so is never selected from this DSN-free entrypoint).
    * ``CTFGEN_WORKER_CONTROL_PLANE_URL``  -- the worker gateway base URL.
    * ``CTFGEN_WORKER_TOKEN``              -- the worker's scoped bearer credential
      (``ctfw1.<id>.<secret>``). This is the ONLY credential the worker holds --
      NEVER a control-plane DB DSN and NEVER a signing key.
    * ``CTFGEN_WORKER_NAME``               -- the worker's registered name.
    * ``CTFGEN_WORKER_LEASE_SECONDS``      -- lease duration (default 60).

    The token is never logged.
    """
    logging.basicConfig(level=logging.INFO)
    transport = os.environ.get("CTFGEN_WORKER_TRANSPORT", "http").lower()
    if transport != "http":
        _LOG.error(
            "ctfgen-worker: transport %r is not runnable from this entrypoint. The "
            "in-process LocalControlPlaneClient is a programmatic single-host path "
            "(it requires a DB session); set CTFGEN_WORKER_TRANSPORT=http.",
            transport,
        )
        return 2

    base_url = os.environ.get("CTFGEN_WORKER_CONTROL_PLANE_URL")
    token = os.environ.get("CTFGEN_WORKER_TOKEN")
    name = os.environ.get("CTFGEN_WORKER_NAME")
    if not (base_url and token and name):
        _LOG.error(
            "ctfgen-worker: set CTFGEN_WORKER_CONTROL_PLANE_URL, CTFGEN_WORKER_TOKEN, "
            "and CTFGEN_WORKER_NAME to run the networked worker."
        )
        return 2

    # Imported lazily so importing this module never requires httpx / a docker CLI.
    from ctf_generator.infrastructure.runtime.docker_backend import (
        DockerRuntimeBackend,
    )
    from ctf_generator.workers.http_client import HttpControlPlaneClient

    lease_seconds = int(os.environ.get("CTFGEN_WORKER_LEASE_SECONDS", "60"))
    config = WorkerConfig(worker_name=name, lease_seconds=lease_seconds)
    client = HttpControlPlaneClient(base_url=base_url, token=token)
    backend = DockerRuntimeBackend()
    worker = Worker(config, client, backend)
    worker.install_signal_handlers()
    worker.run_forever()
    return 0
