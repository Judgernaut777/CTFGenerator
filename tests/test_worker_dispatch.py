"""Pure unit tests for the worker dispatch table (no docker, no DB).

Injects a fake RuntimeBackend and a fake control-plane client so the run loop's
core logic -- job_type routing, the launch re-placement contract, health/resource
reporting, and non-retryable vs retryable failure classification -- is covered
even where docker is absent.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ctf_generator.domain.execution.runtime import (
    ContainerRequest,
    RuntimeObservation,
)
from ctf_generator.domain.instances.models import Instance
from ctf_generator.domain.work.models import Job, JobLease
from ctf_generator.infrastructure.runtime.docker_backend import (
    LaunchResult,
    RuntimeResourceRef,
    UnsupportedRuntimeError,
)
from ctf_generator.workers.worker import Worker, WorkerConfig

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


@dataclass
class _FakeProc:
    stdout: str = ""
    returncode: int = 0


class _FakeBackend:
    """Records runtime calls; returns canned observations."""

    def __init__(self, *, launch_phase: str = "running", raise_unsupported: bool = False):
        self.calls: list[tuple] = []
        self.launch_phase = launch_phase
        self.raise_unsupported = raise_unsupported
        self.container_id = "cid1234567890"

    def launch(self, request: ContainerRequest, *, command=None) -> LaunchResult:
        self.calls.append(("launch", request.instance_id))
        if self.raise_unsupported:
            raise UnsupportedRuntimeError("host lacks a required hardening")
        obs = RuntimeObservation(request.instance_id, self.container_id, self.launch_phase)
        return LaunchResult(
            observation=obs,
            runtime_resources=(
                RuntimeResourceRef("container", self.container_id),
                RuntimeResourceRef("network", "net999"),
            ),
        )

    def observe(self, instance_id, container_id):
        return RuntimeObservation(instance_id, container_id, "running")

    def health_check(self, instance_id, container_id):
        return RuntimeObservation(instance_id, container_id, "running")

    def stop(self, instance_id, container_id, *, timeout=10):
        self.calls.append(("stop", instance_id))

    def restart(self, instance_id, container_id, *, timeout=10):
        self.calls.append(("restart", instance_id))

    def remove(self, instance_id, container_id):
        self.calls.append(("remove", instance_id))

    def collect_logs(self, instance_id, container_id, *, tail=2000):
        return "line1\nline2\n"

    def _run(self, args, *, check=True, timeout=None):
        # _current_container / recover_abandoned probe by label.
        if args[:2] == ["ps", "-aq"]:
            return _FakeProc(stdout=self.container_id + "\n")
        return _FakeProc()


@dataclass
class _FakeClient:
    instance: Instance
    token: str = "ctfw1.cred.secret"
    health: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    transitions: list = field(default_factory=list)
    completed: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    replaced: bool = False
    claim_lease: JobLease | None = None

    def authenticate(self, now):
        return self.token

    def claim(self, token, lease_seconds, now):
        lease, self.claim_lease = self.claim_lease, None
        return lease

    def start(self, token, job_id, lease_token, now):
        self.started = True

    def heartbeat(self, token, job_id, lease_token, lease_seconds, now):
        return False

    def complete(self, token, job_id, lease_token, result, now):
        self.completed.append((job_id, result))

    def fail(self, token, job_id, lease_token, error_class, error_detail, retryable, now):
        self.failed.append((job_id, error_class, retryable))

    def get_instance(self, instance_id):
        return self.instance

    def replace_instance(self, instance_id, now):
        self.replaced = True
        self.instance = Instance(
            instance_id=self.instance.instance_id,
            competition_id=self.instance.competition_id,
            team_name=self.instance.team_name,
            definition_slug=self.instance.definition_slug,
            version_no=self.instance.version_no,
            state=self.instance.state,
            assigned_worker="w1",
            image_ref=self.instance.image_ref,
        )
        return self.instance

    def report_health(self, observation):
        self.health.append(observation)

    def report_runtime_resource(self, resource):
        self.resources.append(resource)

    def transition_instance(self, instance_id, to_state, *, reason, now):
        self.transitions.append((to_state, reason))


def _instance(*, assigned="w1", image="alpine:latest", state="queued") -> Instance:
    return Instance(
        instance_id="inst-1",
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        state=state,
        assigned_worker=assigned,
        image_ref=image,
    )


def _lease(job_type: str, payload: dict) -> JobLease:
    job = Job(
        job_id="job-1",
        job_type=job_type,
        idempotency_key=f"k-{job_type}",
        available_at=_NOW,
        required_capabilities=(job_type,),
        payload=payload,
    )
    return JobLease(job=job, lease_token="lease-1", lease_expires_at=_NOW)


def _worker(client, backend) -> Worker:
    return Worker(
        WorkerConfig(worker_name="w1", lease_seconds=60),
        client,
        backend,  # type: ignore[arg-type]
        command=("sleep", "3600"),
        clock=lambda: _NOW,
    )


class LaunchDispatchTests(unittest.TestCase):
    def test_launch_reports_resources_health_and_transitions(self) -> None:
        client = _FakeClient(instance=_instance())
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend()
        worked = _worker(client, backend).run_once()
        self.assertTrue(worked)
        self.assertIn(("launch", "inst-1"), backend.calls)
        # Two runtime resources reported (container + network).
        kinds = sorted(r.kind for r in client.resources)
        self.assertEqual(kinds, ["container", "network"])
        # A healthy observation reported.
        self.assertTrue(client.health[0].healthy)
        # Observed lifecycle driven queued->starting->healthy.
        self.assertEqual(client.transitions, [("starting", "container started"),
                                              ("healthy", "health check passed")])
        # Job completed, not failed.
        self.assertEqual(len(client.completed), 1)
        self.assertEqual(client.failed, [])

    def test_launch_of_unassigned_instance_replaces_first(self) -> None:
        client = _FakeClient(instance=_instance(assigned=None))
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend()
        _worker(client, backend).run_once()
        self.assertTrue(client.replaced)  # slice-2 launch contract honoured
        self.assertIn(("launch", "inst-1"), backend.calls)

    def test_unsupported_runtime_fails_non_retryable(self) -> None:
        client = _FakeClient(instance=_instance())
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend(raise_unsupported=True)
        _worker(client, backend).run_once()
        self.assertEqual(len(client.failed), 1)
        job_id, error_class, retryable = client.failed[0]
        self.assertEqual(error_class, "unsupported_runtime")
        self.assertFalse(retryable)  # never retry a host that can't isolate
        self.assertEqual(client.completed, [])


class OtherDispatchTests(unittest.TestCase):
    def test_stop_removes_and_transitions_to_stopped(self) -> None:
        client = _FakeClient(instance=_instance(state="active"))
        client.claim_lease = _lease(
            "stop_instance", {"instance_id": "inst-1", "generation": 1, "action": "stop"}
        )
        backend = _FakeBackend()
        _worker(client, backend).run_once()
        self.assertIn(("stop", "inst-1"), backend.calls)
        self.assertIn(("remove", "inst-1"), backend.calls)
        self.assertEqual(client.transitions, [("stopping", "stop requested"),
                                              ("stopped", "container removed")])

    def test_delete_runtime_resources_removes(self) -> None:
        client = _FakeClient(instance=_instance())
        client.claim_lease = _lease(
            "delete_runtime_resources",
            {"instance_id": "inst-1", "generation": 1, "action": "delete"},
        )
        backend = _FakeBackend()
        _worker(client, backend).run_once()
        self.assertIn(("remove", "inst-1"), backend.calls)
        self.assertEqual(len(client.completed), 1)

    def test_unknown_payload_without_instance_id_fails(self) -> None:
        client = _FakeClient(instance=_instance())
        client.claim_lease = _lease("launch_instance", {"generation": 1})
        _worker(client, _FakeBackend()).run_once()
        self.assertEqual(len(client.failed), 1)
        self.assertEqual(client.failed[0][1], "ValueError")

    def test_draining_worker_stops_claiming(self) -> None:
        client = _FakeClient(instance=_instance())
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1"}
        )
        worker = _worker(client, _FakeBackend())
        worker.request_drain()
        self.assertFalse(worker.run_once())  # no claim while draining
        self.assertEqual(client.completed, [])
        self.assertEqual(client.failed, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
