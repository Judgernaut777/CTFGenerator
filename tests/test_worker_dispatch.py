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

    def __init__(
        self,
        *,
        launch_phase: str = "running",
        raise_unsupported: bool = False,
        image_local_id: str | None = None,
        containers: tuple[tuple[str, str], ...] | None = None,
        phase_by_cid: dict[str, str] | None = None,
    ):
        self.calls: list[tuple] = []
        self.launch_phase = launch_phase
        self.raise_unsupported = raise_unsupported
        self.container_id = "cid1234567890"
        # The local image id image_id() reports (for digest-pinning tests);
        # None => "image absent locally".
        self.image_local_id = image_local_id
        # The (container_id, service_name) pairs find_stack_containers reports;
        # None => a single unlabeled container (the single-image instance shape).
        self.containers = containers
        # Per-container observed phase (defaults to "running"); lets a stack test
        # simulate one crashed sibling.
        self.phase_by_cid = phase_by_cid or {}

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

    def launch_stack(self, request, *, command=None):
        self.calls.append(("launch_stack", request.instance_id,
                           tuple(c.service_name for c in request.containers)))
        obs = RuntimeObservation(request.instance_id, self.container_id, self.launch_phase)
        return LaunchResult(
            observation=obs,
            runtime_resources=(
                RuntimeResourceRef("container", self.container_id),
                RuntimeResourceRef("network", "net999"),
            ),
        )

    def observe(self, instance_id, container_id):
        return RuntimeObservation(
            instance_id, container_id, self.phase_by_cid.get(container_id, "running")
        )

    def health_check(self, instance_id, container_id):
        return RuntimeObservation(
            instance_id, container_id, self.phase_by_cid.get(container_id, "running")
        )

    def stop(self, instance_id, container_id, *, timeout=10):
        self.calls.append(("stop", instance_id))

    def restart(self, instance_id, container_id, *, timeout=10):
        self.calls.append(("restart", instance_id, container_id))

    def remove(self, instance_id, container_id):
        self.calls.append(("remove", instance_id))

    def collect_logs(self, instance_id, container_id, *, tail=2000):
        self.calls.append(("collect_logs", instance_id, container_id))
        return "line1\nline2\n"

    def image_id(self, image_ref):
        self.calls.append(("image_id", image_ref))
        return self.image_local_id

    def find_container(self, instance_id):
        self.calls.append(("find_container", instance_id))
        return self.container_id

    def find_stack_containers(self, instance_id):
        self.calls.append(("find_stack_containers", instance_id))
        if self.containers is not None:
            return self.containers
        return ((self.container_id, ""),)

    def reap_managed(self, worker=None):
        self.calls.append(("reap_managed", worker))
        return 0


class _StackBackend(_FakeBackend):
    """A fake backend whose image_id() answers per image_ref (for stack pinning)."""

    def __init__(self, ref_to_digest: dict, **kw):
        super().__init__(**kw)
        self._ref_to_digest = ref_to_digest

    def image_id(self, image_ref):
        self.calls.append(("image_id", image_ref))
        return self._ref_to_digest.get(image_ref)


@dataclass
class _FakeClient:
    instance: Instance
    token: str = "ctfw1.cred.secret"
    health: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    transitions: list = field(default_factory=list)
    completed: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    replaced: bool = False
    claim_lease: JobLease | None = None
    # The worker the control plane (re)assigns the instance to on replace_instance.
    # Defaults to "w1" (this worker); set to a different name to simulate the
    # control plane placing the instance on ANOTHER worker.
    replace_to_worker: str = "w1"
    # The recorded build digest the control plane returns for digest-pinning;
    # None => nothing recorded, so pinning is skipped.
    expected_digest: str | None = None
    # The multi-service launch stack (empty => single-image launch path).
    stack: tuple = ()

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

    def expected_image_digest(self, instance_id, now):
        return self.expected_digest

    def launch_stack_services(self, instance_id, now):
        return self.stack

    def replace_instance(self, instance_id, now):
        self.replaced = True
        self.instance = Instance(
            instance_id=self.instance.instance_id,
            competition_id=self.instance.competition_id,
            team_name=self.instance.team_name,
            definition_slug=self.instance.definition_slug,
            version_no=self.instance.version_no,
            state=self.instance.state,
            assigned_worker=self.replace_to_worker,
            image_ref=self.instance.image_ref,
        )
        return self.instance

    def report_health(self, observation, now):
        self.health.append(observation)

    def report_runtime_resource(self, resource, now):
        self.resources.append(resource)

    def report_endpoint(self, endpoint, now):
        self.endpoints.append(endpoint)

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

    def test_launch_refuses_when_replaced_to_another_worker(self) -> None:
        # The launch contract re-places an unassigned instance, but the control
        # plane may assign it to a DIFFERENT worker. This worker MUST NOT launch an
        # instance it does not own (a report/transition would be ownership-rejected
        # and leak a live container). It fails the job RETRYABLE (a later re-place
        # may assign it here) and never calls backend.launch.
        client = _FakeClient(
            instance=_instance(assigned=None), replace_to_worker="other-worker"
        )
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend()
        _worker(client, backend).run_once()
        self.assertTrue(client.replaced)
        # No container was ever launched for an instance owned elsewhere.
        self.assertNotIn(("launch", "inst-1"), backend.calls)
        self.assertEqual(len(client.failed), 1)
        _job_id, error_class, retryable = client.failed[0]
        self.assertEqual(error_class, "internal")
        self.assertTrue(retryable)  # a later re-place may assign it to this worker
        self.assertEqual(client.completed, [])

    def test_unsupported_runtime_fails_non_retryable(self) -> None:
        client = _FakeClient(instance=_instance())
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend(raise_unsupported=True)
        _worker(client, backend).run_once()
        self.assertEqual(len(client.failed), 1)
        job_id, error_class, retryable = client.failed[0]
        # 'infrastructure' is the queue's error-class vocabulary for a host that
        # cannot satisfy the isolation policy; the specific cause is in the detail.
        self.assertEqual(error_class, "infrastructure")
        self.assertFalse(retryable)  # never retry a host that can't isolate
        self.assertEqual(client.completed, [])

    def test_digest_pinning_launches_when_local_image_matches(self) -> None:
        digest = "sha256:" + "ab" * 32
        client = _FakeClient(instance=_instance(), expected_digest=digest)
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend(image_local_id=digest)  # local image matches
        _worker(client, backend).run_once()
        self.assertIn(("launch", "inst-1"), backend.calls)
        self.assertEqual(len(client.completed), 1)
        self.assertEqual(client.failed, [])

    def test_digest_pinning_refuses_a_mismatched_image(self) -> None:
        client = _FakeClient(
            instance=_instance(), expected_digest="sha256:" + "ab" * 32
        )
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend(image_local_id="sha256:" + "cd" * 32)  # tampered
        _worker(client, backend).run_once()
        # Refused BEFORE launch, non-retryably (a tampered image cannot be fixed).
        self.assertNotIn(("launch", "inst-1"), backend.calls)
        self.assertEqual(len(client.failed), 1)
        _job, error_class, retryable = client.failed[0]
        self.assertEqual(error_class, "infrastructure")
        self.assertFalse(retryable)
        self.assertEqual(client.completed, [])

    def test_digest_pinning_refuses_a_missing_local_image(self) -> None:
        client = _FakeClient(
            instance=_instance(), expected_digest="sha256:" + "ab" * 32
        )
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend(image_local_id=None)  # recorded image absent
        _worker(client, backend).run_once()
        self.assertNotIn(("launch", "inst-1"), backend.calls)
        self.assertEqual(len(client.failed), 1)
        self.assertEqual(client.completed, [])

    def test_stack_instance_launches_the_whole_stack(self) -> None:
        from ctf_generator.domain.execution.runtime import StackServiceImage

        stack = (
            StackServiceImage(
                service_name="edge", image_ref="ir-edge",
                image_digest="sha256:" + "ee" * 32, depends_on=("internal",),
                expose=("8080",), is_primary=True,
            ),
            StackServiceImage(
                service_name="internal", image_ref="ir-internal",
                image_digest="sha256:" + "11" * 32, expose=("9443",),
            ),
        )
        client = _FakeClient(instance=_instance(), stack=stack)
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        # Backend image ids match each service's recorded digest by default? No --
        # image_local_id is a single value; make it match by returning the expected
        # per call is not possible with this fake, so record digests match via a
        # backend that echoes the ref->digest. Use a custom backend.
        backend = _StackBackend({"ir-edge": "sha256:" + "ee" * 32,
                                 "ir-internal": "sha256:" + "11" * 32})
        _worker(client, backend).run_once()
        # launch_stack was called with BOTH services, dependency-ordered
        # (internal before edge).
        stack_calls = [c for c in backend.calls if c[0] == "launch_stack"]
        self.assertEqual(len(stack_calls), 1)
        self.assertEqual(stack_calls[0][2], ("internal", "edge"))
        self.assertNotIn(("launch", "inst-1"), backend.calls)  # not the single path
        self.assertEqual(len(client.completed), 1)

    def test_stack_refuses_when_a_service_image_is_tampered(self) -> None:
        from ctf_generator.domain.execution.runtime import StackServiceImage

        stack = (
            StackServiceImage(
                service_name="edge", image_ref="ir-edge",
                image_digest="sha256:" + "ee" * 32, is_primary=True,
            ),
        )
        client = _FakeClient(instance=_instance(), stack=stack)
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _StackBackend({"ir-edge": "sha256:" + "ff" * 32})  # mismatch
        _worker(client, backend).run_once()
        self.assertNotIn("launch_stack", [c[0] for c in backend.calls])
        self.assertEqual(len(client.failed), 1)
        _job, error_class, retryable = client.failed[0]
        self.assertEqual(error_class, "infrastructure")
        self.assertFalse(retryable)

    def test_no_recorded_digest_skips_pinning(self) -> None:
        # Nothing recorded (expected None) -> pinning skipped -> launch proceeds
        # even though the backend would report a different id (never consulted).
        client = _FakeClient(instance=_instance(), expected_digest=None)
        client.claim_lease = _lease(
            "launch_instance", {"instance_id": "inst-1", "generation": 1, "action": "launch"}
        )
        backend = _FakeBackend(image_local_id="sha256:" + "cd" * 32)
        _worker(client, backend).run_once()
        self.assertIn(("launch", "inst-1"), backend.calls)
        self.assertEqual(len(client.completed), 1)
        self.assertNotIn(("image_id", "alpine:latest"), backend.calls)


    def test_stack_endpoints_are_service_qualified_and_do_not_collide(self) -> None:
        from ctf_generator.domain.execution.runtime import RuntimeEndpoint
        from ctf_generator.infrastructure.runtime.docker_backend import (
            LaunchResult,
        )

        client = _FakeClient(instance=_instance())
        worker = _worker(client, _FakeBackend())
        # Two services publish the SAME port number; their endpoint records must
        # NOT collide onto one name (the pre-fix bug reported both as "port-8080").
        launched = LaunchResult(
            observation=RuntimeObservation("inst-1", "cid1234567890", "running"),
            runtime_resources=(RuntimeResourceRef("container", "cid1234567890"),),
            endpoints=(
                RuntimeEndpoint(
                    container_port=8080, host="10.0.0.2", host_port=8080,
                    service="edge",
                ),
                RuntimeEndpoint(
                    container_port=8080, host="10.0.0.3", host_port=8080,
                    service="internal",
                ),
            ),
        )
        worker._report_launched_facts(client.instance, launched, _NOW)
        names = sorted(e.name for e in client.endpoints)
        self.assertEqual(names, ["edge-port-8080", "internal-port-8080"])

    def test_single_container_endpoint_keeps_the_bare_port_name(self) -> None:
        from ctf_generator.domain.execution.runtime import RuntimeEndpoint
        from ctf_generator.infrastructure.runtime.docker_backend import (
            LaunchResult,
        )

        client = _FakeClient(instance=_instance())
        worker = _worker(client, _FakeBackend())
        launched = LaunchResult(
            observation=RuntimeObservation("inst-1", "cid1234567890", "running"),
            runtime_resources=(RuntimeResourceRef("container", "cid1234567890"),),
            endpoints=(
                RuntimeEndpoint(container_port=8080, host="10.0.0.2", host_port=8080),
            ),
        )
        worker._report_launched_facts(client.instance, launched, _NOW)
        self.assertEqual([e.name for e in client.endpoints], ["port-8080"])


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

    def test_health_of_a_stack_is_unhealthy_when_one_service_crashed(self) -> None:
        # Two service containers; one has exited. A stack is healthy ONLY when
        # EVERY service is running, so the crashed sibling must not be invisible.
        client = _FakeClient(instance=_instance(state="healthy"))
        client.claim_lease = _lease(
            "run_health_check", {"instance_id": "inst-1", "generation": 1}
        )
        backend = _FakeBackend(
            containers=(("c-edge", "edge"), ("c-internal", "internal")),
            phase_by_cid={"c-edge": "running", "c-internal": "exited"},
        )
        _worker(client, backend).run_once()
        self.assertFalse(client.health[-1].healthy)
        self.assertEqual(client.health[-1].observed_state, "degraded")
        self.assertEqual(client.completed[-1][1], {"healthy": False, "services": 2})

    def test_health_of_a_stack_is_healthy_when_all_services_run(self) -> None:
        client = _FakeClient(instance=_instance(state="healthy"))
        client.claim_lease = _lease(
            "run_health_check", {"instance_id": "inst-1", "generation": 1}
        )
        backend = _FakeBackend(
            containers=(("c-edge", "edge"), ("c-internal", "internal")),
        )
        _worker(client, backend).run_once()
        self.assertTrue(client.health[-1].healthy)
        self.assertEqual(client.health[-1].observed_state, "healthy")

    def test_restart_walks_every_service_in_dependency_order(self) -> None:
        from ctf_generator.domain.execution.runtime import StackServiceImage

        stack = (
            StackServiceImage(
                service_name="edge", image_ref="ir-edge",
                image_digest="sha256:" + "ee" * 32, depends_on=("internal",),
                is_primary=True,
            ),
            StackServiceImage(
                service_name="internal", image_ref="ir-internal",
                image_digest="sha256:" + "11" * 32,
            ),
        )
        client = _FakeClient(instance=_instance(state="healthy"), stack=stack)
        client.claim_lease = _lease(
            "restart_instance", {"instance_id": "inst-1", "generation": 1}
        )
        # docker lists newest-first (edge, then internal); dependency order is
        # internal BEFORE edge -- restart must follow the manifest, not the listing.
        backend = _FakeBackend(
            containers=(("c-edge", "edge"), ("c-internal", "internal")),
        )
        _worker(client, backend).run_once()
        restarts = [c for c in backend.calls if c[0] == "restart"]
        self.assertEqual(
            [c[2] for c in restarts], ["c-internal", "c-edge"]
        )
        self.assertTrue(client.health[-1].healthy)

    def test_logs_are_collected_from_every_service(self) -> None:
        client = _FakeClient(instance=_instance(state="healthy"))
        client.claim_lease = _lease(
            "collect_logs", {"instance_id": "inst-1", "generation": 1}
        )
        backend = _FakeBackend(
            containers=(("c-edge", "edge"), ("c-internal", "internal")),
        )
        _worker(client, backend).run_once()
        collected = [c for c in backend.calls if c[0] == "collect_logs"]
        self.assertEqual(sorted(c[2] for c in collected), ["c-edge", "c-internal"])
        # 2 lines per container * 2 containers.
        self.assertEqual(client.completed[-1][1], {"log_lines": 4, "services": 2})

    def test_unknown_payload_without_instance_id_fails(self) -> None:
        client = _FakeClient(instance=_instance())
        client.claim_lease = _lease("launch_instance", {"generation": 1})
        _worker(client, _FakeBackend()).run_once()
        self.assertEqual(len(client.failed), 1)
        # Generic dispatch failures map to the queue's 'internal' class (the
        # exception type is preserved in error_detail, not the error_class).
        self.assertEqual(client.failed[0][1], "internal")

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
