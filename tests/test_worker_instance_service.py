"""Pure unit tests for the worker instance-fact trust gate (no DB, no docker).

Proves the ownership + scope boundary that closes the unauthenticated fact/
transition seam: a worker may report health/resources/endpoints and drive a
transition ONLY for an instance assigned to IT, and ONLY with the right scope.
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

try:
    from ctf_generator.application.execution.worker_instance_service import (
        InstanceOwnershipError,
        WorkerAuthenticationError,
        WorkerInstanceService,
    )
    from ctf_generator.application.worker_enrollment import (
        AuthenticatedWorker,
        ScopeError,
    )
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.instances.models import (
        HealthObservation,
        Instance,
        InstanceEndpoint,
        RuntimeResource,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - the db extra pulls sqlalchemy
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
_ALL_SCOPES = ("instances:report", "instances:transition")


def _worker(name: str) -> Worker:
    return Worker(
        name=name, runtime_type="docker-rootless", architectures=("aarch64",),
        capabilities=("launch_instance",), capacity=2, version="1",
        trust_state="trusted",
    )


def _instance(assigned: str | None) -> Instance:
    return Instance(
        instance_id="inst-1", competition_id="cup", team_name="Red",
        definition_slug="sql", version_no=1, state="queued",
        assigned_worker=assigned,
    )


@dataclass
class _FakeEnrollment:
    worker_name: str | None = "w1"
    scopes: tuple[str, ...] = _ALL_SCOPES

    def authenticate(self, token, now):
        if self.worker_name is None:
            return None
        return AuthenticatedWorker(
            worker=_worker(self.worker_name),
            credential_id="cred-1",
            scopes=self.scopes,
            expires_at=now + timedelta(hours=1),
        )


@dataclass
class _FakeLifecycle:
    instance: Instance | None
    observations: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    transitions: list = field(default_factory=list)

    def get(self, instance_id):
        return self.instance

    def record_observation(self, obs):
        self.observations.append(obs)

    def record_runtime_resource(self, res):
        self.resources.append(res)

    def record_endpoint(self, ep):
        self.endpoints.append(ep)

    def apply_transition(self, instance_id, to_state, *, reason, actor, now):
        self.transitions.append((to_state, actor))


def _svc(*, assigned="w1", worker_name="w1", scopes=_ALL_SCOPES):
    life = _FakeLifecycle(instance=_instance(assigned))
    enroll = _FakeEnrollment(worker_name=worker_name, scopes=scopes)
    return WorkerInstanceService(life, enroll), life  # type: ignore[arg-type]


def _health(worker="w1"):
    return HealthObservation(
        instance_id="inst-1", observed_state="healthy", healthy=True,
        worker=worker, generation=1, observed_at=_NOW,
    )


@unittest.skipUnless(_IMPORT_ERROR is None, f"db extra not importable ({_IMPORT_ERROR})")
class OwnershipTests(unittest.TestCase):
    def test_owner_can_report_and_transition(self) -> None:
        svc, life = _svc(assigned="w1", worker_name="w1")
        svc.report_health("tok", _health("w1"), _NOW)
        svc.report_runtime_resource(
            "tok", RuntimeResource("inst-1", "container", "c1", "w1"), _NOW
        )
        svc.report_endpoint(
            "tok",
            InstanceEndpoint("inst-1", "port-8080", "10.0.0.2", 8080, "tcp",
                             "tcp://10.0.0.2:8080", internal=True),
            _NOW,
        )
        svc.transition_instance("tok", "inst-1", "starting", reason="up", now=_NOW)
        self.assertEqual(len(life.observations), 1)
        self.assertEqual(len(life.resources), 1)
        self.assertEqual(len(life.endpoints), 1)
        self.assertEqual(life.transitions, [("starting", "worker")])

    def test_non_owner_cannot_report(self) -> None:
        # Instance assigned to w2 but the credential is w1.
        svc, life = _svc(assigned="w2", worker_name="w1")
        with self.assertRaises(InstanceOwnershipError):
            svc.report_health("tok", _health("w1"), _NOW)
        self.assertEqual(life.observations, [])

    def test_non_owner_cannot_report_endpoint(self) -> None:
        # Endpoints are reported through the same ownership gate: a worker not
        # assigned the instance may not register a reachable endpoint for it.
        svc, life = _svc(assigned="w2", worker_name="w1")
        with self.assertRaises(InstanceOwnershipError):
            svc.report_endpoint(
                "tok",
                InstanceEndpoint("inst-1", "port-8080", "10.0.0.2", 8080, "tcp",
                                 "tcp://10.0.0.2:8080", internal=True),
                _NOW,
            )
        self.assertEqual(life.endpoints, [])

    def test_non_owner_cannot_transition(self) -> None:
        svc, life = _svc(assigned="w2", worker_name="w1")
        with self.assertRaises(InstanceOwnershipError):
            svc.transition_instance("tok", "inst-1", "starting", reason="x", now=_NOW)
        self.assertEqual(life.transitions, [])

    def test_cannot_stamp_report_as_another_worker(self) -> None:
        # Owner is w1, but the report claims worker=w2 -> rejected.
        svc, life = _svc(assigned="w1", worker_name="w1")
        with self.assertRaises(InstanceOwnershipError):
            svc.report_health("tok", _health("w2"), _NOW)
        with self.assertRaises(InstanceOwnershipError):
            svc.report_runtime_resource(
                "tok", RuntimeResource("inst-1", "container", "c1", "w2"), _NOW
            )
        self.assertEqual(life.observations, [])
        self.assertEqual(life.resources, [])

    def test_scope_mismatch_rejected(self) -> None:
        # Has report but NOT transition scope.
        svc, _ = _svc(scopes=("instances:report",))
        with self.assertRaises(ScopeError):
            svc.transition_instance("tok", "inst-1", "starting", reason="x", now=_NOW)
        # Has transition but NOT report scope.
        svc2, _ = _svc(scopes=("instances:transition",))
        with self.assertRaises(ScopeError):
            svc2.report_health("tok", _health("w1"), _NOW)

    def test_bad_credential_rejected(self) -> None:
        svc, _ = _svc(worker_name=None)  # authenticate -> None
        with self.assertRaises(WorkerAuthenticationError):
            svc.report_health("tok", _health("w1"), _NOW)

    def test_missing_instance_is_lookup_error(self) -> None:
        life = _FakeLifecycle(instance=None)
        svc = WorkerInstanceService(life, _FakeEnrollment())  # type: ignore[arg-type]
        with self.assertRaises(LookupError):
            svc.report_health("tok", _health("w1"), _NOW)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
