"""Pure host unit tests for the scheduling/quota domain + runtime interface (M8).

No database, no framework -- these exercise the frozen value objects, their
invariants, and the pure helpers. They stay green in the stdlib host suite.
"""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

from ctf_generator.domain.execution.runtime import (
    VALID_NETWORK_MODES,
    ContainerPolicy,
    ContainerRequest,
    RuntimeCapabilities,
    RuntimeEndpoint,
    RuntimeObservation,
)
from ctf_generator.domain.scheduling.models import (
    CEILING_DIMENSIONS,
    PLATFORM_SCOPE_KEY,
    POOLED_DIMENSIONS,
    VALID_DIMENSIONS,
    CeilingRequirement,
    NoEligibleWorkerError,
    QuotaExceededError,
    QuotaReservation,
    ReservationItem,
    ResourceDemand,
    ResourceQuota,
    WorkerCandidate,
    WorkerRequirements,
    isolation_capability,
    requirements_from_family,
    worker_matches,
)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


class _FakeFamily:
    def __init__(self, isolation_level: str, archs: tuple[str, ...]) -> None:
        self.isolation_level = isolation_level
        self.supported_architectures = archs


class ResourceQuotaTests(unittest.TestCase):
    def test_available_is_headroom(self) -> None:
        self.assertEqual(ResourceQuota("platform", "p", "cpu_millis", 10, 3).available, 7)

    def test_available_never_negative_after_limit_reduction(self) -> None:
        # A lowered limit below reserved is legal (holds grandfathered).
        self.assertEqual(
            ResourceQuota("team", "t", "active_instances", 2, 5).available, 0
        )

    def test_ceiling_dimension_forbids_nonzero_reserved(self) -> None:
        with self.assertRaises(ValueError):
            ResourceQuota("platform", "p", "max_runtime_seconds", 100, 1)

    def test_ceiling_dimension_allows_zero_reserved(self) -> None:
        ResourceQuota("platform", "p", "max_runtime_seconds", 100, 0)

    def test_invalid_scope_and_dimension_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ResourceQuota("galaxy", "p", "cpu_millis", 1)
        with self.assertRaises(ValueError):
            ResourceQuota("platform", "p", "warp_cores", 1)

    def test_negative_limit_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ResourceQuota("platform", "p", "cpu_millis", -1)

    def test_frozen(self) -> None:
        q = ResourceQuota("platform", "p", "cpu_millis", 10)
        with self.assertRaises(FrozenInstanceError):
            q.limit_value = 20  # type: ignore[misc]

    def test_dimension_sets_partition(self) -> None:
        self.assertEqual(POOLED_DIMENSIONS & CEILING_DIMENSIONS, frozenset())
        self.assertEqual(POOLED_DIMENSIONS | CEILING_DIMENSIONS, VALID_DIMENSIONS)


class ReservationItemTests(unittest.TestCase):
    def test_pooled_only(self) -> None:
        with self.assertRaises(ValueError):
            ReservationItem("platform", "p", "max_runtime_seconds", 1)

    def test_amount_positive(self) -> None:
        with self.assertRaises(ValueError):
            ReservationItem("platform", "p", "cpu_millis", 0)

    def test_valid(self) -> None:
        item = ReservationItem("worker", "w1", "active_instances", 1)
        self.assertEqual(item.amount, 1)


class CeilingRequirementTests(unittest.TestCase):
    def test_ceiling_only(self) -> None:
        with self.assertRaises(ValueError):
            CeilingRequirement("platform", "p", "cpu_millis", 1)

    def test_valid(self) -> None:
        CeilingRequirement("challenge", "c", "max_runtime_seconds", 3600)


class ResourceDemandTests(unittest.TestCase):
    def _item(self, scope="platform", key=PLATFORM_SCOPE_KEY, dim="cpu_millis", amt=1):
        return ReservationItem(scope, key, dim, amt)

    def test_requires_at_least_one_item_or_ceiling(self) -> None:
        with self.assertRaises(ValueError):
            ResourceDemand("r1", "w1", _NOW)

    def test_duplicate_item_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ResourceDemand("r1", "w1", _NOW, items=(self._item(), self._item()))

    def test_sorted_items_deterministic(self) -> None:
        demand = ResourceDemand(
            "r1",
            "w1",
            _NOW,
            items=(
                ReservationItem("worker", "w1", "active_instances", 1),
                ReservationItem("platform", PLATFORM_SCOPE_KEY, "cpu_millis", 2),
                ReservationItem("competition", "c", "memory_mb", 3),
            ),
        )
        order = [(i.scope_type, i.scope_key, i.dimension) for i in demand.sorted_items()]
        self.assertEqual(order, sorted(order))
        # worker scope sorts last, so shared pools are checked before capacity.
        self.assertEqual(order[-1][0], "worker")

    def test_ceiling_only_demand_allowed(self) -> None:
        ResourceDemand(
            "r1",
            "w1",
            _NOW,
            ceilings=(CeilingRequirement("platform", "p", "max_runtime_seconds", 60),),
        )


class QuotaReservationTests(unittest.TestCase):
    def test_released_requires_timestamp(self) -> None:
        with self.assertRaises(ValueError):
            QuotaReservation("r1", "w1", _NOW, state="released")

    def test_held_forbids_released_at(self) -> None:
        with self.assertRaises(ValueError):
            QuotaReservation("r1", "w1", _NOW, state="held", released_at=_NOW)

    def test_valid_held(self) -> None:
        r = QuotaReservation("r1", "w1", _NOW)
        self.assertEqual(r.state, "held")


class WorkerRequirementsAndMatchTests(unittest.TestCase):
    def test_requirements_from_family(self) -> None:
        fam = _FakeFamily("container", ("x86_64", "arm64"))
        req = requirements_from_family(fam, "arm64")
        self.assertEqual(req.architecture, "arm64")
        self.assertIn("launch_instance", req.required_capabilities)
        self.assertIn(isolation_capability("container"), req.required_capabilities)

    def test_requirements_from_family_rejects_unsupported_arch(self) -> None:
        fam = _FakeFamily("container", ("x86_64",))
        with self.assertRaises(ValueError):
            requirements_from_family(fam, "arm64")

    def test_worker_matches_all_axes(self) -> None:
        req = WorkerRequirements(
            "x86_64", frozenset({"launch_instance", "isolation:container"})
        )
        self.assertTrue(
            worker_matches(
                architectures=("x86_64",),
                capabilities=("launch_instance", "isolation:container", "collect_logs"),
                runtime_type="docker-rootless",
                requirements=req,
            )
        )

    def test_worker_matches_fails_on_missing_arch(self) -> None:
        req = WorkerRequirements("arm64", frozenset({"launch_instance"}))
        self.assertFalse(
            worker_matches(
                architectures=("x86_64",),
                capabilities=("launch_instance",),
                runtime_type="docker-rootless",
                requirements=req,
            )
        )

    def test_worker_matches_fails_on_missing_capability(self) -> None:
        req = WorkerRequirements(
            "x86_64", frozenset({"launch_instance", "isolation:raw_tcp"})
        )
        self.assertFalse(
            worker_matches(
                architectures=("x86_64",),
                capabilities=("launch_instance", "isolation:container"),
                runtime_type="docker-rootless",
                requirements=req,
            )
        )

    def test_worker_matches_runtime_constraint(self) -> None:
        req = WorkerRequirements(
            "x86_64", frozenset({"launch_instance"}), runtime_type="podman-rootless"
        )
        self.assertFalse(
            worker_matches(
                architectures=("x86_64",),
                capabilities=("launch_instance",),
                runtime_type="docker-rootless",
                requirements=req,
            )
        )


class WorkerCandidateTests(unittest.TestCase):
    def test_free_capacity(self) -> None:
        self.assertEqual(WorkerCandidate("w1", 5, 2).free_capacity, 3)

    def test_free_capacity_clamped(self) -> None:
        self.assertEqual(WorkerCandidate("w1", 2, 5).free_capacity, 0)


class QuotaExceededErrorTests(unittest.TestCase):
    def test_carries_scope(self) -> None:
        err = QuotaExceededError("boom", scope_type="worker", dimension="active_instances")
        self.assertEqual(err.scope_type, "worker")
        self.assertEqual(err.dimension, "active_instances")

    def test_distinct_from_no_eligible(self) -> None:
        self.assertFalse(issubclass(QuotaExceededError, NoEligibleWorkerError))


class ContainerPolicyTests(unittest.TestCase):
    def test_secure_defaults(self) -> None:
        p = ContainerPolicy(memory_mb=512, cpu_millis=1000)
        self.assertTrue(p.read_only_rootfs)
        self.assertTrue(p.drop_all_capabilities)
        self.assertTrue(p.no_new_privileges)
        self.assertTrue(p.run_as_non_root)
        self.assertTrue(p.user_namespace)
        self.assertFalse(p.privileged)
        self.assertIn(p.network_mode, VALID_NETWORK_MODES)

    def test_privileged_forbidden(self) -> None:
        with self.assertRaises(ValueError):
            ContainerPolicy(memory_mb=512, cpu_millis=1000, privileged=True)

    def test_hardening_flags_cannot_be_disabled(self) -> None:
        for flag in (
            "read_only_rootfs",
            "drop_all_capabilities",
            "no_new_privileges",
            "run_as_non_root",
            "user_namespace",
        ):
            with self.assertRaises(ValueError, msg=flag):
                ContainerPolicy(memory_mb=512, cpu_millis=1000, **{flag: False})

    def test_bad_network_mode_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ContainerPolicy(memory_mb=512, cpu_millis=1000, network_mode="host")

    def test_non_positive_resources_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ContainerPolicy(memory_mb=0, cpu_millis=1000)


class RuntimeCapabilitiesTests(unittest.TestCase):
    def _caps(self, **over) -> RuntimeCapabilities:
        base = dict(
            runtime_type="docker-rootless",
            rootless=True,
            supported_architectures=("x86_64",),
            supports_user_namespaces=True,
            supports_seccomp=True,
            supports_readonly_rootfs=True,
            max_memory_mb=4096,
        )
        base.update(over)
        return RuntimeCapabilities(**base)

    def test_rootful_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._caps(rootless=False)

    def test_satisfies_policy(self) -> None:
        self.assertTrue(
            self._caps().satisfies(ContainerPolicy(memory_mb=512, cpu_millis=1000))
        )

    def test_refuses_policy_over_memory(self) -> None:
        self.assertFalse(
            self._caps(max_memory_mb=256).satisfies(
                ContainerPolicy(memory_mb=512, cpu_millis=1000)
            )
        )

    def test_refuses_policy_without_seccomp(self) -> None:
        self.assertFalse(
            self._caps(supports_seccomp=False).satisfies(
                ContainerPolicy(memory_mb=512, cpu_millis=1000)
            )
        )


class RuntimeRequestObservationTests(unittest.TestCase):
    def test_request_rejects_bad_port(self) -> None:
        pol = ContainerPolicy(memory_mb=512, cpu_millis=1000)
        with self.assertRaises(ValueError):
            ContainerRequest("i1", "team-a", "img:1", pol, exposed_ports=(70000,))

    def test_request_valid(self) -> None:
        pol = ContainerPolicy(memory_mb=512, cpu_millis=1000)
        req = ContainerRequest("i1", "team-a", "img:1", pol, exposed_ports=(8080,))
        self.assertEqual(req.exposed_ports, (8080,))

    def test_observation_phase_validated(self) -> None:
        with self.assertRaises(ValueError):
            RuntimeObservation("i1", "c1", "levitating")

    def test_observation_with_endpoint(self) -> None:
        obs = RuntimeObservation(
            "i1",
            "c1",
            "running",
            endpoints=(RuntimeEndpoint(8080, "10.0.0.5", 34000),),
        )
        self.assertEqual(obs.endpoints[0].host_port, 34000)


if __name__ == "__main__":
    unittest.main()
