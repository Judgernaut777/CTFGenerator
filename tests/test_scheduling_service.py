"""Pure host unit tests for ``SchedulingService`` control flow (M8).

No database: the service takes ``scheduler_factory`` / ``ledger_factory`` /
``policy_factory``, so we drive its placement loop with in-memory stubs to prove
the branch logic that the Docker-gated suite cannot force deterministically:

* a *worker-scope* ``QuotaExceededError`` skips the saturated candidate and
  retries the next one;
* a *non-worker* (shared-pool) ``QuotaExceededError`` propagates -- no candidate
  can help.
"""

from __future__ import annotations

import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    # ``SchedulingService`` imports SQLAlchemy at module load, so this suite
    # needs the db extra importable -- but NO database (it drives the service
    # entirely through injected stubs). It runs wherever the db extra is present
    # and skips cleanly on the bare stdlib host.
    from ctf_generator.application.scheduling.service import SchedulingService
    from ctf_generator.domain.scheduling.models import (
        PLATFORM_SCOPE_KEY,
        QuotaExceededError,
        QuotaReservation,
        ReservationItem,
        WorkerCandidate,
        WorkerRequirements,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_ENABLED = _IMPORT_ERROR is None
_SKIP_REASON = f"db extra not importable ({_IMPORT_ERROR})"

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


class _FakeSession:
    pass


class _FakeDatabase:
    @contextmanager
    def session_scope(self):
        yield _FakeSession()


class _StubScheduler:
    def __init__(self, candidates: list[WorkerCandidate]) -> None:
        self._candidates = candidates

    def candidate_workers(self, *args, **kwargs) -> list[WorkerCandidate]:
        return list(self._candidates)


class _StubLedger:
    """Replays ``reserve`` side effects (an exception is raised, anything else is
    returned) and records every demand it was handed."""

    def __init__(self, reserve_effects: list, get_result=None) -> None:
        self._effects = list(reserve_effects)
        self._get = get_result
        self.reserve_demands: list = []

    def get(self, reservation_id):
        return self._get

    def reserve(self, demand, now):
        self.reserve_demands.append(demand)
        effect = self._effects.pop(0)
        if isinstance(effect, Exception):
            raise effect
        return effect


class _StubPolicy:
    def upsert_limit(self, quota) -> None:  # no-op seed
        pass


def _service(scheduler: _StubScheduler, ledger: _StubLedger) -> SchedulingService:
    policy = _StubPolicy()
    return SchedulingService(
        _FakeDatabase(),
        scheduler_factory=lambda _session: scheduler,
        ledger_factory=lambda _session: ledger,
        policy_factory=lambda _session: policy,
    )


def _requirements() -> WorkerRequirements:
    return WorkerRequirements(
        "x86_64", frozenset({"launch_instance", "isolation:container"})
    )


def _reserve(svc: SchedulingService, rid: str):
    return svc.select_and_reserve(
        requirements=_requirements(),
        reservation_id=rid,
        pooled_items=(
            ReservationItem("platform", PLATFORM_SCOPE_KEY, "active_instances", 1),
        ),
        expires_at=_NOW + timedelta(hours=1),
        now=_NOW,
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class SelectAndReserveBranchTests(unittest.TestCase):
    def test_worker_saturation_skips_to_next_candidate(self) -> None:
        scheduler = _StubScheduler(
            [WorkerCandidate("busy", 1, 0), WorkerCandidate("free", 1, 0)]
        )
        placed = QuotaReservation("r1", "free", _NOW + timedelta(hours=1))
        ledger = _StubLedger(
            reserve_effects=[
                QuotaExceededError(
                    "worker full",
                    scope_type="worker",
                    scope_key="busy",
                    dimension="active_instances",
                ),
                placed,
            ]
        )
        svc = _service(scheduler, ledger)

        reservation, worker = _reserve(svc, "r1")

        self.assertEqual(worker, "free")
        self.assertIs(reservation, placed)
        # The saturated candidate was tried first, then skipped to the next.
        self.assertEqual([d.worker_key for d in ledger.reserve_demands], ["busy", "free"])

    def test_shared_pool_overrun_propagates(self) -> None:
        scheduler = _StubScheduler(
            [WorkerCandidate("busy", 5, 0), WorkerCandidate("other", 5, 0)]
        )
        ledger = _StubLedger(
            reserve_effects=[
                QuotaExceededError(
                    "platform pool full",
                    scope_type="platform",
                    scope_key=PLATFORM_SCOPE_KEY,
                    dimension="active_instances",
                )
            ]
        )
        svc = _service(scheduler, ledger)

        with self.assertRaises(QuotaExceededError) as ctx:
            _reserve(svc, "r1")
        self.assertEqual(ctx.exception.scope_type, "platform")
        # Propagated on the FIRST candidate -- the loop did not retry.
        self.assertEqual([d.worker_key for d in ledger.reserve_demands], ["busy"])


if __name__ == "__main__":
    unittest.main()
