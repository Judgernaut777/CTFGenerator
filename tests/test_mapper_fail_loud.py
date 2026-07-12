"""Fail-loud mapper unit tests for the M7 fresh-insert paths.

Pure (no database) but import the infrastructure mappers, which pull in
SQLAlchemy -- so these are gated on the [db] extra being importable (not on a
running PostgreSQL) and skip cleanly on the stdlib host.

    PYTHONPATH=src:tests python -m unittest test_mapper_fail_loud
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

try:
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.work.models import Job
    from ctf_generator.infrastructure.database.mappers import (
        job_to_orm,
        worker_to_orm,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_ENABLED = _IMPORT_ERROR is None
_SKIP_REASON = f"db extra not importable ({_IMPORT_ERROR})"
_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def _worker(**overrides) -> Worker:
    base = dict(
        name="w1",
        runtime_type="docker-rootless",
        architectures=("arm64",),
        capabilities=("build_challenge",),
        capacity=2,
        version="0.7.0",
    )
    base.update(overrides)
    return Worker(**base)


def _job(**overrides) -> Job:
    base = dict(
        job_id="7d5f5df1-9556-4d76-8a3d-000000000001",
        job_type="build_challenge",
        idempotency_key="k1",
        available_at=_NOW,
    )
    base.update(overrides)
    return Job(**base)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerToOrmFreshFailLoudTests(unittest.TestCase):
    def test_clean_pending_worker_maps(self) -> None:
        # The fresh path deliberately leaves trust_state to the DB default, so
        # it is unset (None) on the un-flushed row -- assert the identity/profile
        # fields the mapper does populate.
        row = worker_to_orm(_worker())
        self.assertEqual(row.name, "w1")
        self.assertEqual(row.runtime_type, "docker-rootless")
        self.assertEqual(row.capacity, 2)

    def test_non_pending_rejected(self) -> None:
        with self.assertRaises(ValueError):
            worker_to_orm(_worker(trust_state="revoked", revoked_at=_NOW))

    def test_each_operational_stamp_rejected_on_fresh_insert(self) -> None:
        for overrides in (
            {"drain_requested_at": _NOW},
            {"quarantined_at": _NOW, "quarantine_reason": "x"},
            {"last_heartbeat_at": _NOW},
        ):
            with self.subTest(overrides=tuple(overrides)):
                with self.assertRaises(ValueError):
                    worker_to_orm(_worker(**overrides))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class JobToOrmFreshFailLoudTests(unittest.TestCase):
    def test_clean_queued_job_maps(self) -> None:
        row = job_to_orm(_job(), None, None)
        self.assertEqual(row.status, "queued")
        self.assertEqual(row.attempt_count, 0)

    def test_non_queued_rejected(self) -> None:
        with self.assertRaises(ValueError):
            job_to_orm(_job(status="cancelled", finished_at=_NOW), None, None)

    def test_each_lifecycle_field_rejected_on_fresh_insert(self) -> None:
        for overrides in (
            {"claimed_by": "w1"},
            {"heartbeat_at": _NOW},
            {"lease_expires_at": _NOW},
            {"cancel_requested_at": _NOW},
            {"started_at": _NOW},
            {"finished_at": _NOW},
            {"error_class": "transient"},
            {"error_detail": "boom"},
            {"result_json": {"a": 1}},
            {"result_ref": "artifacts/x"},
            {"log_ref": "logs/x"},
        ):
            with self.subTest(overrides=tuple(overrides)):
                with self.assertRaises(ValueError):
                    job_to_orm(_job(**overrides), None, None)

    def test_nonzero_attempt_count_rejected(self) -> None:
        with self.assertRaises(ValueError):
            job_to_orm(_job(attempt_count=1, max_attempts=3), None, None)


if __name__ == "__main__":
    unittest.main()
