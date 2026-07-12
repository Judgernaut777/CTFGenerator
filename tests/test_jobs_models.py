"""Host-pure unit tests for the job-queue domain aggregates (M7).

Stdlib only -- no database, no [db] extra. The Docker-gated integration suite
(test_jobs_repository_integration.py) proves the store enforces the same
rules; here we prove the domain rejects bad values at construction and that
the transition-matrix constant is self-consistent (the DB trigger mirrors it,
asserted pair-for-pair in the integration suite).
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctf_generator.domain.work.models import (
    LEGAL_JOB_TRANSITIONS,
    TERMINAL_JOB_STATUSES,
    VALID_JOB_ERROR_CLASSES,
    VALID_JOB_STATUSES,
    VALID_JOB_TYPES,
    Job,
    JobLease,
    JobTransition,
)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def _job(**overrides) -> Job:
    base = dict(
        job_id="7d5f5df1-9556-4d76-8a3d-000000000001",
        job_type="build_challenge",
        idempotency_key="build:sql:v1:abc123",
        available_at=_NOW,
    )
    base.update(overrides)
    return Job(**base)


class JobValidationTests(unittest.TestCase):
    def test_minimal_job_defaults(self) -> None:
        job = _job()
        self.assertEqual(job.status, "queued")
        self.assertEqual(job.priority, 100)
        self.assertEqual(job.attempt_count, 0)
        self.assertEqual(job.max_attempts, 3)
        self.assertEqual(job.required_capabilities, ())
        self.assertIsNone(job.claimed_by)

    def test_rejects_unknown_job_type(self) -> None:
        with self.assertRaises(ValueError):
            _job(job_type="mine_bitcoin")

    def test_rejects_unknown_status(self) -> None:
        with self.assertRaises(ValueError):
            _job(status="paused")

    def test_rejects_empty_idempotency_key(self) -> None:
        for bad in ("", "   ", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _job(idempotency_key=bad)

    def test_rejects_naive_available_at(self) -> None:
        with self.assertRaises(ValueError):
            _job(available_at=datetime(2026, 7, 12, 12, 0))

    def test_rejects_negative_priority(self) -> None:
        with self.assertRaises(ValueError):
            _job(priority=-1)

    def test_rejects_attempts_over_budget(self) -> None:
        with self.assertRaises(ValueError):
            _job(attempt_count=4, max_attempts=3)

    def test_rejects_zero_max_attempts(self) -> None:
        with self.assertRaises(ValueError):
            _job(max_attempts=0)

    def test_rejects_zero_backoff(self) -> None:
        with self.assertRaises(ValueError):
            _job(backoff_base_seconds=0)

    def test_rejects_unknown_error_class(self) -> None:
        with self.assertRaises(ValueError):
            _job(error_class="whoopsie")

    def test_rejects_non_tuple_capabilities(self) -> None:
        with self.assertRaises(ValueError):
            _job(required_capabilities=["docker"])  # list, not tuple

    def test_rejects_blank_capability(self) -> None:
        with self.assertRaises(ValueError):
            _job(required_capabilities=("docker", " "))

    def test_rejects_half_given_version_pair(self) -> None:
        with self.assertRaises(ValueError):
            _job(definition_slug="sql", version_no=None)
        with self.assertRaises(ValueError):
            _job(definition_slug=None, version_no=1)

    def test_accepts_full_audit_linkage(self) -> None:
        job = _job(competition_id="cup", definition_slug="sql", version_no=2)
        self.assertEqual(job.competition_id, "cup")
        self.assertEqual(job.version_no, 2)

    def test_payload_excluded_from_equality(self) -> None:
        a = _job(payload={"build_sha256": "aa"})
        b = _job(payload={"build_sha256": "bb"})
        self.assertEqual(a, b)  # payload is compare=False, like ScoreEvent


class JobLeaseTests(unittest.TestCase):
    # (lease_token values below are test fixtures, not secrets -- S106 noqa'd)

    def test_valid_lease(self) -> None:
        lease = JobLease(job=_job(), lease_token="tok-1", lease_expires_at=_NOW)  # noqa: S106
        self.assertEqual(lease.lease_token, "tok-1")

    def test_rejects_blank_token(self) -> None:
        with self.assertRaises(ValueError):
            JobLease(job=_job(), lease_token=" ", lease_expires_at=_NOW)  # noqa: S106

    def test_rejects_naive_expiry(self) -> None:
        with self.assertRaises(ValueError):
            JobLease(
                job=_job(),
                lease_token="tok",  # noqa: S106
                lease_expires_at=datetime(2026, 7, 12),
            )

    def test_rejects_non_job(self) -> None:
        with self.assertRaises(ValueError):
            JobLease(job="job", lease_token="tok", lease_expires_at=_NOW)  # noqa: S106


class JobTransitionTests(unittest.TestCase):
    def test_enqueue_transition_from_none(self) -> None:
        t = JobTransition(
            job_id="j1", from_status=None, to_status="queued", attempt=0,
            occurred_at=_NOW,
        )
        self.assertIsNone(t.from_status)

    def test_rejects_unknown_statuses(self) -> None:
        with self.assertRaises(ValueError):
            JobTransition(
                job_id="j1", from_status="bogus", to_status="queued", attempt=0,
                occurred_at=_NOW,
            )
        with self.assertRaises(ValueError):
            JobTransition(
                job_id="j1", from_status=None, to_status="bogus", attempt=0,
                occurred_at=_NOW,
            )

    def test_rejects_negative_attempt(self) -> None:
        with self.assertRaises(ValueError):
            JobTransition(
                job_id="j1", from_status=None, to_status="queued", attempt=-1,
                occurred_at=_NOW,
            )

    def test_rejects_unknown_error_class(self) -> None:
        with self.assertRaises(ValueError):
            JobTransition(
                job_id="j1", from_status="running", to_status="failed", attempt=1,
                occurred_at=_NOW, error_class="oops",
            )


class TransitionMatrixTests(unittest.TestCase):
    """The single-source-of-truth constant the DB trigger mirrors."""

    def test_every_status_has_an_entry(self) -> None:
        self.assertEqual(set(LEGAL_JOB_TRANSITIONS), VALID_JOB_STATUSES)

    def test_targets_are_valid_statuses(self) -> None:
        for source, targets in LEGAL_JOB_TRANSITIONS.items():
            self.assertLessEqual(
                targets, VALID_JOB_STATUSES, f"bad targets for {source}"
            )

    def test_no_self_transitions(self) -> None:
        # Self "transitions" are field updates, not state moves.
        for source, targets in LEGAL_JOB_TRANSITIONS.items():
            self.assertNotIn(source, targets)

    def test_terminal_statuses(self) -> None:
        # succeeded/failed/cancelled are fully terminal; dead_letter's one
        # exit is the operator requeue.
        self.assertEqual(LEGAL_JOB_TRANSITIONS["succeeded"], frozenset())
        self.assertEqual(LEGAL_JOB_TRANSITIONS["failed"], frozenset())
        self.assertEqual(LEGAL_JOB_TRANSITIONS["cancelled"], frozenset())
        self.assertEqual(LEGAL_JOB_TRANSITIONS["dead_letter"], frozenset({"queued"}))
        self.assertEqual(
            TERMINAL_JOB_STATUSES,
            frozenset({"succeeded", "failed", "cancelled", "dead_letter"}),
        )

    def test_expected_flow_paths_exist(self) -> None:
        self.assertIn("claimed", LEGAL_JOB_TRANSITIONS["queued"])
        self.assertIn("running", LEGAL_JOB_TRANSITIONS["claimed"])
        self.assertIn("succeeded", LEGAL_JOB_TRANSITIONS["running"])
        self.assertIn("queued", LEGAL_JOB_TRANSITIONS["claimed"])  # lease expiry
        self.assertIn("queued", LEGAL_JOB_TRANSITIONS["running"])  # retryable
        self.assertIn("dead_letter", LEGAL_JOB_TRANSITIONS["running"])

    def test_twelve_job_types_and_seven_statuses(self) -> None:
        self.assertEqual(len(VALID_JOB_TYPES), 12)
        self.assertEqual(len(VALID_JOB_STATUSES), 7)
        self.assertEqual(len(VALID_JOB_ERROR_CLASSES), 7)


if __name__ == "__main__":
    unittest.main()
