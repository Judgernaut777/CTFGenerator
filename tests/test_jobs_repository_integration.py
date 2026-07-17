"""PostgreSQL integration tests for the durable job queue (M7, ADR-003).

Docker-gated like the other repository suites; skips cleanly without the db
extra / CTFGEN_TEST_DATABASE_URL so the stdlib host suite stays green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_jobs_repository_integration
"""

from __future__ import annotations

import os
import threading
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy import event
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import IntegrityError, ProgrammingError

    from ctf_generator.application.jobs.service import (
        JobIdempotencyConflictError,
        JobService,
    )
    from ctf_generator.domain.authoring.models import (
        ChallengeDefinition,
        ChallengeVersion,
    )
    from ctf_generator.domain.challenges.models import CompetitionConfig
    from ctf_generator.domain.work.models import (
        LEGAL_JOB_TRANSITIONS,
        TERMINAL_JOB_STATUSES,
        VALID_JOB_STATUSES,
        Job,
    )
    from ctf_generator.infrastructure.database.challenge_definition_repository import (
        SqlAlchemyChallengeDefinitionRepository,
    )
    from ctf_generator.infrastructure.database.challenge_version_repository import (
        SqlAlchemyChallengeVersionRepository,
    )
    from ctf_generator.infrastructure.database.competition_repository import (
        SqlAlchemyCompetitionRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.job_queue_repository import (
        SqlAlchemyJobQueue,
    )
    from ctf_generator.infrastructure.database.session import Database

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"db extra not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_it_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _alembic_config(url) -> AlembicConfig:
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


@contextmanager
def _migrated_database():
    with _isolated_database() as url:
        command.upgrade(_alembic_config(url), "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield db, url
        finally:
            db.dispose()


@contextmanager
def _count_statements(engine):
    """Counts SQL statements executed against ``engine`` for the duration of
    the ``with`` block (a query-count oracle for the N+1 regression test)."""
    counter = {"n": 0}

    def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        counter["n"] += 1

    event.listen(engine, "before_cursor_execute", _before_cursor_execute)
    try:
        yield counter
    finally:
        event.remove(engine, "before_cursor_execute", _before_cursor_execute)


def _job(idempotency_key: str | None = None, **overrides) -> Job:
    base = dict(
        job_id=str(uuid.uuid4()),
        job_type="build_challenge",
        idempotency_key=idempotency_key or f"key-{uuid.uuid4().hex}",
        available_at=_NOW,
    )
    base.update(overrides)
    return Job(**base)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class JobEnqueueTests(unittest.TestCase):
    def test_enqueue_get_round_trip_with_transition(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job(
                priority=5,
                payload={"build_sha256": "abc"},
                required_capabilities=("docker", "arm64"),
            )
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with db.session_scope() as s:
                queue = SqlAlchemyJobQueue(s)
                got = queue.get(job.job_id)
                by_key = queue.get_by_idempotency_key(job.idempotency_key)
                history = queue.list_transitions(job.job_id)
        self.assertIsNotNone(got)
        self.assertEqual(got.status, "queued")
        self.assertEqual(got.priority, 5)
        self.assertEqual(got.payload, {"build_sha256": "abc"})
        self.assertEqual(got.required_capabilities, ("arm64", "docker"))  # sorted
        self.assertIsNotNone(got.created_at)
        self.assertEqual(by_key.job_id, got.job_id)
        self.assertEqual(len(history), 1)
        self.assertIsNone(history[0].from_status)
        self.assertEqual(history[0].to_status, "queued")

    def test_enqueue_with_audit_linkage_unknown_competition_fails_loud(self) -> None:
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).enqueue(_job(competition_id="ghost"))

    def test_duplicate_idempotency_key_raises_integrity_error(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(_job(idempotency_key="dup-1"))
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).enqueue(_job(idempotency_key="dup-1"))

    def test_enqueue_idempotent_service_returns_original(self) -> None:
        with _migrated_database() as (db, _url):
            service = JobService(db)
            first, created1 = service.enqueue_idempotent(
                _job(idempotency_key="dup-2")
            )
            second, created2 = service.enqueue_idempotent(
                _job(idempotency_key="dup-2")
            )
        self.assertTrue(created1)
        self.assertFalse(created2)
        self.assertEqual(second.job_id, first.job_id)

    def test_enqueue_transition_recorded_at_now_not_available_at(self) -> None:
        with _migrated_database() as (db, _url):
            enqueue_at = _NOW
            available_at = _NOW + timedelta(hours=2)  # future dispatch gate
            job = _job(available_at=available_at)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job, enqueue_at)
            with db.session_scope() as s:
                queue = SqlAlchemyJobQueue(s)
                got = queue.get(job.job_id)
                history = queue.list_transitions(job.job_id)
        self.assertEqual(got.available_at, available_at)  # gate unchanged
        self.assertEqual(history[0].occurred_at, enqueue_at)  # audit at now

    def test_enqueue_idempotent_conflicting_payload_raises(self) -> None:
        with _migrated_database() as (db, _url):
            service = JobService(db)
            service.enqueue_idempotent(
                _job(idempotency_key="idk", payload={"build_sha256": "aa"})
            )
            with self.assertRaises(JobIdempotencyConflictError):
                service.enqueue_idempotent(
                    _job(idempotency_key="idk", payload={"build_sha256": "bb"})
                )

    def test_enqueue_idempotent_conflicting_job_type_raises(self) -> None:
        with _migrated_database() as (db, _url):
            service = JobService(db)
            service.enqueue_idempotent(
                _job(idempotency_key="idk2", job_type="build_challenge")
            )
            with self.assertRaises(JobIdempotencyConflictError):
                service.enqueue_idempotent(
                    _job(idempotency_key="idk2", job_type="collect_logs")
                )

    def test_enqueue_idempotent_identical_request_collapses(self) -> None:
        with _migrated_database() as (db, _url):
            service = JobService(db)
            first, created1 = service.enqueue_idempotent(
                _job(
                    idempotency_key="idk3",
                    payload={"build_sha256": "aa"},
                    required_capabilities=("docker", "arm64"),
                )
            )
            second, created2 = service.enqueue_idempotent(
                _job(
                    idempotency_key="idk3",
                    payload={"build_sha256": "aa"},
                    required_capabilities=("arm64", "docker"),  # order differs
                )
            )
        self.assertTrue(created1)
        self.assertFalse(created2)
        self.assertEqual(second.job_id, first.job_id)

    def test_get_malformed_or_absent_id_returns_none(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                queue = SqlAlchemyJobQueue(s)
                self.assertIsNone(queue.get("not-a-uuid"))
                self.assertIsNone(queue.get(str(uuid.uuid4())))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class JobClaimTests(unittest.TestCase):
    def test_claim_orders_by_priority_then_available_at(self) -> None:
        with _migrated_database() as (db, _url):
            low = _job(priority=200)
            high = _job(priority=1)
            with db.session_scope() as s:
                queue = SqlAlchemyJobQueue(s)
                queue.enqueue(low)
                queue.enqueue(high)
            with db.session_scope() as s:
                lease = SqlAlchemyJobQueue(s).claim(
                    "w1", frozenset(), 60, _NOW
                )
        self.assertIsNotNone(lease)
        self.assertEqual(lease.job.job_id, high.job_id)
        self.assertEqual(lease.job.status, "claimed")
        self.assertEqual(lease.job.attempt_count, 1)
        self.assertEqual(lease.job.claimed_by, "w1")

    def test_future_available_at_is_not_claimable(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(
                    _job(available_at=_NOW + timedelta(hours=1))
                )
            with db.session_scope() as s:
                self.assertIsNone(
                    SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
                )
            with db.session_scope() as s:
                self.assertIsNotNone(
                    SqlAlchemyJobQueue(s).claim(
                        "w1", frozenset(), 60, _NOW + timedelta(hours=2)
                    )
                )

    def test_capability_filtering(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job(required_capabilities=("docker", "arm64"))
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            # A worker lacking a required capability claims nothing.
            with db.session_scope() as s:
                self.assertIsNone(
                    SqlAlchemyJobQueue(s).claim(
                        "weak", frozenset({"docker"}), 60, _NOW
                    )
                )
            # A capability-free worker (empty array binding!) claims nothing.
            with db.session_scope() as s:
                self.assertIsNone(
                    SqlAlchemyJobQueue(s).claim("bare", frozenset(), 60, _NOW)
                )
            # A superset worker claims it.
            with db.session_scope() as s:
                lease = SqlAlchemyJobQueue(s).claim(
                    "strong", frozenset({"docker", "arm64", "x86"}), 60, _NOW
                )
        self.assertIsNotNone(lease)
        self.assertEqual(lease.job.job_id, job.job_id)

    def test_capability_free_worker_claims_capability_free_job(self) -> None:
        # Covers the empty text[] CAST on both sides of <@.
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(_job())
            with db.session_scope() as s:
                lease = SqlAlchemyJobQueue(s).claim("bare", frozenset(), 60, _NOW)
        self.assertIsNotNone(lease)

    def test_concurrent_claim_uniqueness_8_threads_20_jobs(self) -> None:
        with _migrated_database() as (db, _url):
            jobs = [_job() for _ in range(20)]
            with db.session_scope() as s:
                queue = SqlAlchemyJobQueue(s)
                for job in jobs:
                    queue.enqueue(job)

            claimed: dict[int, list[str]] = {i: [] for i in range(8)}
            errors: list[BaseException] = []
            barrier = threading.Barrier(8)

            def drain(worker_index: int) -> None:
                try:
                    barrier.wait(timeout=30)
                    while True:
                        with db.session_scope() as s:
                            lease = SqlAlchemyJobQueue(s).claim(
                                f"w{worker_index}", frozenset(), 60, _NOW
                            )
                        if lease is None:
                            return
                        claimed[worker_index].append(lease.job.job_id)
                except BaseException as exc:  # noqa: BLE001 - re-raised below
                    errors.append(exc)

            threads = [
                threading.Thread(target=drain, args=(i,)) for i in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)

        self.assertEqual(errors, [])
        all_claimed = [job_id for ids in claimed.values() for job_id in ids]
        # Each job claimed exactly once: no duplicates, union == all.
        self.assertEqual(len(all_claimed), 20)
        self.assertEqual(set(all_claimed), {job.job_id for job in jobs})

    def test_8_threads_race_for_1_job_exactly_one_wins(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job()
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)

            results: list[object] = []
            errors: list[BaseException] = []
            barrier = threading.Barrier(8)
            lock = threading.Lock()

            def race(worker_index: int) -> None:
                try:
                    barrier.wait(timeout=30)
                    with db.session_scope() as s:
                        lease = SqlAlchemyJobQueue(s).claim(
                            f"w{worker_index}", frozenset(), 60, _NOW
                        )
                    with lock:
                        results.append(lease)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=race, args=(i,)) for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)

        self.assertEqual(errors, [])
        wins = [r for r in results if r is not None]
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(results), 8)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class JobLifecycleTests(unittest.TestCase):
    def _claimed(self, db, job: Job, lease_seconds: int = 60):
        with db.session_scope() as s:
            SqlAlchemyJobQueue(s).enqueue(job)
        with db.session_scope() as s:
            return SqlAlchemyJobQueue(s).claim("w1", frozenset(), lease_seconds, _NOW)

    def test_start_heartbeat_complete_happy_path(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job()
            lease = self._claimed(db, job)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).start(job.job_id, lease.lease_token, _NOW)
            with db.session_scope() as s:
                cancel = SqlAlchemyJobQueue(s).heartbeat(
                    job.job_id, lease.lease_token, 60, _NOW + timedelta(seconds=30)
                )
            self.assertFalse(cancel)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).complete(
                    job.job_id,
                    lease.lease_token,
                    {"artifact": "sha256:aa"},
                    "artifacts/aa",
                    "logs/aa",
                    _NOW + timedelta(minutes=1),
                )
            with db.session_scope() as s:
                queue = SqlAlchemyJobQueue(s)
                got = queue.get(job.job_id)
                history = queue.list_transitions(job.job_id)
        self.assertEqual(got.status, "succeeded")
        self.assertEqual(got.result_json, {"artifact": "sha256:aa"})
        self.assertEqual(got.result_ref, "artifacts/aa")
        self.assertIsNone(got.claimed_by)  # lease cleared on completion
        self.assertEqual(
            [t.to_status for t in history],
            ["queued", "claimed", "running", "succeeded"],
        )

    def test_stale_lease_token_raises_lookuperror_and_changes_nothing(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job()
            self._claimed(db, job)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).start(job.job_id, str(uuid.uuid4()), _NOW)
            with db.session_scope() as s:
                got = SqlAlchemyJobQueue(s).get(job.job_id)
        self.assertEqual(got.status, "claimed")

    def test_fail_nonretryable_is_failed(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job()
            lease = self._claimed(db, job)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).start(job.job_id, lease.lease_token, _NOW)
            with db.session_scope() as s:
                updated = SqlAlchemyJobQueue(s).fail(
                    job.job_id,
                    lease.lease_token,
                    "validation",
                    "manifest rejected",
                    False,
                    _NOW,
                )
        self.assertEqual(updated.status, "failed")
        self.assertEqual(updated.error_class, "validation")

    def test_fail_retryable_requeues_with_backoff(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job(backoff_base_seconds=30, max_attempts=3)
            lease = self._claimed(db, job)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).start(job.job_id, lease.lease_token, _NOW)
            with db.session_scope() as s:
                updated = SqlAlchemyJobQueue(s).fail(
                    job.job_id, lease.lease_token, "transient", None, True, _NOW
                )
        self.assertEqual(updated.status, "queued")
        self.assertEqual(updated.attempt_count, 1)
        # attempt 1 -> backoff base * 2^0 = 30s
        self.assertEqual(updated.available_at, _NOW + timedelta(seconds=30))

    def test_retryable_failures_exhaust_to_dead_letter_then_operator_retry(
        self,
    ) -> None:
        with _migrated_database() as (db, _url):
            job = _job(max_attempts=2, backoff_base_seconds=1)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            now = _NOW
            for attempt in (1, 2):
                now = now + timedelta(hours=1)
                with db.session_scope() as s:
                    lease = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, now)
                self.assertIsNotNone(lease, f"attempt {attempt} claim failed")
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).start(job.job_id, lease.lease_token, now)
                with db.session_scope() as s:
                    updated = SqlAlchemyJobQueue(s).fail(
                        job.job_id, lease.lease_token, "transient", None, True, now
                    )
            self.assertEqual(updated.status, "dead_letter")
            with db.session_scope() as s:
                dead = SqlAlchemyJobQueue(s).list_dead_letter()
            self.assertEqual([j.job_id for j in dead], [job.job_id])
            # Operator requeue resets the attempt budget.
            with db.session_scope() as s:
                retried = SqlAlchemyJobQueue(s).retry_dead_letter(job.job_id, now)
            self.assertEqual(retried.status, "queued")
            self.assertEqual(retried.attempt_count, 0)
            self.assertIsNone(retried.error_class)

    def test_retry_non_dead_letter_raises(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job()
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).retry_dead_letter(job.job_id, _NOW)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class LeaseExpiryTests(unittest.TestCase):
    def test_reap_requeues_and_stale_worker_is_fenced(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job(max_attempts=3, backoff_base_seconds=30)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with db.session_scope() as s:
                stale = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
            self.assertIsNotNone(stale)

            # The lease expires; the reaper requeues with backoff.
            reap_at = _NOW + timedelta(minutes=5)
            with db.session_scope() as s:
                reaped = SqlAlchemyJobQueue(s).reap_expired(reap_at)
            self.assertEqual([j.job_id for j in reaped], [job.job_id])
            self.assertEqual(reaped[0].status, "queued")
            self.assertEqual(reaped[0].attempt_count, 1)
            self.assertEqual(reaped[0].error_class, "lease_expired")
            self.assertEqual(
                reaped[0].available_at, reap_at + timedelta(seconds=30)
            )

            # Another worker claims it after the backoff.
            claim_at = reap_at + timedelta(minutes=5)
            with db.session_scope() as s:
                fresh = SqlAlchemyJobQueue(s).claim("w2", frozenset(), 60, claim_at)
            self.assertIsNotNone(fresh)
            self.assertEqual(fresh.job.attempt_count, 2)

            # The original worker's late complete() is harmlessly rejected.
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).complete(
                        job.job_id, stale.lease_token, None, None, None, claim_at
                    )
            with db.session_scope() as s:
                got = SqlAlchemyJobQueue(s).get(job.job_id)
            self.assertEqual(got.status, "claimed")
            self.assertEqual(got.claimed_by, "w2")

    def test_reap_with_exhausted_budget_dead_letters(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job(max_attempts=1)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
            with db.session_scope() as s:
                reaped = SqlAlchemyJobQueue(s).reap_expired(_NOW + timedelta(hours=1))
        self.assertEqual(reaped[0].status, "dead_letter")
        self.assertEqual(reaped[0].error_class, "lease_expired")

    def test_reap_ignores_live_leases(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(_job())
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).claim("w1", frozenset(), 3600, _NOW)
            with db.session_scope() as s:
                reaped = SqlAlchemyJobQueue(s).reap_expired(
                    _NOW + timedelta(minutes=5)
                )
        self.assertEqual(reaped, [])

    def test_duplicate_delivery_one_succeeded_row_with_second_result(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job(max_attempts=3)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with db.session_scope() as s:
                first = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).start(job.job_id, first.lease_token, _NOW)
            later = _NOW + timedelta(minutes=10)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).reap_expired(later)
            with db.session_scope() as s:
                second = SqlAlchemyJobQueue(s).claim(
                    "w2", frozenset(), 60, later + timedelta(minutes=1)
                )
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).start(
                    job.job_id, second.lease_token, later + timedelta(minutes=1)
                )
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).complete(
                    job.job_id,
                    second.lease_token,
                    {"winner": "w2"},
                    None,
                    None,
                    later + timedelta(minutes=2),
                )
            # The zombie's completion attempt is fenced out.
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).complete(
                        job.job_id,
                        first.lease_token,
                        {"winner": "w1"},
                        None,
                        None,
                        later + timedelta(minutes=3),
                    )
            with db.session_scope() as s:
                got = SqlAlchemyJobQueue(s).get(job.job_id)
        self.assertEqual(got.status, "succeeded")
        self.assertEqual(got.result_json, {"winner": "w2"})


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AuditRefBatchTests(unittest.TestCase):
    """``list_dead_letter``/``reap_expired`` resolve the optional audit
    linkage (competition slug; definition slug + version_no) via a BATCHED
    ``IN`` lookup -- two queries total regardless of row count -- instead of
    the old per-row ``_audit_refs`` N+1 (up to two point SELECTs per job).
    These tests prove the batch path returns results identical to the
    pre-existing per-row path (``get()`` -> ``_to_domain`` -> ``_audit_refs``,
    used here as the oracle) and that the read-only ``list_dead_letter``
    query count stays constant as row count N grows."""

    _SLUG_PREFIX = "batch-slug"

    def _seed_catalog(self, db, n: int) -> tuple[str, list[tuple[str, int]]]:
        """One competition plus ``n`` distinct published (definition_slug,
        version_no) pairs for jobs to carry as audit linkage."""
        competition_id = f"batch-cup-{uuid.uuid4().hex[:8]}"
        with db.session_scope() as s:
            SqlAlchemyCompetitionRepository(s).add(
                CompetitionConfig(
                    competition_id=competition_id,
                    name="Batch Cup",
                    start_time=_NOW,
                    end_time=_NOW + timedelta(hours=48),
                )
            )
        versions: list[tuple[str, int]] = []
        for i in range(n):
            slug = f"{self._SLUG_PREFIX}-{uuid.uuid4().hex[:8]}-{i}"
            with db.session_scope() as s:
                SqlAlchemyChallengeDefinitionRepository(s).add(
                    ChallengeDefinition(family="web", slug=slug, title=f"Chal {i}")
                )
                SqlAlchemyChallengeVersionRepository(s).add(
                    ChallengeVersion(
                        definition_slug=slug,
                        version_no=1,
                        state="draft",
                        family_version="1.0",
                        seed=f"seed-{i}",
                        spec_sha256=f"spec-hash-{i}",
                        spec={"title": f"Chal {i}"},
                        spec_version="1.0",
                        mode="red",
                        published_at=None,
                    )
                )
            versions.append((slug, 1))
        return competition_id, versions

    def _dead_letter_job(
        self, db, competition_id: str, slug: str, version_no: int
    ) -> str:
        """Enqueue, claim, start, and fail-to-exhaustion a single job carrying
        the given audit linkage, returning its job_id."""
        job = _job(
            max_attempts=1,
            competition_id=competition_id,
            definition_slug=slug,
            version_no=version_no,
        )
        with db.session_scope() as s:
            SqlAlchemyJobQueue(s).enqueue(job)
        with db.session_scope() as s:
            lease = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
        with db.session_scope() as s:
            SqlAlchemyJobQueue(s).start(job.job_id, lease.lease_token, _NOW)
        with db.session_scope() as s:
            SqlAlchemyJobQueue(s).fail(
                job.job_id, lease.lease_token, "internal", "boom", True, _NOW
            )
        return job.job_id

    def test_list_dead_letter_matches_per_row_lookup(self) -> None:
        with _migrated_database() as (db, _url):
            n = 6
            competition_id, versions = self._seed_catalog(db, n)
            job_ids = [
                self._dead_letter_job(db, competition_id, slug, version_no)
                for slug, version_no in versions
            ]

            # The pre-existing per-row path (get() -> _to_domain ->
            # _audit_refs) is the oracle: the batch path must return
            # byte-identical Jobs.
            with db.session_scope() as s:
                queue = SqlAlchemyJobQueue(s)
                expected = [queue.get(job_id) for job_id in job_ids]

            with db.session_scope() as s:
                dead = SqlAlchemyJobQueue(s).list_dead_letter()

        self.assertEqual(
            sorted(dead, key=lambda j: j.job_id),
            sorted(expected, key=lambda j: j.job_id),
        )
        for job in dead:
            self.assertEqual(job.competition_id, competition_id)
            self.assertIsNotNone(job.definition_slug)
            self.assertEqual(job.version_no, 1)

    def test_list_dead_letter_query_count_is_constant_in_row_count(self) -> None:
        counts: dict[int, int] = {}
        for n in (1, 8):
            with _migrated_database() as (db, _url):
                competition_id, versions = self._seed_catalog(db, n)
                for slug, version_no in versions:
                    self._dead_letter_job(db, competition_id, slug, version_no)
                with db.session_scope() as s:
                    with _count_statements(db.engine) as counter:
                        dead = SqlAlchemyJobQueue(s).list_dead_letter()
                self.assertEqual(len(dead), n)
                counts[n] = counter["n"]
        # 1 SELECT for the dead_letter rows + at most 2 batch "IN" lookups
        # (competitions, challenge-versions) -- NOT one extra pair of point
        # SELECTs per row (the old N+1 would make this grow with N).
        self.assertLessEqual(counts[1], 3)
        self.assertEqual(
            counts[1],
            counts[8],
            "list_dead_letter query count must not grow with row count "
            f"(1 row: {counts[1]} queries, 8 rows: {counts[8]} queries)",
        )

    def test_reap_expired_matches_per_row_lookup(self) -> None:
        with _migrated_database() as (db, _url):
            n = 4
            competition_id, versions = self._seed_catalog(db, n)
            job_ids: list[str] = []
            for slug, version_no in versions:
                job = _job(
                    max_attempts=3,
                    backoff_base_seconds=30,
                    competition_id=competition_id,
                    definition_slug=slug,
                    version_no=version_no,
                )
                job_ids.append(job.job_id)
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).enqueue(job)
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)

            reap_at = _NOW + timedelta(minutes=5)
            with db.session_scope() as s:
                reaped = SqlAlchemyJobQueue(s).reap_expired(reap_at, limit=100)

            # Oracle: the pre-existing per-row get() path, evaluated after the
            # same state change, must agree with what reap_expired returned.
            with db.session_scope() as s:
                queue = SqlAlchemyJobQueue(s)
                expected = [queue.get(job_id) for job_id in job_ids]

        self.assertEqual(len(reaped), n)
        self.assertEqual(
            sorted(reaped, key=lambda j: j.job_id),
            sorted(expected, key=lambda j: j.job_id),
        )
        for job in reaped:
            self.assertEqual(job.status, "queued")
            self.assertEqual(job.competition_id, competition_id)
            self.assertIsNotNone(job.definition_slug)
            self.assertEqual(job.version_no, 1)

    def test_list_dead_letter_and_reap_expired_handle_no_linkage(self) -> None:
        """Rows with neither competition_id nor challenge_version_id set must
        not trigger any batch lookup query and must map to (None, None,
        None), matching the old per-row behavior."""
        with _migrated_database() as (db, _url):
            plain = _job(max_attempts=1)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(plain)
            with db.session_scope() as s:
                lease = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).start(plain.job_id, lease.lease_token, _NOW)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).fail(
                    plain.job_id, lease.lease_token, "internal", "boom", True, _NOW
                )
            with db.session_scope() as s:
                with _count_statements(db.engine) as counter:
                    dead = SqlAlchemyJobQueue(s).list_dead_letter()
        self.assertEqual([j.job_id for j in dead], [plain.job_id])
        self.assertIsNone(dead[0].competition_id)
        self.assertIsNone(dead[0].definition_slug)
        self.assertIsNone(dead[0].version_no)
        # No linkage on the only row -> no batch lookup query, just the one
        # SELECT for the dead_letter rows themselves.
        self.assertEqual(counter["n"], 1)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CancellationTests(unittest.TestCase):
    def test_cancel_queued_job_directly(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job()
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with db.session_scope() as s:
                cancelled = SqlAlchemyJobQueue(s).request_cancel(job.job_id, _NOW)
        self.assertEqual(cancelled.status, "cancelled")

    def test_cooperative_cancel_of_running_job(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job()
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with db.session_scope() as s:
                lease = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).start(job.job_id, lease.lease_token, _NOW)
            with db.session_scope() as s:
                still_running = SqlAlchemyJobQueue(s).request_cancel(
                    job.job_id, _NOW
                )
            self.assertEqual(still_running.status, "running")
            # The worker learns of the request from its next heartbeat...
            with db.session_scope() as s:
                cancel_requested = SqlAlchemyJobQueue(s).heartbeat(
                    job.job_id, lease.lease_token, 60, _NOW + timedelta(seconds=10)
                )
            self.assertTrue(cancel_requested)
            # ...and acknowledges cooperatively.
            with db.session_scope() as s:
                final = SqlAlchemyJobQueue(s).fail(
                    job.job_id,
                    lease.lease_token,
                    "cancelled",
                    None,
                    False,
                    _NOW + timedelta(seconds=11),
                )
        self.assertEqual(final.status, "cancelled")

    def test_cancel_terminal_job_raises(self) -> None:
        with _migrated_database() as (db, _url):
            job = _job()
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).request_cancel(job.job_id, _NOW)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyJobQueue(s).request_cancel(job.job_id, _NOW)

    def test_cancel_requested_claimed_job_reaps_to_cancelled(self) -> None:
        # A cancel requested while claimed/running takes precedence over the
        # lease-expiry requeue path: the job ends 'cancelled', not requeued.
        with _migrated_database() as (db, _url):
            job = _job(max_attempts=3)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
            with db.session_scope() as s:
                still = SqlAlchemyJobQueue(s).request_cancel(job.job_id, _NOW)
            self.assertEqual(still.status, "claimed")  # cooperative stamp only
            with db.session_scope() as s:
                reaped = SqlAlchemyJobQueue(s).reap_expired(
                    _NOW + timedelta(minutes=5)
                )
            self.assertEqual([j.status for j in reaped], ["cancelled"])
            with db.session_scope() as s:
                got = SqlAlchemyJobQueue(s).get(job.job_id)
                history = SqlAlchemyJobQueue(s).list_transitions(job.job_id)
        self.assertEqual(got.status, "cancelled")
        self.assertEqual(history[-1].to_status, "cancelled")

    def test_claim_skips_cancel_requested_queued_job(self) -> None:
        # A queued row carrying cancel_requested_at (a requeue that raced a
        # cancel) must not be re-dispatched; a clean sibling still claims.
        with _migrated_database() as (db, _url):
            clean = _job()
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(clean)
            cancel_id = uuid.uuid4()
            with db.session_scope() as s:
                s.execute(
                    sa.text(
                        "INSERT INTO jobs (id, job_type, status, "
                        "idempotency_key, available_at, cancel_requested_at, "
                        "priority) VALUES (:id, 'build_challenge', 'queued', "
                        ":key, :avail, :cancel, 1)"
                    ),
                    {
                        "id": cancel_id,
                        "key": f"cancelled-{cancel_id.hex}",
                        "avail": _NOW,
                        "cancel": _NOW,
                    },
                )
            # priority 1 would win, but it is cancel-requested and skipped, so
            # the clean priority-100 job is claimed instead.
            with db.session_scope() as s:
                lease = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
            self.assertIsNotNone(lease)
            self.assertEqual(lease.job.job_id, clean.job_id)

    def test_retry_dead_letter_clears_cancel_signal(self) -> None:
        # A dead-letter row carrying cancel_requested_at (only reachable by a
        # raw insert -- INSERT is unguarded) is re-dispatchable after the
        # operator requeue, and a subsequent heartbeat reports no cancel.
        with _migrated_database() as (db, _url):
            dead_id = uuid.uuid4()
            with db.session_scope() as s:
                s.execute(
                    sa.text(
                        "INSERT INTO jobs (id, job_type, status, "
                        "idempotency_key, available_at, finished_at, "
                        "error_class, cancel_requested_at, attempt_count, "
                        "max_attempts) VALUES (:id, 'build_challenge', "
                        "'dead_letter', :key, :avail, :fin, 'internal', "
                        ":cancel, 1, 1)"
                    ),
                    {
                        "id": dead_id,
                        "key": f"dead-{dead_id.hex}",
                        "avail": _NOW,
                        "fin": _NOW,
                        "cancel": _NOW,
                    },
                )
            with db.session_scope() as s:
                requeued = SqlAlchemyJobQueue(s).retry_dead_letter(str(dead_id), _NOW)
            self.assertEqual(requeued.status, "queued")
            self.assertIsNone(requeued.cancel_requested_at)
            with db.session_scope() as s:
                lease = SqlAlchemyJobQueue(s).claim("w1", frozenset(), 60, _NOW)
            self.assertIsNotNone(lease)
            self.assertEqual(lease.job.job_id, str(dead_id))
            with db.session_scope() as s:
                cancel = SqlAlchemyJobQueue(s).heartbeat(
                    str(dead_id), lease.lease_token, 60, _NOW
                )
        self.assertFalse(cancel)  # the cancel signal was cleared on requeue


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class TransitionGuardTests(unittest.TestCase):
    """The plpgsql guard is byte-equivalent to the domain matrix: every
    (from, to) pair is asserted to be accepted/rejected exactly as
    LEGAL_JOB_TRANSITIONS says (self-updates allowed only off terminal)."""

    @staticmethod
    def _state_columns(status: str) -> dict[str, object]:
        """Column values satisfying every CHECK for ``status`` (so the guard,
        not a CHECK constraint, is what accepts/rejects)."""
        cols: dict[str, object] = {
            "claimed_by": None,
            "lease_token": None,
            "lease_expires_at": None,
            "heartbeat_at": None,
            "started_at": None,
            "finished_at": None,
            "error_class": None,
        }
        if status in ("claimed", "running"):
            cols.update(
                claimed_by="w1",
                lease_token=uuid.uuid4(),
                lease_expires_at=_NOW + timedelta(minutes=1),
            )
        if status == "running":
            cols.update(started_at=_NOW)
        if status in ("succeeded", "failed", "cancelled", "dead_letter"):
            cols.update(finished_at=_NOW)
        if status in ("failed", "dead_letter"):
            cols.update(error_class="internal")
        return cols

    def _seed(self, session, status: str) -> uuid.UUID:
        job_id = uuid.uuid4()
        cols = self._state_columns(status)
        session.execute(
            sa.text(
                "INSERT INTO jobs (id, job_type, status, idempotency_key, "
                "available_at, claimed_by, lease_token, lease_expires_at, "
                "heartbeat_at, started_at, finished_at, error_class) "
                "VALUES (:id, 'build_challenge', :status, :key, :avail, "
                ":claimed_by, :lease_token, :lease_expires_at, :heartbeat_at, "
                ":started_at, :finished_at, :error_class)"
            ),
            {
                "id": job_id,
                "status": status,
                "key": f"seed-{job_id.hex}",
                "avail": _NOW,
                **cols,
            },
        )
        return job_id

    def test_guard_matches_domain_matrix_pair_for_pair(self) -> None:
        with _migrated_database() as (db, url):
            engine = sa.create_engine(url, future=True)
            try:
                for source in sorted(VALID_JOB_STATUSES):
                    for target in sorted(VALID_JOB_STATUSES):
                        if source == target:
                            expect_ok = source not in TERMINAL_JOB_STATUSES
                        else:
                            expect_ok = target in LEGAL_JOB_TRANSITIONS[source]
                        with self.subTest(source=source, target=target):
                            with engine.begin() as conn:
                                job_id = self._seed(conn, source)
                            target_cols = self._state_columns(target)
                            update = sa.text(
                                "UPDATE jobs SET status = :status, "
                                "claimed_by = :claimed_by, "
                                "lease_token = :lease_token, "
                                "lease_expires_at = :lease_expires_at, "
                                "heartbeat_at = :heartbeat_at, "
                                "started_at = :started_at, "
                                "finished_at = :finished_at, "
                                "error_class = :error_class "
                                "WHERE id = :id"
                            )
                            params = {"status": target, "id": job_id, **target_cols}
                            if expect_ok:
                                with engine.begin() as conn:
                                    conn.execute(update, params)
                            else:
                                with self.assertRaises(ProgrammingError):
                                    with engine.begin() as conn:
                                        conn.execute(update, params)
            finally:
                engine.dispose()

    def test_immutable_columns_frozen_after_insert(self) -> None:
        with _migrated_database() as (db, url):
            engine = sa.create_engine(url, future=True)
            try:
                with engine.begin() as conn:
                    job_id = self._seed(conn, "queued")
                for stmt in (
                    "UPDATE jobs SET payload = '{\"x\": 1}' WHERE id = :id",
                    "UPDATE jobs SET idempotency_key = 'other' WHERE id = :id",
                    "UPDATE jobs SET job_type = 'collect_logs' WHERE id = :id",
                ):
                    with self.subTest(stmt=stmt):
                        with self.assertRaises(ProgrammingError):
                            with engine.begin() as conn:
                                conn.execute(sa.text(stmt), {"id": job_id})
            finally:
                engine.dispose()

    def test_job_transitions_append_only(self) -> None:
        with _migrated_database() as (db, url):
            job = _job()
            with db.session_scope() as s:
                SqlAlchemyJobQueue(s).enqueue(job)
            engine = sa.create_engine(url, future=True)
            try:
                for stmt in (
                    "UPDATE job_transitions SET to_status = 'failed'",
                    "DELETE FROM job_transitions",
                    "TRUNCATE job_transitions",
                ):
                    with self.subTest(stmt=stmt):
                        with self.assertRaises(ProgrammingError):
                            with engine.begin() as conn:
                                conn.execute(sa.text(stmt))
            finally:
                engine.dispose()

    def test_check_constraints_are_integrity_errors(self) -> None:
        # A CHECK violation (not a trigger RAISE) surfaces as IntegrityError.
        with _migrated_database() as (db, url):
            engine = sa.create_engine(url, future=True)
            try:
                with self.assertRaises(IntegrityError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "INSERT INTO jobs (id, job_type, status, "
                                "idempotency_key, available_at) VALUES "
                                "(:id, 'mine_bitcoin', 'queued', 'k1', :avail)"
                            ),
                            {"id": uuid.uuid4(), "avail": _NOW},
                        )
            finally:
                engine.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class JobsMigrationTests(unittest.TestCase):
    def test_migration_upgrade_downgrade(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            engine = sa.create_engine(url, future=True)
            try:
                command.upgrade(cfg, "0006_jobs")
                insp = sa.inspect(engine)
                for table in ("jobs", "job_transitions"):
                    self.assertIn(table, insp.get_table_names())
                # Down one step: jobs machinery gone, guard fn dropped, the
                # shared reject_mutation (owned by 0004) retained.
                command.downgrade(cfg, "0005_ledger")
                insp = sa.inspect(engine)
                self.assertNotIn("jobs", insp.get_table_names())
                with engine.connect() as conn:
                    fns = (
                        conn.execute(
                            sa.text(
                                "SELECT proname FROM pg_proc WHERE proname IN "
                                "('job_transition_guard', 'reject_mutation')"
                            )
                        )
                        .scalars()
                        .all()
                    )
                self.assertEqual(fns, ["reject_mutation"])
                # Up again is clean.
                command.upgrade(cfg, "0006_jobs")
                self.assertIn("jobs", sa.inspect(engine).get_table_names())
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
