"""PostgreSQL integration tests for capability-aware scheduling (M8).

Docker-gated; skips cleanly without the db extra / CTFGEN_TEST_DATABASE_URL.

Proves the scheduler picks the sole capable worker, excludes every
non-dispatch-eligible worker (pending / draining / quarantined / revoked /
stale), ranks by image-cache affinity then free capacity, and that
``SchedulingService.select_and_reserve`` skips a full worker, propagates a
shared-pool overrun, is idempotent per instance id, and raises
``NoEligibleWorkerError`` when nothing qualifies.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_scheduling_repository_integration
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
    from sqlalchemy.engine import make_url

    from ctf_generator.application.scheduling.service import SchedulingService
    from ctf_generator.domain.execution.models import Worker
    from ctf_generator.domain.scheduling.models import (
        PLATFORM_SCOPE_KEY,
        NoEligibleWorkerError,
        QuotaExceededError,
        ReservationItem,
        ResourceQuota,
        WorkerRequirements,
        worker_matches,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.quota_repository import (
        SqlAlchemyQuotaPolicyRepository,
    )
    from ctf_generator.infrastructure.database.scheduler_repository import (
        SqlAlchemyScheduler,
    )
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerRegistry,
    )

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
_CAPS = ("launch_instance", "isolation:container", "collect_logs")
_REQ = None  # built lazily when enabled


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


def _requirements() -> WorkerRequirements:
    return WorkerRequirements(
        "x86_64", frozenset({"launch_instance", "isolation:container"})
    )


def _make_worker(
    db,
    name,
    *,
    trust="trusted",
    caps=_CAPS,
    archs=("x86_64",),
    capacity=2,
    runtime="docker-rootless",
    heartbeat=_NOW,
    draining=False,
    quarantined=False,
) -> None:
    with db.session_scope() as s:
        reg = SqlAlchemyWorkerRegistry(s)
        reg.add(Worker(name, runtime, archs, caps, capacity, "1.0.0"))
        if trust in ("trusted",) or draining or quarantined:
            reg.approve(name)
        if heartbeat is not None:
            reg.heartbeat(name, heartbeat)
        if draining:
            reg.drain(name, _NOW)
        if quarantined:
            reg.quarantine(name, _NOW, "test-quarantine")
        if trust == "revoked":
            reg.revoke(name, _NOW)


def _saturate_worker(db, name, capacity) -> None:
    """Directly seed the worker's active_instances quota at limit == reserved
    so the scheduler sees zero free capacity."""
    with db.session_scope() as s:
        SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
            ResourceQuota("worker", name, "active_instances", capacity)
        )
        s.execute(
            sa.text(
                "UPDATE resource_quotas SET reserved_value = :cap "
                "WHERE scope_type = 'worker' AND scope_key = :name "
                "AND dimension = 'active_instances'"
            ),
            {"cap": capacity, "name": name},
        )


def _cache_image(db, name, image_ref) -> None:
    with db.session_scope() as s:
        worker_id = s.execute(
            sa.text("SELECT id FROM workers WHERE name = :n"), {"n": name}
        ).scalar_one()
        s.execute(
            sa.text(
                "INSERT INTO worker_image_cache (id, worker_id, image_ref) "
                "VALUES (:id, :w, :img)"
            ),
            {"id": str(uuid.uuid4()), "w": worker_id, "img": image_ref},
        )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CandidateSelectionTests(unittest.TestCase):
    def test_picks_the_sole_capable_worker(self) -> None:
        with _migrated_database() as (db, _url):
            _make_worker(db, "cap-worker")
            _make_worker(db, "wrong-arch", archs=("arm64",))
            _make_worker(db, "no-cap", caps=("build_challenge",))
            with db.session_scope() as s:
                cands = SqlAlchemyScheduler(s).candidate_workers(
                    _requirements(), _NOW, 60
                )
            self.assertEqual([c.worker_name for c in cands], ["cap-worker"])

    def test_excludes_non_dispatch_eligible_workers(self) -> None:
        with _migrated_database() as (db, _url):
            _make_worker(db, "pending", trust="pending")
            _make_worker(db, "draining", draining=True)
            _make_worker(db, "quarantined", quarantined=True)
            _make_worker(db, "revoked", trust="revoked")
            _make_worker(db, "stale", heartbeat=_NOW - timedelta(hours=1))
            _make_worker(db, "never-beat", heartbeat=None)
            _make_worker(db, "good")
            with db.session_scope() as s:
                cands = SqlAlchemyScheduler(s).candidate_workers(
                    _requirements(), _NOW, 60
                )
            self.assertEqual([c.worker_name for c in cands], ["good"])

    def test_no_candidate_when_none_qualify(self) -> None:
        with _migrated_database() as (db, _url):
            _make_worker(db, "wrong", archs=("arm64",))
            with db.session_scope() as s:
                cands = SqlAlchemyScheduler(s).candidate_workers(
                    _requirements(), _NOW, 60
                )
            self.assertEqual(cands, [])

    def test_full_worker_excluded(self) -> None:
        with _migrated_database() as (db, _url):
            _make_worker(db, "busy", capacity=1)
            _saturate_worker(db, "busy", 1)
            _make_worker(db, "free", capacity=1)
            with db.session_scope() as s:
                cands = SqlAlchemyScheduler(s).candidate_workers(
                    _requirements(), _NOW, 60
                )
            self.assertEqual([c.worker_name for c in cands], ["free"])

    def test_image_cache_affinity_ranks_first(self) -> None:
        with _migrated_database() as (db, _url):
            # Two equally-free workers; only "warm" has the image cached, so it
            # ranks ahead despite the newer heartbeat tie-break not applying.
            _make_worker(db, "cold", heartbeat=_NOW)
            _make_worker(db, "warm", heartbeat=_NOW)
            _cache_image(db, "warm", "img:app@sha256:abc")
            with db.session_scope() as s:
                cands = SqlAlchemyScheduler(s).candidate_workers(
                    _requirements(), _NOW, 60, image_ref="img:app@sha256:abc"
                )
            self.assertEqual(cands[0].worker_name, "warm")
            self.assertTrue(cands[0].image_cached)

    def test_free_capacity_reports_capacity_without_quota(self) -> None:
        with _migrated_database() as (db, _url):
            _make_worker(db, "w", capacity=4)
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w"), 4)

    def test_free_capacity_unknown_worker_raises(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                with self.assertRaises(LookupError):
                    SqlAlchemyScheduler(s).free_capacity("ghost")


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class SelectAndReserveTests(unittest.TestCase):
    def _platform_pool(self, db, limit) -> None:
        with db.session_scope() as s:
            SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
                ResourceQuota("platform", PLATFORM_SCOPE_KEY, "active_instances", limit)
            )

    def _reserve(self, svc, rid, *, pool_amount=1):
        return svc.select_and_reserve(
            requirements=_requirements(),
            reservation_id=rid,
            pooled_items=(
                ReservationItem(
                    "platform", PLATFORM_SCOPE_KEY, "active_instances", pool_amount
                ),
            ),
            expires_at=_NOW + timedelta(hours=1),
            now=_NOW,
        )

    def test_places_and_reserves_on_capable_worker(self) -> None:
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            _make_worker(db, "w1", capacity=2)
            svc = SchedulingService(db)
            reservation, worker = self._reserve(svc, str(uuid.uuid4()))
            self.assertEqual(worker, "w1")
            self.assertEqual(reservation.state, "held")
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w1"), 1)

    def test_full_worker_skipped_then_next_chosen(self) -> None:
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            _make_worker(db, "busy", capacity=1)
            _saturate_worker(db, "busy", 1)
            _make_worker(db, "free", capacity=1)
            svc = SchedulingService(db)
            _reservation, worker = self._reserve(svc, str(uuid.uuid4()))
            self.assertEqual(worker, "free")

    def test_worker_saturation_raises_no_eligible(self) -> None:
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            _make_worker(db, "w1", capacity=1)
            svc = SchedulingService(db)
            self._reserve(svc, str(uuid.uuid4()))  # fills the only worker
            with self.assertRaises(NoEligibleWorkerError):
                self._reserve(svc, str(uuid.uuid4()))

    def test_shared_pool_overrun_propagates(self) -> None:
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 1)  # only one instance platform-wide
            _make_worker(db, "w1", capacity=5)
            svc = SchedulingService(db)
            self._reserve(svc, str(uuid.uuid4()))
            with self.assertRaises(QuotaExceededError):
                self._reserve(svc, str(uuid.uuid4()))

    def test_reserve_is_idempotent_per_instance_id(self) -> None:
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            _make_worker(db, "w1", capacity=3)
            svc = SchedulingService(db)
            rid = str(uuid.uuid4())
            first, _w = self._reserve(svc, rid)
            second, _w2 = self._reserve(svc, rid)
            self.assertEqual(first.reservation_id, second.reservation_id)
            # Only one unit consumed despite two calls.
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w1"), 2)

    def test_release_then_rereserve_reholds_capacity(self) -> None:
        # Reusing a reservation_id whose hold was RELEASED must re-reserve
        # capacity, not replay the stale (capacity-free) placement.
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            _make_worker(db, "w1", capacity=2)
            svc = SchedulingService(db)
            rid = str(uuid.uuid4())
            _r, worker = self._reserve(svc, rid)
            self.assertEqual(worker, "w1")
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w1"), 1)

            self.assertTrue(svc.release(rid, _NOW))
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w1"), 2)

            reheld, worker2 = self._reserve(svc, rid)  # same id -> re-holds
            self.assertEqual(worker2, "w1")
            self.assertEqual(reheld.state, "held")
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w1"), 1)

    def test_concurrent_first_reserves_on_fresh_worker_both_succeed(self) -> None:
        # Two concurrent first launches both lazily seed the worker's capacity
        # quota. The seed is race-safe (INSERT ... ON CONFLICT DO NOTHING), so
        # neither surfaces a raw IntegrityError misread as a duplicate reserve.
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            _make_worker(db, "w1", capacity=2)  # fresh: no worker quota row yet
            svc = SchedulingService(db)
            barrier = threading.Barrier(2)
            workers: list[str] = []
            errors: list[Exception] = []
            lock = threading.Lock()

            def attempt() -> None:
                rid = str(uuid.uuid4())
                barrier.wait()
                try:
                    _r, worker = self._reserve(svc, rid)
                    with lock:
                        workers.append(worker)
                except Exception as exc:  # pragma: no cover - failure path
                    with lock:
                        errors.append(exc)

            threads = [threading.Thread(target=attempt) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(errors, [])  # no raw IntegrityError from the seed race
            self.assertEqual(sorted(workers), ["w1", "w1"])
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w1"), 0)

    def test_no_worker_raises_no_eligible(self) -> None:
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            svc = SchedulingService(db)
            with self.assertRaises(NoEligibleWorkerError):
                self._reserve(svc, str(uuid.uuid4()))

    def test_release_returns_capacity(self) -> None:
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            _make_worker(db, "w1", capacity=1)
            svc = SchedulingService(db)
            rid = str(uuid.uuid4())
            self._reserve(svc, rid)
            self.assertTrue(svc.release(rid, _NOW))
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w1"), 1)

    def test_release_expired_sweeps_leaked_holds(self) -> None:
        with _migrated_database() as (db, _url):
            self._platform_pool(db, 10)
            _make_worker(db, "w1", capacity=2)
            svc = SchedulingService(db)
            rid = str(uuid.uuid4())
            svc.select_and_reserve(
                requirements=_requirements(),
                reservation_id=rid,
                pooled_items=(
                    ReservationItem(
                        "platform", PLATFORM_SCOPE_KEY, "active_instances", 1
                    ),
                ),
                expires_at=_NOW - timedelta(minutes=1),  # already expired
                now=_NOW - timedelta(hours=1),
            )
            released = svc.release_expired(_NOW)
            self.assertIn(rid, released)
            with db.session_scope() as s:
                self.assertEqual(SqlAlchemyScheduler(s).free_capacity("w1"), 2)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerMatchesEquivalenceTests(unittest.TestCase):
    """The pure ``worker_matches`` spec and the SQL ``candidate_workers`` filter
    encode the same capability predicate; this cross-checks them over identical
    fixtures so they cannot silently diverge."""

    def test_capability_axis_agrees_with_sql_filter(self) -> None:
        req = _requirements()  # x86_64, {launch_instance, isolation:container}
        # name, archs, caps, runtime (all trusted / live / free capacity)
        specs = [
            ("m-basic", ("x86_64",), _CAPS, "docker-rootless"),
            ("m-multi-arch", ("x86_64", "arm64"), _CAPS, "docker-rootless"),
            ("m-podman", ("x86_64",), _CAPS, "podman-rootless"),
            ("x-arch", ("arm64",), _CAPS, "docker-rootless"),
            (
                "x-no-launch",
                ("x86_64",),
                ("isolation:container", "collect_logs"),
                "docker-rootless",
            ),
            (
                "x-wrong-iso",
                ("x86_64",),
                ("launch_instance", "isolation:raw_tcp", "collect_logs"),
                "docker-rootless",
            ),
        ]
        with _migrated_database() as (db, _url):
            for name, archs, caps, runtime in specs:
                _make_worker(
                    db, name, archs=archs, caps=caps, runtime=runtime, capacity=2
                )
            with db.session_scope() as s:
                sql = {
                    c.worker_name
                    for c in SqlAlchemyScheduler(s).candidate_workers(req, _NOW, 60)
                }
            spec = {
                name
                for name, archs, caps, runtime in specs
                if worker_matches(
                    architectures=archs,
                    capabilities=caps,
                    runtime_type=runtime,
                    requirements=req,
                )
            }
            self.assertEqual(sql, spec)
            self.assertEqual(sql, {"m-basic", "m-multi-arch", "m-podman"})

    def test_runtime_axis_agrees_with_sql_filter(self) -> None:
        req = WorkerRequirements(
            "x86_64",
            frozenset({"launch_instance", "isolation:container"}),
            runtime_type="podman-rootless",
        )
        specs = [
            ("docker", ("x86_64",), _CAPS, "docker-rootless"),
            ("podman", ("x86_64",), _CAPS, "podman-rootless"),
        ]
        with _migrated_database() as (db, _url):
            for name, archs, caps, runtime in specs:
                _make_worker(
                    db, name, archs=archs, caps=caps, runtime=runtime, capacity=2
                )
            with db.session_scope() as s:
                sql = {
                    c.worker_name
                    for c in SqlAlchemyScheduler(s).candidate_workers(req, _NOW, 60)
                }
            spec = {
                name
                for name, archs, caps, runtime in specs
                if worker_matches(
                    architectures=archs,
                    capabilities=caps,
                    runtime_type=runtime,
                    requirements=req,
                )
            }
            self.assertEqual(sql, spec)
            self.assertEqual(sql, {"podman"})

    def test_candidate_filter_gates_ineligible_even_when_capability_matches(
        self,
    ) -> None:
        # Every worker below satisfies the pure capability spec, but
        # candidate_workers ADDS dispatch-eligibility gating (trust / drain /
        # quarantine / revoke / heartbeat freshness) -- proving the SQL filter is
        # a strict superset of the capability predicate, never a divergence on it.
        req = _requirements()
        for caps in (_CAPS,):
            self.assertTrue(
                worker_matches(
                    architectures=("x86_64",),
                    capabilities=caps,
                    runtime_type="docker-rootless",
                    requirements=req,
                )
            )
        with _migrated_database() as (db, _url):
            _make_worker(db, "ok")
            _make_worker(db, "draining", draining=True)
            _make_worker(db, "quarantined", quarantined=True)
            _make_worker(db, "revoked", trust="revoked")
            _make_worker(db, "stale", heartbeat=_NOW - timedelta(hours=1))
            _make_worker(db, "pending", trust="pending")
            with db.session_scope() as s:
                sql = {
                    c.worker_name
                    for c in SqlAlchemyScheduler(s).candidate_workers(req, _NOW, 60)
                }
            self.assertEqual(sql, {"ok"})


if __name__ == "__main__":
    unittest.main()
