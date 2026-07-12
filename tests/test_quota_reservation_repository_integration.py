"""PostgreSQL integration tests for the quota reservation ledger (M8).

Docker-gated like the other repository suites; skips cleanly without the db
extra / CTFGEN_TEST_DATABASE_URL so the stdlib host suite stays green.

Proves the load-bearing properties: atomic all-or-nothing reserve, concurrent
saturation cannot exceed a pool, idempotent double-release, ceiling caps,
duplicate-reservation_id guard, the delete guard on a held quota, append-only
items, and self-healing reconcile.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_quota_reservation_repository_integration
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
    from sqlalchemy.exc import IntegrityError, ProgrammingError

    from ctf_generator.domain.scheduling.models import (
        PLATFORM_SCOPE_KEY,
        CeilingRequirement,
        QuotaExceededError,
        ReservationItem,
        ResourceDemand,
        ResourceQuota,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.quota_repository import (
        SqlAlchemyQuotaLedger,
        SqlAlchemyQuotaPolicyRepository,
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


def _platform_item(dimension="active_instances", amount=1) -> ReservationItem:
    return ReservationItem("platform", PLATFORM_SCOPE_KEY, dimension, amount)


def _seed_quota(db, dimension, limit, scope_type="platform", scope_key=None):
    if scope_key is None:
        scope_key = PLATFORM_SCOPE_KEY
    with db.session_scope() as s:
        SqlAlchemyQuotaPolicyRepository(s).upsert_limit(
            ResourceQuota(scope_type, scope_key, dimension, limit)
        )


def _reserved(db, dimension, scope_type="platform", scope_key=None) -> int:
    if scope_key is None:
        scope_key = PLATFORM_SCOPE_KEY
    with db.session_scope() as s:
        return (
            SqlAlchemyQuotaPolicyRepository(s)
            .get(scope_type, scope_key, dimension)
            .reserved_value
        )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class QuotaReserveReleaseTests(unittest.TestCase):
    def test_reserve_increments_and_release_restores(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", 5)
            demand = ResourceDemand(
                reservation_id=str(uuid.uuid4()),
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                items=(_platform_item(amount=2),),
            )
            with db.session_scope() as s:
                reservation = SqlAlchemyQuotaLedger(s).reserve(demand, _NOW)
            self.assertEqual(reservation.state, "held")
            self.assertEqual(_reserved(db, "active_instances"), 2)

            with db.session_scope() as s:
                released = SqlAlchemyQuotaLedger(s).release(demand.reservation_id, _NOW)
            self.assertTrue(released)
            self.assertEqual(_reserved(db, "active_instances"), 0)

    def test_double_release_is_noop(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", 5)
            rid = str(uuid.uuid4())
            demand = ResourceDemand(
                reservation_id=rid,
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                items=(_platform_item(),),
            )
            with db.session_scope() as s:
                SqlAlchemyQuotaLedger(s).reserve(demand, _NOW)
            with db.session_scope() as s:
                self.assertTrue(SqlAlchemyQuotaLedger(s).release(rid, _NOW))
            with db.session_scope() as s:
                self.assertFalse(SqlAlchemyQuotaLedger(s).release(rid, _NOW))
            self.assertEqual(_reserved(db, "active_instances"), 0)

    def test_release_missing_is_noop(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                self.assertFalse(
                    SqlAlchemyQuotaLedger(s).release(str(uuid.uuid4()), _NOW)
                )

    def test_all_or_nothing_rollback(self) -> None:
        # cpu_millis pool has room; memory_mb pool is exhausted -> the whole
        # reserve aborts and the cpu_millis increment is rolled back.
        with _migrated_database() as (db, _url):
            _seed_quota(db, "cpu_millis", 10)
            _seed_quota(db, "memory_mb", 0)
            demand = ResourceDemand(
                reservation_id=str(uuid.uuid4()),
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                items=(
                    _platform_item("cpu_millis", 1),
                    _platform_item("memory_mb", 1),
                ),
            )
            with self.assertRaises(QuotaExceededError):
                with db.session_scope() as s:
                    SqlAlchemyQuotaLedger(s).reserve(demand, _NOW)
            self.assertEqual(_reserved(db, "cpu_millis"), 0)
            with db.session_scope() as s:
                self.assertIsNone(SqlAlchemyQuotaLedger(s).get(demand.reservation_id))

    def test_duplicate_reservation_id_raises_integrity_error(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", 5)
            rid = str(uuid.uuid4())
            first = ResourceDemand(
                reservation_id=rid,
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                items=(_platform_item(),),
            )
            with db.session_scope() as s:
                SqlAlchemyQuotaLedger(s).reserve(first, _NOW)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyQuotaLedger(s).reserve(first, _NOW)

    def test_ceiling_within_cap_ok_over_cap_rejected(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "max_runtime_seconds", 3600)
            ok = ResourceDemand(
                reservation_id=str(uuid.uuid4()),
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                ceilings=(
                    CeilingRequirement(
                        "platform", PLATFORM_SCOPE_KEY, "max_runtime_seconds", 3600
                    ),
                ),
            )
            with db.session_scope() as s:
                SqlAlchemyQuotaLedger(s).reserve(ok, _NOW)
            # ceiling never counts.
            self.assertEqual(_reserved(db, "max_runtime_seconds"), 0)

            over = ResourceDemand(
                reservation_id=str(uuid.uuid4()),
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                ceilings=(
                    CeilingRequirement(
                        "platform", PLATFORM_SCOPE_KEY, "max_runtime_seconds", 3601
                    ),
                ),
            )
            with self.assertRaises(QuotaExceededError):
                with db.session_scope() as s:
                    SqlAlchemyQuotaLedger(s).reserve(over, _NOW)

    def test_reserve_against_missing_quota_raises_lookup(self) -> None:
        with _migrated_database() as (db, _url):
            demand = ResourceDemand(
                reservation_id=str(uuid.uuid4()),
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                items=(_platform_item(),),
            )
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyQuotaLedger(s).reserve(demand, _NOW)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class QuotaConcurrencyTests(unittest.TestCase):
    def test_concurrent_reserves_cannot_exceed_pool(self) -> None:
        pool = 5
        workers = 8
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", pool)
            barrier = threading.Barrier(workers)
            successes: list[str] = []
            overruns: list[str] = []
            lock = threading.Lock()

            def attempt() -> None:
                rid = str(uuid.uuid4())
                demand = ResourceDemand(
                    reservation_id=rid,
                    worker_key="w1",
                    expires_at=_NOW + timedelta(hours=1),
                    items=(_platform_item(),),
                )
                barrier.wait()
                try:
                    with db.session_scope() as s:
                        SqlAlchemyQuotaLedger(s).reserve(demand, _NOW)
                    with lock:
                        successes.append(rid)
                except QuotaExceededError:
                    with lock:
                        overruns.append(rid)

            threads = [threading.Thread(target=attempt) for _ in range(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(successes), pool)
            self.assertEqual(len(overruns), workers - pool)
            self.assertEqual(_reserved(db, "active_instances"), pool)

    def test_reconcile_recomputes_from_held_items(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", 10)
            rid = str(uuid.uuid4())
            demand = ResourceDemand(
                reservation_id=rid,
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                items=(_platform_item(amount=3),),
            )
            with db.session_scope() as s:
                SqlAlchemyQuotaLedger(s).reserve(demand, _NOW)
            # Corrupt the counter, then self-heal.
            with db.session_scope() as s:
                s.execute(
                    sa.text(
                        "UPDATE resource_quotas SET reserved_value = 99 "
                        "WHERE dimension = 'active_instances'"
                    )
                )
            with db.session_scope() as s:
                changed = SqlAlchemyQuotaLedger(s).reconcile_counters()
            self.assertGreaterEqual(changed, 1)
            self.assertEqual(_reserved(db, "active_instances"), 3)

    def test_list_expired_returns_stale_holds(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", 10)
            rid = str(uuid.uuid4())
            demand = ResourceDemand(
                reservation_id=rid,
                worker_key="w1",
                expires_at=_NOW - timedelta(minutes=1),  # already expired
                items=(_platform_item(),),
            )
            with db.session_scope() as s:
                SqlAlchemyQuotaLedger(s).reserve(demand, _NOW - timedelta(hours=1))
            with db.session_scope() as s:
                expired = SqlAlchemyQuotaLedger(s).list_expired(_NOW)
            self.assertEqual([r.reservation_id for r in expired], [rid])


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class QuotaGuardTests(unittest.TestCase):
    def test_delete_quota_with_reserved_raises_programming_error(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", 5)
            demand = ResourceDemand(
                reservation_id=str(uuid.uuid4()),
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                items=(_platform_item(),),
            )
            with db.session_scope() as s:
                SqlAlchemyQuotaLedger(s).reserve(demand, _NOW)
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(
                        sa.text(
                            "DELETE FROM resource_quotas "
                            "WHERE dimension = 'active_instances'"
                        )
                    )

    def test_delete_drained_quota_allowed(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", 5)
            with db.session_scope() as s:
                s.execute(
                    sa.text(
                        "DELETE FROM resource_quotas "
                        "WHERE dimension = 'active_instances'"
                    )
                )
            with db.session_scope() as s:
                self.assertIsNone(
                    SqlAlchemyQuotaPolicyRepository(s).get(
                        "platform", PLATFORM_SCOPE_KEY, "active_instances"
                    )
                )

    def test_reservation_items_are_append_only(self) -> None:
        with _migrated_database() as (db, _url):
            _seed_quota(db, "active_instances", 5)
            demand = ResourceDemand(
                reservation_id=str(uuid.uuid4()),
                worker_key="w1",
                expires_at=_NOW + timedelta(hours=1),
                items=(_platform_item(),),
            )
            with db.session_scope() as s:
                SqlAlchemyQuotaLedger(s).reserve(demand, _NOW)
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.text("UPDATE quota_reservation_items SET amount = 99"))
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.text("DELETE FROM quota_reservation_items"))


if __name__ == "__main__":
    unittest.main()
