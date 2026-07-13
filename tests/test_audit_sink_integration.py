"""Tests for the durable + composite audit sinks (M16 slice 16a).

Two layers:

* NON-FATAL guard (host-side, no DB required): a ``DbAuditSink`` whose write fails
  -- and any sink that raises inside a ``CompositeAuditSink`` -- must NEVER
  propagate out of ``record``. An audit write can never turn an audited success
  into a 500 or roll back the user's operation.
* Durable persistence (Docker-gated): ``DbAuditSink.record`` persists a queryable
  ``AuditEvent``; ``CompositeAuditSink`` fans one event out to BOTH the DB trail
  and the log sink.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_audit_sink_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator.infrastructure.database.audit_repository import (
        SqlAlchemyAuditRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.api.audit import (
        CompositeAuditSink,
        DbAuditSink,
        audit,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IMPORTABLE = _IMPORT_ERROR is None
_ENABLED = _IMPORTABLE and bool(_TEST_URL)
_IMPORT_SKIP = f"[api]/[db] not importable ({_IMPORT_ERROR})"
_DB_SKIP = (
    _IMPORT_SKIP
    if not _IMPORTABLE
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, event: dict) -> None:
        self.events.append(dict(event))


class _ExplodingSink:
    def record(self, event: dict) -> None:
        raise RuntimeError("sink is down")


@unittest.skipUnless(_IMPORTABLE, _IMPORT_SKIP)
class AuditSinkNonFatalHostTests(unittest.TestCase):
    """No database required -- proves the best-effort guard."""

    def test_exploding_sink_in_composite_does_not_propagate(self) -> None:
        good = _RecordingSink()
        composite = CompositeAuditSink(_ExplodingSink(), good)
        # Must NOT raise even though the first sink explodes...
        audit(composite, actor="a", action="x", target="t", outcome="success")
        # ...and the healthy sibling still received the event.
        self.assertEqual(len(good.events), 1)
        self.assertEqual(good.events[0]["action"], "x")

    def test_db_sink_swallows_connection_failure(self) -> None:
        # A DbAuditSink pointed at an unreachable database. record() must catch the
        # connection error and return normally -- never raise.
        broken = Database(
            DatabaseConfig(
                url="postgresql+psycopg://nobody:nobody@127.0.0.1:1/nonexistent"
            )
        )
        sink = DbAuditSink(broken)
        try:
            sink.record(
                {
                    "actor": "admin",
                    "action": "competition.create",
                    "target": "comp-1",
                    "outcome": "success",
                    "request_id": "req-1",
                }
            )
        finally:
            broken.dispose()
        # No assertion needed: reaching here without an exception IS the proof.

    def test_db_sink_swallows_invalid_event(self) -> None:
        # An event whose outcome is not in the closed vocabulary makes the domain
        # aggregate raise inside record(); the guard swallows it (nothing persisted,
        # nothing raised).
        broken = Database(
            DatabaseConfig(url="postgresql+psycopg://x:x@127.0.0.1:1/none")
        )
        try:
            DbAuditSink(broken).record(
                {
                    "actor": "admin",
                    "action": "x",
                    "target": "t",
                    "outcome": "not-a-valid-outcome",
                    "request_id": "r",
                }
            )
        finally:
            broken.dispose()


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_audit_sink_{uuid.uuid4().hex[:12]}"
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
            yield db
        finally:
            db.dispose()


@unittest.skipUnless(_ENABLED, _DB_SKIP)
class DbAuditSinkTests(unittest.TestCase):
    def test_record_persists_a_queryable_event(self) -> None:
        with _migrated_database() as db:
            DbAuditSink(db).record(
                {
                    "actor": "admin-user",
                    "action": "competition.create",
                    "target": "comp-1",
                    "outcome": "success",
                    "request_id": "req-xyz",
                    "reason": "seeded during setup",
                }
            )
            with db.session_scope() as s:
                page = SqlAlchemyAuditRepository(s).list(limit=10)
        self.assertEqual(len(page.items), 1)
        event = page.items[0]
        self.assertEqual(event.actor, "admin-user")
        self.assertEqual(event.action, "competition.create")
        self.assertEqual(event.target, "comp-1")
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.request_id, "req-xyz")
        self.assertEqual(event.reason, "seeded during setup")
        self.assertIsNotNone(event.occurred_at.tzinfo)

    def test_composite_writes_to_both_db_and_log(self) -> None:
        with _migrated_database() as db:
            log_spy = _RecordingSink()
            composite = CompositeAuditSink(DbAuditSink(db), log_spy)
            audit(
                composite,
                actor="admin-user",
                action="job.cancel",
                target="job-7",
                outcome="success",
            )
            with db.session_scope() as s:
                page = SqlAlchemyAuditRepository(s).list(action="job.cancel", limit=10)
        # Durable trail got it...
        self.assertEqual(len(page.items), 1)
        self.assertEqual(page.items[0].target, "job-7")
        # ...and the log sink got the same event.
        self.assertEqual(len(log_spy.events), 1)
        self.assertEqual(log_spy.events[0]["action"], "job.cancel")

    def test_db_write_failure_in_composite_leaves_log_sink_intact(self) -> None:
        # A DbAuditSink whose write fails (unreachable DB) inside a composite must
        # not stop the healthy log sink and must not raise.
        broken = Database(
            DatabaseConfig(url="postgresql+psycopg://x:x@127.0.0.1:1/none")
        )
        log_spy = _RecordingSink()
        composite = CompositeAuditSink(DbAuditSink(broken), log_spy)
        try:
            audit(composite, actor="a", action="x", target="t", outcome="success")
        finally:
            broken.dispose()
        self.assertEqual(len(log_spy.events), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
