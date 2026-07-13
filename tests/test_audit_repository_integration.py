"""PostgreSQL integration tests for the append-only audit trail (M16 slice 16a).

Docker-gated like the other repository suites: requires the ``db`` extra and
``CTFGEN_TEST_DATABASE_URL``; skips cleanly otherwise so the stdlib host suite
stays green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_audit_repository_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from alembic.script import ScriptDirectory
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ProgrammingError

    from ctf_generator.domain.audit.models import AuditCursor, AuditEvent
    from ctf_generator.infrastructure.database.audit_repository import (
        SqlAlchemyAuditRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.models import AuditEvent as AuditEventRow
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

_T0 = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)


@contextmanager
def _isolated_database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_audit_{uuid.uuid4().hex[:12]}"
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


def _event(
    *,
    actor: str = "admin-user",
    action: str = "competition.create",
    target: str = "comp-1",
    outcome: str = "success",
    request_id: str = "req-1",
    reason: str | None = None,
    offset_seconds: int = 0,
) -> AuditEvent:
    return AuditEvent(
        audit_event_id=str(uuid.uuid4()),
        actor=actor,
        action=action,
        target=target,
        outcome=outcome,
        request_id=request_id,
        reason=reason,
        occurred_at=_T0 + timedelta(seconds=offset_seconds),
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AuditRepositoryTests(unittest.TestCase):
    def test_head_is_audit_events(self) -> None:
        cfg = _alembic_config(_TEST_URL)
        head = ScriptDirectory.from_config(cfg).get_current_head()
        self.assertEqual(head, "0014_audit_events")

    def test_add_and_list_returns_domain_newest_first(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                repo = SqlAlchemyAuditRepository(s)
                repo.add(_event(action="a.one", offset_seconds=0))
                repo.add(_event(action="a.two", offset_seconds=10))
                repo.add(_event(action="a.three", offset_seconds=20))
            with db.session_scope() as s:
                page = SqlAlchemyAuditRepository(s).list(limit=50)
        self.assertTrue(all(isinstance(e, AuditEvent) for e in page.items))
        self.assertFalse(any(isinstance(e, AuditEventRow) for e in page.items))
        # occurred_at DESC (newest first).
        self.assertEqual(
            [e.action for e in page.items], ["a.three", "a.two", "a.one"]
        )
        self.assertIsNone(page.next_cursor)

    def test_filters_by_actor_action_outcome_and_time(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                repo = SqlAlchemyAuditRepository(s)
                repo.add(_event(actor="alice", action="job.cancel",
                                outcome="success", offset_seconds=0))
                repo.add(_event(actor="bob", action="job.cancel",
                                outcome="denied", offset_seconds=30))
                repo.add(_event(actor="alice", action="competition.create",
                                outcome="success", offset_seconds=60))
            with db.session_scope() as s:
                repo = SqlAlchemyAuditRepository(s)
                by_actor = repo.list(actor="alice", limit=50)
                by_action = repo.list(action="job.cancel", limit=50)
                by_outcome = repo.list(outcome="denied", limit=50)
                windowed = repo.list(
                    since=_T0 + timedelta(seconds=15),
                    until=_T0 + timedelta(seconds=45),
                    limit=50,
                )
        self.assertEqual({e.actor for e in by_actor.items}, {"alice"})
        self.assertEqual(len(by_actor.items), 2)
        self.assertEqual({e.action for e in by_action.items}, {"job.cancel"})
        self.assertEqual({e.outcome for e in by_outcome.items}, {"denied"})
        self.assertEqual([e.actor for e in windowed.items], ["bob"])

    def test_cursor_pagination_walks_the_whole_trail(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                repo = SqlAlchemyAuditRepository(s)
                for i in range(5):
                    repo.add(_event(action=f"a.{i}", offset_seconds=i))
            collected: list[str] = []
            cursor: AuditCursor | None = None
            with db.session_scope() as s:
                repo = SqlAlchemyAuditRepository(s)
                for _ in range(10):  # bounded to avoid an infinite loop on a bug
                    page = repo.list(limit=2, cursor=cursor)
                    collected.extend(e.action for e in page.items)
                    if page.next_cursor is None:
                        break
                    cursor = page.next_cursor
        # Every event, exactly once, newest-first, in two-item pages.
        self.assertEqual(collected, ["a.4", "a.3", "a.2", "a.1", "a.0"])

    def test_reason_round_trips(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyAuditRepository(s).add(
                    _event(action="admin.override", reason="incident #42 remediation")
                )
            with db.session_scope() as s:
                page = SqlAlchemyAuditRepository(s).list(action="admin.override", limit=5)
        self.assertEqual(page.items[0].reason, "incident #42 remediation")

    def test_row_update_is_rejected_by_trigger(self) -> None:
        with _migrated_database() as (db, _url):
            event = _event()
            with db.session_scope() as s:
                SqlAlchemyAuditRepository(s).add(event)
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(
                        sa.text(
                            "UPDATE audit_events SET outcome = 'denied' WHERE id = :id"
                        ),
                        {"id": event.audit_event_id},
                    )

    def test_row_delete_is_rejected_by_trigger(self) -> None:
        with _migrated_database() as (db, _url):
            event = _event()
            with db.session_scope() as s:
                SqlAlchemyAuditRepository(s).add(event)
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(
                        sa.text("DELETE FROM audit_events WHERE id = :id"),
                        {"id": event.audit_event_id},
                    )
            # The row is still there -- tamper-evidence.
            with db.session_scope() as s:
                page = SqlAlchemyAuditRepository(s).list(limit=5)
            self.assertEqual(len(page.items), 1)

    def test_truncate_is_rejected_by_trigger(self) -> None:
        # TRUNCATE would wipe the whole tamper-evident trail at once; the migration
        # adds a BEFORE TRUNCATE guard, so it must raise too (mirrors the ledger's
        # append-only proof, which covers UPDATE + DELETE + TRUNCATE).
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyAuditRepository(s).add(_event())
            with self.assertRaises(ProgrammingError):
                with db.session_scope() as s:
                    s.execute(sa.text("TRUNCATE audit_events"))
            with db.session_scope() as s:
                page = SqlAlchemyAuditRepository(s).list(limit=5)
            self.assertEqual(len(page.items), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
