"""PostgreSQL integration tests for the M6 persistence foundation.

Docker-gated. These require SQLAlchemy/Alembic (the ``db`` extra) and a running
PostgreSQL reachable via ``CTFGEN_TEST_DATABASE_URL``. When either is absent --
e.g. the PEP 668 stdlib-only host running the unit suite -- every test SKIPS, so
this module never breaks the core gate. Run it in CI's integration tier / a
Docker container with a postgres service:

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_database_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:  # heavy deps are optional; guard so import never fails the host suite
    import sqlalchemy as sa
    from sqlalchemy.engine import make_url
    from alembic import command
    from alembic.config import Config as AlembicConfig

    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - exercised only without the extra
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"db extra not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)


@contextmanager
def _isolated_database():
    """Create a throwaway database, yield its URL, and drop it afterwards.

    Proves each test can run against an isolated database rather than sharing
    state. Connects to the server via the configured URL with AUTOCOMMIT to
    issue CREATE/DROP DATABASE (which cannot run inside a transaction).
    """
    base = make_url(_TEST_URL)
    name = f"ctfgen_it_{uuid.uuid4().hex[:12]}"
    # Pin the admin connection to the standard maintenance database so CREATE/DROP
    # DATABASE work regardless of which database the caller's URL names.
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        # Yield a DSN STRING with the password preserved. `str(URL)` masks the
        # password as '***', which would then fail auth downstream -- render it
        # explicitly so callers get a usable connection string.
        yield base.set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            # Atomic terminate+drop (PG 13+) so a late connection to the db can't
            # race the drop and leak it.
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _alembic_config(url) -> "AlembicConfig":
    cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
    cfg.set_main_option("sqlalchemy.url", str(url))
    return cfg


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class DatabaseIntegrationTests(unittest.TestCase):
    def test_engine_connects(self) -> None:
        with _isolated_database() as url:
            db = Database(DatabaseConfig(url=str(url)))
            try:
                with db.engine.connect() as conn:
                    self.assertEqual(conn.execute(sa.text("SELECT 1")).scalar(), 1)
            finally:
                db.dispose()

    def test_session_scope_commits_and_rolls_back(self) -> None:
        with _isolated_database() as url:
            db = Database(DatabaseConfig(url=str(url)))
            try:
                with db.session_scope() as s:
                    s.execute(sa.text("CREATE TABLE t (id int primary key)"))
                # committed create is visible; a failing scope rolls back its writes
                with db.session_scope() as s:
                    s.execute(sa.text("INSERT INTO t (id) VALUES (1)"))
                with self.assertRaises(RuntimeError):
                    with db.session_scope() as s:
                        s.execute(sa.text("INSERT INTO t (id) VALUES (2)"))
                        raise RuntimeError("boom")  # triggers rollback
                with db.session_scope() as s:
                    rows = s.execute(sa.text("SELECT id FROM t ORDER BY id")).scalars().all()
                self.assertEqual(rows, [1])  # row 2 was rolled back
            finally:
                db.dispose()

    def test_alembic_upgrade_and_downgrade(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            engine = sa.create_engine(url, future=True)
            try:
                command.upgrade(cfg, "head")
                with engine.connect() as conn:
                    version = conn.execute(
                        sa.text("SELECT version_num FROM alembic_version")
                    ).scalar()
                self.assertEqual(version, "0001_baseline")

                command.downgrade(cfg, "base")
                with engine.connect() as conn:
                    remaining = conn.execute(
                        sa.text("SELECT count(*) FROM alembic_version")
                    ).scalar()
                self.assertEqual(remaining, 0)
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
