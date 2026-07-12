"""Migration/ORM drift + clean up/down integration test (M7).

Docker-gated like the other repository suites; skips cleanly without the db
extra / CTFGEN_TEST_DATABASE_URL.

Proves two properties on an isolated database:

1.  After ``upgrade head``, ``compare_metadata`` against ``Base.metadata`` is
    empty with ``compare_type`` and ``compare_server_default`` on -- the hand
    written migrations do not drift from the ORM models.
2.  ``upgrade head`` then ``downgrade base`` leaves only ``alembic_version`` and
    no leftover public functions (every migration's downgrade drops what it
    created), and a subsequent re-``upgrade head`` is clean.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_migration_drift_integration
"""

from __future__ import annotations

import os
import unittest
import uuid
from contextlib import contextmanager

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.config import Config as AlembicConfig
    from alembic.migration import MigrationContext
    from sqlalchemy.engine import make_url

    # Import the models module for its side effect: registering every ORM table
    # on ``Base.metadata`` (compare_metadata needs the full metadata).
    import ctf_generator.infrastructure.database.models  # noqa: F401
    from ctf_generator.infrastructure.database.base import Base

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


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class MigrationDriftTests(unittest.TestCase):
    def test_head_has_no_autogenerate_drift(self) -> None:
        with _isolated_database() as url:
            command.upgrade(_alembic_config(url), "head")
            engine = sa.create_engine(url, future=True)
            try:
                with engine.connect() as conn:
                    ctx = MigrationContext.configure(
                        conn,
                        opts={
                            "target_metadata": Base.metadata,
                            "compare_type": True,
                            "compare_server_default": True,
                        },
                    )
                    diffs = compare_metadata(ctx, Base.metadata)
            finally:
                engine.dispose()
        self.assertEqual(diffs, [], f"unexpected schema drift: {diffs!r}")

    def test_full_downgrade_leaves_clean_database(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            command.upgrade(cfg, "head")
            command.downgrade(cfg, "base")
            engine = sa.create_engine(url, future=True)
            try:
                with engine.connect() as conn:
                    tables = (
                        conn.execute(
                            sa.text(
                                "SELECT tablename FROM pg_tables "
                                "WHERE schemaname = 'public' ORDER BY tablename"
                            )
                        )
                        .scalars()
                        .all()
                    )
                    functions = (
                        conn.execute(
                            sa.text(
                                "SELECT p.proname FROM pg_proc p "
                                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                                "WHERE n.nspname = 'public' ORDER BY p.proname"
                            )
                        )
                        .scalars()
                        .all()
                    )
                self.assertEqual(tables, ["alembic_version"])
                self.assertEqual(functions, [])  # no leftover trigger functions
                command.upgrade(cfg, "head")
                head_tables = set(sa.inspect(engine).get_table_names())
                self.assertIn("jobs", head_tables)
                # M10a auth tables are present at head and dropped cleanly on
                # downgrade (they must not appear in the "clean database" set
                # above -- proven by the ["alembic_version"] assertion).
                self.assertIn("auth_credentials", head_tables)
                self.assertIn("sessions", head_tables)
                self.assertIn("user_system_roles", head_tables)
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
