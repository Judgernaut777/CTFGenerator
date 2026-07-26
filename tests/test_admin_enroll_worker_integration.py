"""``ctfgen-admin enroll-worker`` -- operator worker enrollment (PostgreSQL-gated).

Proves the operator path that mints a worker's scoped bearer token: registration
persists a pending identity, approval flips trust + issues the first credential,
and the printed ``CTFGEN_WORKER_TOKEN=...`` authenticates against the enrollment
service. Closes the gap where worker enrollment was reachable only from test code.

SKIPS cleanly without [db] + CTFGEN_TEST_DATABASE_URL.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_admin_enroll_worker_integration
"""

from __future__ import annotations

import io
import os
import unittest
import uuid
from contextlib import contextmanager, redirect_stdout
from datetime import UTC, datetime

try:
    import sqlalchemy as sa
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy.engine import make_url

    from ctf_generator.application.worker_enrollment import WorkerEnrollmentService
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.interfaces.cli.admin import main as admin_main

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)
_SKIP_REASON = (
    f"[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)


@contextmanager
def _migrated_db():
    base = make_url(_TEST_URL)
    name = f"ctfgen_enroll_it_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(
        base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        url = base.set(database=name).render_as_string(hide_password=False)
        cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        db = Database(DatabaseConfig(url=url))
        try:
            yield url, db
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class EnrollWorkerCliTests(unittest.TestCase):
    def test_enroll_prints_a_token_that_authenticates(self) -> None:
        with _migrated_db() as (url, db):
            buf = io.StringIO()
            # The CLI reads the DSN from the environment, like the real deployment.
            with unittest_env(CTFGEN_DATABASE_URL=url):
                with redirect_stdout(buf):
                    rc = admin_main(
                        ["enroll-worker", "--name", "w-cli-1", "--capacity", "2"]
                    )
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            token_line = [
                ln for ln in out.splitlines() if ln.startswith("CTFGEN_WORKER_TOKEN=")
            ]
            self.assertEqual(len(token_line), 1, out)
            token = token_line[0].split("=", 1)[1]
            self.assertTrue(token.startswith("ctfw1."), token)

            # The minted token authenticates as a trusted worker.
            auth = WorkerEnrollmentService(db).authenticate(token, datetime.now(UTC))
            self.assertIsNotNone(auth)
            self.assertEqual(auth.worker.name, "w-cli-1")
            self.assertEqual(auth.worker.trust_state, "trusted")


class _unittest_env:
    def __init__(self, **kv: str) -> None:
        self._kv = kv
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        for k, v in self._kv.items():
            self._saved[k] = os.environ.get(k)
            os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k, old in self._saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def unittest_env(**kv: str) -> _unittest_env:
    return _unittest_env(**kv)


if __name__ == "__main__":
    unittest.main()
