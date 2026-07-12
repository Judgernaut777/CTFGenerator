"""PostgreSQL integration tests for worker identity, trust, and credentials (M7).

Docker-gated like the other repository suites; skips cleanly without the db
extra / CTFGEN_TEST_DATABASE_URL so the stdlib host suite stays green.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/postgres \\
      PYTHONPATH=src:tests python -m unittest test_worker_repository_integration
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
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import IntegrityError, ProgrammingError

    from ctf_generator.application.worker_enrollment import (
        WorkerEnrollmentService,
        parse_token,
    )
    from ctf_generator.domain.execution.models import Worker, WorkerCredential
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.worker_repository import (
        SqlAlchemyWorkerCredentialRepository,
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


def _worker(name: str = "worker-1", **overrides) -> Worker:
    base = dict(
        name=name,
        runtime_type="docker-rootless",
        architectures=("arm64",),
        capabilities=("build_challenge",),
        capacity=2,
        version="0.7.0",
    )
    base.update(overrides)
    return Worker(**base)


def _credential(worker_name: str = "worker-1", **overrides) -> WorkerCredential:
    base = dict(
        credential_id=str(uuid.uuid4()),
        worker_name=worker_name,
        token_hash=uuid.uuid4().hex + uuid.uuid4().hex,  # 64 hex chars
        scopes=("jobs:claim",),
        issued_at=_NOW,
        expires_at=_NOW + timedelta(hours=24),
    )
    base.update(overrides)
    return WorkerCredential(**base)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerRegistryTests(unittest.TestCase):
    def test_registration_round_trip(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).add(_worker())
            with db.session_scope() as s:
                got = SqlAlchemyWorkerRegistry(s).get("worker-1")
        self.assertIsNotNone(got)
        self.assertEqual(got.trust_state, "pending")
        self.assertEqual(got.architectures, ("arm64",))
        self.assertEqual(got.capabilities, ("build_challenge",))
        self.assertIsNone(got.last_heartbeat_at)

    def test_duplicate_name_raises_integrity_error(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).add(_worker())
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyWorkerRegistry(s).add(_worker())

    def test_heartbeat_is_tz_aware(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).add(_worker())
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).heartbeat("worker-1", _NOW)
            with db.session_scope() as s:
                got = SqlAlchemyWorkerRegistry(s).get("worker-1")
        self.assertEqual(got.last_heartbeat_at, _NOW)
        self.assertIsNotNone(got.last_heartbeat_at.tzinfo)

    def test_update_profile_touches_profile_only(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                registry = SqlAlchemyWorkerRegistry(s)
                registry.add(_worker())
                registry.approve("worker-1")
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).update_profile(
                    _worker(capacity=8, version="0.8.0")
                )
            with db.session_scope() as s:
                got = SqlAlchemyWorkerRegistry(s).get("worker-1")
        self.assertEqual(got.capacity, 8)
        self.assertEqual(got.version, "0.8.0")
        self.assertEqual(got.trust_state, "trusted")  # untouched by profile

    def test_full_transition_matrix(self) -> None:
        with _migrated_database() as (db, _url):
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).add(_worker())
            # approve: pending -> trusted; a second approve is illegal.
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).approve("worker-1")
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyWorkerRegistry(s).approve("worker-1")
            # quarantine / clear (reversible overlay).
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).quarantine(
                    "worker-1", _NOW, "suspicious build output"
                )
            with db.session_scope() as s:
                got = SqlAlchemyWorkerRegistry(s).get("worker-1")
                self.assertEqual(got.quarantine_reason, "suspicious build output")
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).clear_quarantine("worker-1")
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyWorkerRegistry(s).clear_quarantine("worker-1")
            # drain / resume (reversible overlay).
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).drain("worker-1", _NOW)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).resume("worker-1")
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyWorkerRegistry(s).resume("worker-1")
            # revoke is terminal: nothing transitions out of it.
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).revoke("worker-1", _NOW)
            for illegal in ("approve", "revoke"):
                with self.subTest(illegal=illegal):
                    with self.assertRaises(LookupError):
                        with db.session_scope() as s:
                            registry = SqlAlchemyWorkerRegistry(s)
                            if illegal == "approve":
                                registry.approve("worker-1")
                            else:
                                registry.revoke("worker-1", _NOW)

    def test_missing_worker_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyWorkerRegistry(s).approve("ghost")

    def test_quarantine_pairing_check_is_db_backstopped(self) -> None:
        with _migrated_database() as (db, url):
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).add(_worker())
            engine = sa.create_engine(url, future=True)
            try:
                with self.assertRaises(IntegrityError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "UPDATE workers SET quarantined_at = now() "
                                "WHERE name = 'worker-1'"
                            )
                        )
            finally:
                engine.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerCredentialRepositoryTests(unittest.TestCase):
    def _seed_worker(self, db, name: str = "worker-1") -> None:
        with db.session_scope() as s:
            SqlAlchemyWorkerRegistry(s).add(_worker(name))

    def test_add_get_round_trip(self) -> None:
        with _migrated_database() as (db, _url):
            self._seed_worker(db)
            cred = _credential()
            with db.session_scope() as s:
                SqlAlchemyWorkerCredentialRepository(s).add(cred)
            with db.session_scope() as s:
                repo = SqlAlchemyWorkerCredentialRepository(s)
                got = repo.get(cred.credential_id)
                active = repo.get_active_for_worker("worker-1")
        self.assertEqual(got.token_hash, cred.token_hash)
        self.assertEqual(got.worker_name, "worker-1")
        self.assertEqual(active.credential_id, cred.credential_id)

    def test_second_active_credential_raises_integrity_error(self) -> None:
        with _migrated_database() as (db, _url):
            self._seed_worker(db)
            with db.session_scope() as s:
                SqlAlchemyWorkerCredentialRepository(s).add(_credential())
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyWorkerCredentialRepository(s).add(_credential())

    def test_rotation_is_atomic_failure_applies_neither(self) -> None:
        # Revoke-old + insert-new share one UoW: if the insert fails (here a
        # deliberately CHECK-violating hash smuggled via raw SQL), the
        # revocation of the old credential must roll back with it.
        with _migrated_database() as (db, _url):
            self._seed_worker(db)
            cred = _credential()
            with db.session_scope() as s:
                SqlAlchemyWorkerCredentialRepository(s).add(cred)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    repo = SqlAlchemyWorkerCredentialRepository(s)
                    repo.revoke(cred.credential_id, _NOW)
                    s.execute(
                        sa.text(
                            "INSERT INTO worker_credentials "
                            "(id, worker_id, token_hash, scopes, issued_at, "
                            "expires_at) SELECT :id, worker_id, 'ctfw1.plain', "
                            "scopes, issued_at, expires_at FROM "
                            "worker_credentials WHERE id = :old"
                        ),
                        {"id": uuid.uuid4(), "old": cred.credential_id},
                    )
            with db.session_scope() as s:
                active = SqlAlchemyWorkerCredentialRepository(s).get_active_for_worker(
                    "worker-1"
                )
        self.assertIsNotNone(active)  # the old credential is still live
        self.assertEqual(active.credential_id, cred.credential_id)

    def test_revoke_then_new_credential_is_allowed(self) -> None:
        with _migrated_database() as (db, _url):
            self._seed_worker(db)
            first = _credential()
            with db.session_scope() as s:
                SqlAlchemyWorkerCredentialRepository(s).add(first)
            with db.session_scope() as s:
                repo = SqlAlchemyWorkerCredentialRepository(s)
                repo.revoke(first.credential_id, _NOW)
                repo.add(_credential())
            with db.session_scope() as s:
                history = SqlAlchemyWorkerCredentialRepository(s).list_for_worker(
                    "worker-1"
                )
        self.assertEqual(len(history), 2)

    def test_double_revoke_raises_lookuperror(self) -> None:
        with _migrated_database() as (db, _url):
            self._seed_worker(db)
            cred = _credential()
            with db.session_scope() as s:
                SqlAlchemyWorkerCredentialRepository(s).add(cred)
            with db.session_scope() as s:
                SqlAlchemyWorkerCredentialRepository(s).revoke(
                    cred.credential_id, _NOW
                )
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyWorkerCredentialRepository(s).revoke(
                        cred.credential_id, _NOW
                    )

    def test_freeze_trigger_blocks_every_other_update_and_delete(self) -> None:
        with _migrated_database() as (db, url):
            self._seed_worker(db)
            cred = _credential()
            with db.session_scope() as s:
                SqlAlchemyWorkerCredentialRepository(s).add(cred)
            engine = sa.create_engine(url, future=True)
            try:
                for stmt in (
                    "UPDATE worker_credentials SET scopes = '{jobs:claim,artifacts:pull}'",
                    "UPDATE worker_credentials SET expires_at = now() + interval '1 year'",
                    "UPDATE worker_credentials SET token_hash = repeat('b', 64)",
                    "DELETE FROM worker_credentials",
                    "TRUNCATE worker_credentials",
                ):
                    with self.subTest(stmt=stmt):
                        with self.assertRaises(ProgrammingError):
                            with engine.begin() as conn:
                                conn.execute(sa.text(stmt))
                # Un-revoking (revoked_at back to NULL) is also frozen.
                with engine.begin() as conn:
                    conn.execute(
                        sa.text(
                            "UPDATE worker_credentials SET revoked_at = now() "
                            "WHERE id = :id"
                        ),
                        {"id": cred.credential_id},
                    )
                with self.assertRaises(ProgrammingError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "UPDATE worker_credentials SET revoked_at = NULL "
                                "WHERE id = :id"
                            ),
                            {"id": cred.credential_id},
                        )
            finally:
                engine.dispose()

    def test_plaintext_shaped_token_hash_rejected_by_check(self) -> None:
        with _migrated_database() as (db, url):
            self._seed_worker(db)
            engine = sa.create_engine(url, future=True)
            try:
                with self.assertRaises(IntegrityError):
                    with engine.begin() as conn:
                        conn.execute(
                            sa.text(
                                "INSERT INTO worker_credentials "
                                "(id, worker_id, token_hash, scopes, issued_at, "
                                "expires_at) SELECT :id, id, "
                                "'ctfw1.cred.plaintextsecret', '{jobs:claim}', "
                                "now(), now() + interval '1 day' "
                                "FROM workers WHERE name = 'worker-1'"
                            ),
                            {"id": uuid.uuid4()},
                        )
            finally:
                engine.dispose()


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkerEnrollmentServiceTests(unittest.TestCase):
    def test_register_creates_pending_worker_with_no_credential(self) -> None:
        with _migrated_database() as (db, _url):
            service = WorkerEnrollmentService(db)
            registered = service.register_worker(_worker())
            self.assertEqual(registered.trust_state, "pending")
            with db.session_scope() as s:
                creds = SqlAlchemyWorkerCredentialRepository(s).list_for_worker(
                    "worker-1"
                )
        self.assertEqual(creds, [])

    def test_approve_issues_first_credential_and_authenticates(self) -> None:
        with _migrated_database() as (db, _url):
            service = WorkerEnrollmentService(db)
            service.register_worker(_worker())
            issued = service.approve_worker("worker-1", _NOW)
            token = issued.token()
            self.assertTrue(token.startswith("ctfw1."))
            self.assertNotIn(issued.secret, repr(issued))
            worker = service.authenticate(token, _NOW + timedelta(hours=1))
        self.assertIsNotNone(worker)
        self.assertEqual(worker.name, "worker-1")
        self.assertEqual(worker.trust_state, "trusted")

    def test_rotation_invalidates_old_and_validates_new(self) -> None:
        with _migrated_database() as (db, _url):
            service = WorkerEnrollmentService(db)
            service.register_worker(_worker())
            old = service.approve_worker("worker-1", _NOW)
            new = service.rotate_credential("worker-1", _NOW + timedelta(hours=1))
            at = _NOW + timedelta(hours=2)
            self.assertIsNone(service.authenticate(old.token(), at))
            self.assertIsNotNone(service.authenticate(new.token(), at))

    def test_revoke_worker_kills_authentication(self) -> None:
        with _migrated_database() as (db, _url):
            service = WorkerEnrollmentService(db)
            service.register_worker(_worker())
            issued = service.approve_worker("worker-1", _NOW)
            at = _NOW + timedelta(hours=1)
            self.assertIsNotNone(service.authenticate(issued.token(), at))
            service.revoke_worker("worker-1", at)
            self.assertIsNone(service.authenticate(issued.token(), at))

    def test_expired_credential_fails_authentication(self) -> None:
        with _migrated_database() as (db, _url):
            service = WorkerEnrollmentService(db)
            service.register_worker(_worker())
            issued = service.approve_worker(
                "worker-1", _NOW, ttl=timedelta(hours=1)
            )
            # now is caller-passed, so expiry needs no sleeping and no
            # dependence on the container's clock.
            self.assertIsNotNone(
                service.authenticate(issued.token(), _NOW + timedelta(minutes=59))
            )
            self.assertIsNone(
                service.authenticate(issued.token(), _NOW + timedelta(hours=2))
            )

    def test_quarantined_worker_fails_authentication(self) -> None:
        with _migrated_database() as (db, _url):
            service = WorkerEnrollmentService(db)
            service.register_worker(_worker())
            issued = service.approve_worker("worker-1", _NOW)
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).quarantine(
                    "worker-1", _NOW, "incident-42"
                )
            at = _NOW + timedelta(hours=1)
            self.assertIsNone(service.authenticate(issued.token(), at))
            with db.session_scope() as s:
                SqlAlchemyWorkerRegistry(s).clear_quarantine("worker-1")
            self.assertIsNotNone(service.authenticate(issued.token(), at))

    def test_wrong_secret_and_malformed_tokens_fail(self) -> None:
        with _migrated_database() as (db, _url):
            service = WorkerEnrollmentService(db)
            service.register_worker(_worker())
            issued = service.approve_worker("worker-1", _NOW)
            at = _NOW + timedelta(hours=1)
            for bad in (
                f"ctfw1.{issued.credential_id}.wrong-secret",
                f"ctfw2.{issued.credential_id}.{issued.secret}",
                "not-a-token",
                "",
                f"ctfw1.{uuid.uuid4()}.{issued.secret}",
            ):
                with self.subTest(bad=bad[:24]):
                    self.assertIsNone(service.authenticate(bad, at))

    def test_parse_token_round_trip(self) -> None:
        parsed = parse_token("ctfw1.cred-id.secret.with.dots")
        self.assertEqual(parsed, ("cred-id", "secret.with.dots"))
        self.assertIsNone(parse_token("ctfw1.only-two"))
        self.assertIsNone(parse_token(None))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class WorkersMigrationTests(unittest.TestCase):
    def test_migration_upgrade_downgrade(self) -> None:
        with _isolated_database() as url:
            cfg = _alembic_config(url)
            engine = sa.create_engine(url, future=True)
            try:
                command.upgrade(cfg, "0007_workers")
                insp = sa.inspect(engine)
                for table in ("workers", "worker_credentials"):
                    self.assertIn(table, insp.get_table_names())
                command.downgrade(cfg, "0006_jobs")
                insp = sa.inspect(engine)
                self.assertNotIn("workers", insp.get_table_names())
                with engine.connect() as conn:
                    fns = (
                        conn.execute(
                            sa.text(
                                "SELECT proname FROM pg_proc WHERE proname IN "
                                "('worker_credentials_freeze', 'reject_mutation')"
                            )
                        )
                        .scalars()
                        .all()
                    )
                self.assertEqual(fns, ["reject_mutation"])
                command.upgrade(cfg, "0007_workers")
                self.assertIn("workers", sa.inspect(engine).get_table_names())
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
