"""PostgreSQL integration tests for the auth repositories (M10a; [db] + real PG).

credential add/get/update round-trips + one-credential-per-user uniqueness;
session live/expired/revoked lookup + revoke stamp + the append-only freeze
trigger; system-role grant/list/revoke idempotency. SKIPS cleanly without the
``[db]`` extra or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_auth_repository_integration
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

    from ctf_generator.domain.auth.models import (
        AuthCredential,
        AuthSession,
        SystemRoleAssignment,
    )
    from ctf_generator.domain.identity.models import User
    from ctf_generator.infrastructure.database.auth_repository import (
        SqlAlchemyAuthCredentialRepository,
        SqlAlchemyAuthSessionRepository,
        SqlAlchemySystemRoleRepository,
    )
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database
    from ctf_generator.infrastructure.database.user_repository import (
        SqlAlchemyUserRepository,
    )

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SKIP_REASON = (
    f"[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
_HASH = "pbkdf2_sha256$600000$c2FsdA==$aGFzaA=="
_HASH2 = "pbkdf2_sha256$700000$b3RoZXI=$b3RoZXJo"


def _token_hash(seed: str) -> str:
    import hashlib

    return hashlib.sha256(seed.encode()).hexdigest()


@contextmanager
def _database():
    base = make_url(_TEST_URL)
    name = f"ctfgen_auth_it_{uuid.uuid4().hex[:12]}"
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
            yield db
        finally:
            db.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _seed_user(db, email="user@example.com") -> None:
    with db.session_scope() as s:
        SqlAlchemyUserRepository(s).add(User(email=email, display_name="A User"))


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AuthCredentialRepositoryTests(unittest.TestCase):
    def test_add_get_update_round_trip(self) -> None:
        with _database() as db:
            _seed_user(db)
            with db.session_scope() as s:
                SqlAlchemyAuthCredentialRepository(s).add(
                    AuthCredential("User@example.com", _HASH, _NOW, _NOW)
                )
            with db.session_scope() as s:
                got = SqlAlchemyAuthCredentialRepository(s).get("user@example.com")
            self.assertIsNotNone(got)
            self.assertEqual(got.password_hash, _HASH)
            # Canonical stored email returned regardless of lookup casing.
            self.assertEqual(got.user_email, "user@example.com")

            with db.session_scope() as s:
                SqlAlchemyAuthCredentialRepository(s).update(
                    AuthCredential(
                        "user@example.com", _HASH2, got.created_at, _NOW + timedelta(hours=1)
                    )
                )
            with db.session_scope() as s:
                rotated = SqlAlchemyAuthCredentialRepository(s).get("user@example.com")
            self.assertEqual(rotated.password_hash, _HASH2)

    def test_one_credential_per_user(self) -> None:
        with _database() as db:
            _seed_user(db)
            with db.session_scope() as s:
                SqlAlchemyAuthCredentialRepository(s).add(
                    AuthCredential("user@example.com", _HASH, _NOW, _NOW)
                )
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    SqlAlchemyAuthCredentialRepository(s).add(
                        AuthCredential("user@example.com", _HASH2, _NOW, _NOW)
                    )

    def test_add_unknown_user_fails_loud(self) -> None:
        with _database() as db:
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyAuthCredentialRepository(s).add(
                        AuthCredential("ghost@example.com", _HASH, _NOW, _NOW)
                    )

    def test_update_missing_credential(self) -> None:
        with _database() as db:
            _seed_user(db)
            with self.assertRaises(LookupError):
                with db.session_scope() as s:
                    SqlAlchemyAuthCredentialRepository(s).update(
                        AuthCredential("user@example.com", _HASH, _NOW, _NOW)
                    )

    def test_plaintext_hash_rejected_by_db(self) -> None:
        # The domain blocks this, but the CHECK is the DB backstop -- prove it by
        # writing a bare plaintext directly (bypassing the domain guard).
        with _database() as db:
            _seed_user(db)
            with self.assertRaises(IntegrityError):
                with db.session_scope() as s:
                    uid = s.execute(sa.text("SELECT id FROM users LIMIT 1")).scalar()
                    s.execute(
                        sa.text(
                            "INSERT INTO auth_credentials "
                            "(id, user_id, password_hash, updated_at) "
                            "VALUES (:i, :u, 'plaintextpw', now())"
                        ),
                        {"i": str(uuid.uuid4()), "u": uid},
                    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AuthSessionRepositoryTests(unittest.TestCase):
    def _add(self, db, seed, *, expires, revoked=None, sid=None):
        session = AuthSession(
            session_id=sid or str(uuid.uuid4()),
            user_email="user@example.com",
            token_hash=_token_hash(seed),
            issued_at=_NOW,
            expires_at=expires,
            revoked_at=revoked,
        )
        with db.session_scope() as s:
            SqlAlchemyAuthSessionRepository(s).add(session)
        return session

    def test_live_lookup_and_revoke(self) -> None:
        with _database() as db:
            _seed_user(db)
            sess = self._add(db, "tok-live", expires=_NOW + timedelta(hours=12))
            with db.session_scope() as s:
                got = SqlAlchemyAuthSessionRepository(s).get_by_token_hash(
                    _token_hash("tok-live")
                )
            self.assertIsNotNone(got)
            self.assertTrue(got.is_live(_NOW + timedelta(hours=1)))
            self.assertEqual(got.user_email, "user@example.com")

            with db.session_scope() as s:
                SqlAlchemyAuthSessionRepository(s).revoke(
                    sess.session_id, _NOW + timedelta(hours=1)
                )
            with db.session_scope() as s:
                revoked = SqlAlchemyAuthSessionRepository(s).get(sess.session_id)
            self.assertIsNotNone(revoked.revoked_at)
            self.assertFalse(revoked.is_live(_NOW + timedelta(hours=2)))

    def test_expired_session_not_live(self) -> None:
        with _database() as db:
            _seed_user(db)
            self._add(db, "tok-exp", expires=_NOW + timedelta(minutes=1))
            with db.session_scope() as s:
                got = SqlAlchemyAuthSessionRepository(s).get_by_token_hash(
                    _token_hash("tok-exp")
                )
            self.assertFalse(got.is_live(_NOW + timedelta(hours=1)))

    def test_revoke_is_idempotent(self) -> None:
        with _database() as db:
            _seed_user(db)
            sess = self._add(db, "tok-idem", expires=_NOW + timedelta(hours=12))
            with db.session_scope() as s:
                repo = SqlAlchemyAuthSessionRepository(s)
                repo.revoke(sess.session_id, _NOW + timedelta(hours=1))
                repo.revoke(sess.session_id, _NOW + timedelta(hours=2))  # no-op

    def test_unknown_token_hash_is_none(self) -> None:
        with _database() as db:
            _seed_user(db)
            with db.session_scope() as s:
                self.assertIsNone(
                    SqlAlchemyAuthSessionRepository(s).get_by_token_hash(
                        _token_hash("nope")
                    )
                )

    def test_freeze_trigger_blocks_arbitrary_update(self) -> None:
        # The near-append-only freeze trigger permits only the revoked_at stamp;
        # any other column change must be rejected at the DB.
        with _database() as db:
            _seed_user(db)
            sess = self._add(db, "tok-freeze", expires=_NOW + timedelta(hours=12))
            with self.assertRaises((ProgrammingError, IntegrityError)):
                with db.session_scope() as s:
                    s.execute(
                        sa.text(
                            "UPDATE sessions SET token_hash = :h WHERE id = :i"
                        ),
                        {"h": _token_hash("mutated"), "i": sess.session_id},
                    )

    def test_delete_is_blocked(self) -> None:
        with _database() as db:
            _seed_user(db)
            sess = self._add(db, "tok-del", expires=_NOW + timedelta(hours=12))
            with self.assertRaises((ProgrammingError, IntegrityError)):
                with db.session_scope() as s:
                    s.execute(
                        sa.text("DELETE FROM sessions WHERE id = :i"),
                        {"i": sess.session_id},
                    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class SystemRoleRepositoryTests(unittest.TestCase):
    def test_grant_list_revoke_idempotent(self) -> None:
        with _database() as db:
            _seed_user(db)
            with db.session_scope() as s:
                repo = SqlAlchemySystemRoleRepository(s)
                repo.grant(SystemRoleAssignment("user@example.com", "admin"))
                repo.grant(SystemRoleAssignment("user@example.com", "admin"))  # no-op
                repo.grant(SystemRoleAssignment("user@example.com", "support"))
            with db.session_scope() as s:
                roles = SqlAlchemySystemRoleRepository(s).list_for_user(
                    "user@example.com"
                )
            self.assertEqual(roles, frozenset({"admin", "support"}))

            with db.session_scope() as s:
                repo = SqlAlchemySystemRoleRepository(s)
                self.assertTrue(repo.revoke("user@example.com", "support"))
                self.assertFalse(repo.revoke("user@example.com", "support"))
            with db.session_scope() as s:
                roles = SqlAlchemySystemRoleRepository(s).list_for_user(
                    "user@example.com"
                )
            self.assertEqual(roles, frozenset({"admin"}))

    def test_unknown_user_reads_empty(self) -> None:
        with _database() as db:
            with db.session_scope() as s:
                self.assertEqual(
                    SqlAlchemySystemRoleRepository(s).list_for_user("ghost@x.io"),
                    frozenset(),
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
