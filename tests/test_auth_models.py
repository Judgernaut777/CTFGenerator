"""Pure domain tests for the auth value types (host suite -- no deps).

Exercises the frozen-dataclass invariants of ``AuthCredential`` / ``AuthSession``
/ ``SystemRoleAssignment`` / ``IssuedSession`` and the ``is_encoded_password_hash``
helper. Stdlib only, so this runs everywhere the domain runs.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from ctf_generator.domain.auth.models import (
    VALID_SYSTEM_ROLES,
    AuthCredential,
    AuthSession,
    IssuedSession,
    SystemRoleAssignment,
    is_encoded_password_hash,
)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)
_HASH = "pbkdf2_sha256$600000$c2FsdA==$aGFzaA=="
_TOKEN_HASH = "a" * 64


class EncodedHashHelperTests(unittest.TestCase):
    def test_accepts_encoded_forms(self) -> None:
        self.assertTrue(is_encoded_password_hash(_HASH))
        self.assertTrue(is_encoded_password_hash("argon2id$v=19$m=1$x$y"))

    def test_rejects_plaintext_and_malformed(self) -> None:
        for bad in ["", "hunter2", "no-dollar-sign", "a$", "$b", "has space$x", 123, None]:
            self.assertFalse(is_encoded_password_hash(bad), bad)


class AuthCredentialTests(unittest.TestCase):
    def test_valid(self) -> None:
        c = AuthCredential("a@b.io", _HASH, _NOW, _NOW)
        self.assertEqual(c.user_email, "a@b.io")

    def test_rejects_plaintext_hash(self) -> None:
        with self.assertRaises(ValueError):
            AuthCredential("a@b.io", "plaintext", _NOW, _NOW)

    def test_rejects_empty_email(self) -> None:
        with self.assertRaises(ValueError):
            AuthCredential("  ", _HASH, _NOW, _NOW)

    def test_rejects_naive_timestamps(self) -> None:
        with self.assertRaises(ValueError):
            AuthCredential("a@b.io", _HASH, datetime(2026, 7, 12, 12, 0), _NOW)

    def test_rejects_updated_before_created(self) -> None:
        with self.assertRaises(ValueError):
            AuthCredential("a@b.io", _HASH, _NOW, _NOW - timedelta(seconds=1))


class AuthSessionTests(unittest.TestCase):
    def _session(self, **kw):
        base = dict(
            session_id="s1",
            user_email="a@b.io",
            token_hash=_TOKEN_HASH,
            issued_at=_NOW,
            expires_at=_NOW + timedelta(hours=12),
        )
        base.update(kw)
        return AuthSession(**base)

    def test_valid_and_live(self) -> None:
        s = self._session()
        self.assertTrue(s.is_live(_NOW + timedelta(hours=1)))

    def test_expired_not_live(self) -> None:
        s = self._session()
        self.assertFalse(s.is_live(_NOW + timedelta(hours=13)))

    def test_revoked_not_live(self) -> None:
        s = self._session(revoked_at=_NOW + timedelta(minutes=1))
        self.assertFalse(s.is_live(_NOW + timedelta(minutes=2)))

    def test_rejects_non_hex_token_hash(self) -> None:
        with self.assertRaises(ValueError):
            self._session(token_hash="z" * 64)
        with self.assertRaises(ValueError):
            self._session(token_hash="abc")  # noqa: S106

    def test_rejects_expiry_not_after_issue(self) -> None:
        with self.assertRaises(ValueError):
            self._session(expires_at=_NOW)


class SystemRoleAssignmentTests(unittest.TestCase):
    def test_valid_roles(self) -> None:
        for role in VALID_SYSTEM_ROLES:
            self.assertEqual(SystemRoleAssignment("a@b.io", role).role, role)

    def test_rejects_competition_role(self) -> None:
        # player/organizer are competition roles, NOT system roles.
        for role in ("player", "organizer", "judge", "bogus"):
            with self.assertRaises(ValueError):
                SystemRoleAssignment("a@b.io", role)


class IssuedSessionTests(unittest.TestCase):
    def test_token_is_repr_suppressed(self) -> None:
        issued = IssuedSession("s1", "a@b.io", _NOW, token="raw-secret-token")  # noqa: S106
        self.assertNotIn("raw-secret-token", repr(issued))
        self.assertEqual(issued.token, "raw-secret-token")

    def test_rejects_empty_token(self) -> None:
        with self.assertRaises(ValueError):
            IssuedSession("s1", "a@b.io", _NOW, token="")


if __name__ == "__main__":
    unittest.main()
