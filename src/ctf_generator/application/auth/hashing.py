"""Pluggable password hashing (application layer, M10a).

A narrow :class:`PasswordHasher` seam plus the default stdlib implementation,
:class:`Pbkdf2Sha256Hasher` (PBKDF2-HMAC-SHA256 via ``hashlib.pbkdf2_hmac``).
The design is deliberately upgrade-friendly:

* the encoded hash is a self-describing, portable string
  ``pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>`` -- ``verify`` reads the
  algorithm + parameters out of the stored string, so raising the default
  iteration count (or dropping in a future ``Argon2Hasher``) never invalidates
  existing credentials;
* :meth:`verify` is constant-time (``hmac.compare_digest``) and returns
  ``False`` (never raises) for a malformed / unknown-algorithm encoded hash, so
  a corrupt row can never crash the login path;
* :meth:`needs_rehash` lets the service transparently upgrade a credential to
  the current parameters on the next successful login.

Stdlib only -- no new dependency (consistent with the codebase). The default
iteration count (600_000) meets current OWASP guidance for PBKDF2-HMAC-SHA256.
A password/hash is NEVER logged (REQ-INV-011); this module logs nothing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Protocol

# OWASP-guidance floor for PBKDF2-HMAC-SHA256 (2023+). Configurable upward per
# deployment; never below this without an ADR.
DEFAULT_PBKDF2_ITERATIONS = 600_000

_ALGORITHM = "pbkdf2_sha256"
_SALT_BYTES = 16
_DK_BYTES = 32  # SHA-256 digest size


class PasswordHasher(Protocol):
    """Hash + verify a plaintext password against a portable encoded hash.

    Implementations MUST NOT log the password or the hash, MUST compare in
    constant time, and MUST return ``False`` (not raise) from ``verify`` on a
    malformed encoded hash.
    """

    def hash(self, password: str) -> str:
        """Return a self-describing encoded hash of ``password`` (with a fresh
        random salt)."""
        ...

    def verify(self, password: str, encoded: str) -> bool:
        """Constant-time check of ``password`` against ``encoded``. ``False`` on
        mismatch or a malformed / unknown-algorithm ``encoded``."""
        ...

    def needs_rehash(self, encoded: str) -> bool:
        """True iff ``encoded`` was produced with weaker parameters (or a
        different algorithm) than this hasher's current settings, so the service
        should transparently re-hash on the next successful verify."""
        ...


class Pbkdf2Sha256Hasher:
    """PBKDF2-HMAC-SHA256 password hasher (stdlib ``hashlib``)."""

    algorithm = _ALGORITHM

    def __init__(self, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> None:
        if not isinstance(iterations, int) or iterations < 1:
            raise ValueError("iterations must be a positive int")
        self._iterations = iterations

    @property
    def iterations(self) -> int:
        return self._iterations

    def _derive(self, password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=_DK_BYTES
        )

    def hash(self, password: str) -> str:
        if not isinstance(password, str) or password == "":
            raise ValueError("password must be a non-empty string")
        salt = secrets.token_bytes(_SALT_BYTES)
        dk = self._derive(password, salt, self._iterations)
        return "{}${}${}${}".format(
            _ALGORITHM,
            self._iterations,
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(dk).decode("ascii"),
        )

    def verify(self, password: str, encoded: str) -> bool:
        parsed = _parse(encoded)
        if parsed is None:
            return False
        algorithm, iterations, salt, expected_dk = parsed
        if algorithm != _ALGORITHM:
            return False
        if not isinstance(password, str):
            return False
        candidate = self._derive(password, salt, iterations)
        return hmac.compare_digest(candidate, expected_dk)

    def needs_rehash(self, encoded: str) -> bool:
        parsed = _parse(encoded)
        if parsed is None:
            return True  # malformed -> re-hash on next successful verify
        algorithm, iterations, _salt, _dk = parsed
        return algorithm != _ALGORITHM or iterations < self._iterations


def _parse(encoded: str) -> tuple[str, int, bytes, bytes] | None:
    """Split ``pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>`` into its parts, or
    ``None`` if malformed. Never raises."""
    if not isinstance(encoded, str):
        return None
    parts = encoded.split("$")
    if len(parts) != 4:
        return None
    algorithm, iterations_s, salt_b64, dk_b64 = parts
    try:
        iterations = int(iterations_s)
        if iterations < 1:
            return None
        salt = base64.b64decode(salt_b64, validate=True)
        dk = base64.b64decode(dk_b64, validate=True)
    except (ValueError, TypeError):
        return None
    if not salt or not dk:
        return None
    return algorithm, iterations, salt, dk


def default_password_hasher() -> PasswordHasher:
    """The production default hasher (PBKDF2-HMAC-SHA256 at the default
    iteration count)."""
    return Pbkdf2Sha256Hasher()
