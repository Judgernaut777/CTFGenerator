"""Authentication application layer (M10 slice a).

Owns the local-password + server-session use cases over the auth persistence
repositories, plus the pluggable password-hashing seam. The password KDF, secret
generation, and constant-time comparison live here (never in the stdlib-pure
domain). See ADR-007.
"""

from __future__ import annotations

from .hashing import PasswordHasher, Pbkdf2Sha256Hasher, default_password_hasher
from .service import (
    AuthService,
    InvalidCredentialsError,
    ResolvedPrincipal,
    validate_password_strength,
)

__all__ = [
    "AuthService",
    "InvalidCredentialsError",
    "PasswordHasher",
    "Pbkdf2Sha256Hasher",
    "ResolvedPrincipal",
    "default_password_hasher",
    "validate_password_strength",
]
