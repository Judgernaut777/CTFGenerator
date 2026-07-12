"""Authentication domain value types (M10 slice a).

Pure, stdlib-only frozen aggregates for local password credentials + server-side
sessions + deployment-global system-role assignments. No hashing, I/O, or
framework lives here -- only the value types and their invariants (the password
KDF and secret generation are application concerns; see
``ctf_generator.application.auth``).
"""

from __future__ import annotations

from .models import (
    VALID_SYSTEM_ROLES,
    AuthCredential,
    AuthSession,
    IssuedSession,
    SystemRoleAssignment,
    is_encoded_password_hash,
)

__all__ = [
    "VALID_SYSTEM_ROLES",
    "AuthCredential",
    "AuthSession",
    "IssuedSession",
    "SystemRoleAssignment",
    "is_encoded_password_hash",
]
