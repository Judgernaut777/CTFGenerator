"""Authentication application layer (M10 slice a).

Owns the local-password + server-session use cases over the auth persistence
repositories, plus the pluggable password-hashing seam. The password KDF, secret
generation, and constant-time comparison live here (never in the stdlib-pure
domain). See ADR-007.

The pure password-hashing seam (:mod:`.hashing`) is imported eagerly -- it is
stdlib-only, so ``import ctf_generator.application.auth.hashing`` must work on a
host without the ``[db]`` extra (its unit tests run in the plain host gate). The
:class:`~.service.AuthService` and its errors pull in the SQLAlchemy-backed
repositories, so they are re-exported LAZILY (PEP 562 ``__getattr__``): callers
that ``from ctf_generator.application.auth import AuthService`` still work, but
merely importing this package (or the pure ``.hashing`` submodule) does NOT drag
in SQLAlchemy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .hashing import PasswordHasher, Pbkdf2Sha256Hasher, default_password_hasher

if TYPE_CHECKING:  # for type checkers / IDEs only; not executed at runtime
    from .service import (
        AuthService,
        InvalidCredentialsError,
        ResolvedPrincipal,
        validate_password_strength,
    )

_LAZY = frozenset(
    {
        "AuthService",
        "InvalidCredentialsError",
        "ResolvedPrincipal",
        "validate_password_strength",
    }
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


def __getattr__(name: str):
    """Lazily resolve the SQLAlchemy-backed service names (PEP 562) so importing
    this package -- or the pure ``.hashing`` submodule -- never requires the
    ``[db]`` extra."""
    if name in _LAZY:
        from . import service

        return getattr(service, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
