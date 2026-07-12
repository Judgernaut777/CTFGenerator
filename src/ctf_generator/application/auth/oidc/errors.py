"""OIDC flow errors (M10c).

``OidcAuthError`` is the single, deliberately-undifferentiated federated-login
failure. It subclasses the application :class:`~ctf_generator.application.auth.
service.InvalidCredentialsError` so the EXISTING interface handler maps it to a
generic ``401 unauthorized`` -- exactly like a failed password login, leaking
nothing about which check failed (bad/expired/replayed state, token-exchange
failure, invalid signature / ``alg:none`` / wrong ``aud`` / wrong ``iss`` /
expired / bad nonce, disallowed domain, unverified or unprovisioned email). The
authorization ``code``, ``client_secret``, and raw ID token are never carried in
the message or returned.
"""

from __future__ import annotations

from ..service import InvalidCredentialsError


class OidcAuthError(InvalidCredentialsError):
    """A federated (OIDC) login attempt failed. Maps to 401; never leaks which
    check failed or any secret/code/token."""
