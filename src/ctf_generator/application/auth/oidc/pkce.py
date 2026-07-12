"""Pure PKCE / anti-forgery helpers (M10c) -- stdlib only, no I/O.

Separated from the service so they are trivially unit-testable and importable
without the ``[oidc]`` extra. All values are generated with :mod:`secrets`.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

# 32 random bytes -> a 256-bit, URL-safe, base64 token. Used for both the
# anti-forgery ``state`` (CSRF) and the ``nonce`` (ID-token replay).
_ENTROPY_BYTES = 32


def generate_state() -> str:
    """A >=256-bit URL-safe anti-forgery ``state`` (CSRF)."""
    return secrets.token_urlsafe(_ENTROPY_BYTES)


def generate_nonce() -> str:
    """A >=256-bit URL-safe ``nonce`` bound into the ID token (replay defense)."""
    return secrets.token_urlsafe(_ENTROPY_BYTES)


def generate_code_verifier() -> str:
    """A high-entropy PKCE ``code_verifier`` (RFC 7636 unreserved set, 43..128
    chars). ``token_urlsafe(64)`` yields ~86 chars, comfortably inside the range."""
    return secrets.token_urlsafe(64)


def generate_binding_secret() -> str:
    """A >=256-bit URL-safe browser-binding secret. Set as an httpOnly cookie at
    ``/auth/oidc/login`` and required (its hash) at the callback so the login
    transaction is bound to the initiating user-agent (login-CSRF / fixation
    defense). Only the sha256 hex is stored at rest (see :func:`hash_binding`)."""
    return secrets.token_urlsafe(_ENTROPY_BYTES)


def hash_binding(secret: str) -> str:
    """The sha256 hex of the browser-binding secret -- the only form stored in
    the login transaction (the raw secret lives only in the browser cookie)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def code_challenge_s256(code_verifier: str) -> str:
    """The S256 PKCE ``code_challenge``: base64url(SHA-256(verifier)), unpadded."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def hash_state(state: str) -> str:
    """The sha256 hex of the anti-forgery state -- the only form stored at rest
    (the raw state travels only in the authorization URL / callback query)."""
    return hashlib.sha256(state.encode("utf-8")).hexdigest()
