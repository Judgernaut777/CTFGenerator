"""Authentication value types: ``AuthCredential``, ``AuthSession``,
``SystemRoleAssignment`` (+ the one-time ``IssuedSession``).

Pure domain aggregates -- frozen dataclasses over stdlib only, no framework,
I/O, or infrastructure imports. They model *only* the persisted shapes and their
invariants; the password KDF, secret generation, and constant-time comparison
are application concerns (``ctf_generator.application.auth``). Consistent with
ADR-002 / ADR-007, **no plaintext secret is ever modelled in loggable domain
state**:

* ``AuthCredential`` -- one local password credential per user, keyed by
  ``user_email``. It carries only the *encoded* password hash
  (``pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>`` today -- an opaque, portable,
  self-describing string, never a plaintext password).
* ``AuthSession`` -- a server-side session, keyed by ``session_id``. Only the
  sha256 hex of the opaque bearer token is modelled (``token_hash``); the raw
  token never appears here. ``rotated_from`` links a refreshed session to its
  predecessor; ``revoked_at`` is the single mutable stamp (logout / refresh).
* ``SystemRoleAssignment`` -- a deployment-global role grant (``admin`` /
  ``support``) on a user's auth account. Competition roles are the identity
  domain's ``Membership`` (per-competition); the two role tiers are disjoint.
* ``IssuedSession`` -- the one-time return value carrying a freshly minted
  plaintext bearer token (``repr``-suppressed so accidental logging never prints
  it). It exists once, in memory, at login / refresh.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# The deployment-global (system) roles. Unlike the eight competition
# ``VALID_ROLES`` (which are per-competition via ``Membership``), a system role
# is granted on the user's auth account and applies across the whole
# single-deployment installation. The set is intentionally a strict subset of
# the identity domain's ``VALID_ROLES`` -- ``admin`` and ``support`` are the two
# non-competition-scoped roles (ADR-007). The store mirrors this as a CHECK.
VALID_SYSTEM_ROLES = frozenset({"admin", "support"})

_HEX64 = frozenset("0123456789abcdef")


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_tz_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")


def _require_token_hash(value: str, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or not set(value) <= _HEX64
    ):
        raise ValueError(
            f"{field_name} must be 64 lowercase hex chars (sha256 of the token; "
            "never store a plaintext token)"
        )


def is_encoded_password_hash(value: object) -> bool:
    """True iff ``value`` is a well-formed *encoded* password hash string.

    Format-agnostic on purpose so a future Argon2 hasher is a drop-in: it only
    requires the ``<algorithm>$<params...>`` shape (a non-empty algorithm label
    followed by at least one ``$``-separated parameter, no whitespace, and never
    a bare plaintext password). It deliberately does NOT validate the KDF
    parameters -- that is the hasher's job at verify time.
    """
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        return False
    parts = value.split("$")
    if len(parts) < 2:
        return False
    return all(part != "" for part in parts)


@dataclass(frozen=True)
class AuthCredential:
    """A user's local password credential (one per user, keyed by
    ``user_email``). Carries only the encoded password hash -- never a plaintext
    password. ``password_hash`` is the single mutable business field (rotated by
    a password change); ``created_at`` is set at first registration and
    ``updated_at`` stamps the last password change.
    """

    user_email: str
    password_hash: str
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _require_nonempty(self.user_email, "user_email")
        if not is_encoded_password_hash(self.password_hash):
            raise ValueError(
                "password_hash must be an encoded '<algorithm>$<params>' string "
                "(never a plaintext password)"
            )
        _require_tz_aware(self.created_at, "created_at")
        _require_tz_aware(self.updated_at, "updated_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")


@dataclass(frozen=True)
class AuthSession:
    """A server-side session, keyed by ``session_id`` (an application-assigned
    uuid string, the row PK). Only the sha256 hex of the opaque bearer token is
    persisted (``token_hash``); the plaintext travels once in
    :class:`IssuedSession`. ``revoked_at`` is the single mutable stamp (logout /
    refresh); ``rotated_from`` links a refreshed session to its predecessor.
    """

    session_id: str
    user_email: str
    token_hash: str
    issued_at: datetime
    expires_at: datetime
    rotated_from: str | None = None
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.session_id, "session_id")
        _require_nonempty(self.user_email, "user_email")
        _require_token_hash(self.token_hash, "token_hash")
        _require_tz_aware(self.issued_at, "issued_at")
        _require_tz_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.rotated_from is not None:
            _require_nonempty(self.rotated_from, "rotated_from")
        if self.revoked_at is not None:
            _require_tz_aware(self.revoked_at, "revoked_at")

    def is_live(self, now: datetime) -> bool:
        """True iff the session is neither revoked nor expired at ``now``."""
        _require_tz_aware(now, "now")
        return self.revoked_at is None and self.expires_at > now


@dataclass(frozen=True)
class SystemRoleAssignment:
    """A deployment-global role grant on a user's auth account. ``role`` must be
    one of :data:`VALID_SYSTEM_ROLES` (``admin`` / ``support``)."""

    user_email: str
    role: str

    def __post_init__(self) -> None:
        _require_nonempty(self.user_email, "user_email")
        if self.role not in VALID_SYSTEM_ROLES:
            raise ValueError(
                f"system role must be one of {sorted(VALID_SYSTEM_ROLES)}, "
                f"got {self.role!r}"
            )


@dataclass(frozen=True)
class OidcLoginTransaction:
    """A short-lived, one-time-use OIDC authorization-code login transaction
    (M10c). Created when the login redirect is built and CONSUMED (deleted) when
    the callback returns, it binds the anti-forgery ``state`` to the ``nonce``
    (ID-token replay defense), the PKCE ``code_verifier`` (code-interception
    defense), and a ``binding_hash`` (sha256 of a browser-cookie secret, tying
    the flow to the initiating user-agent -- login-CSRF / fixation defense) so
    the callback can validate them.

    Only the **sha256 hex** of the state is modelled (``state_hash``, 64-hex --
    the exact ``AuthSession.token_hash`` discipline): the raw state travels only
    in the authorization URL and the callback query, never at rest. The
    ``code_verifier`` and ``nonce`` are transient server-only secrets kept here
    solely until the one callback consumes them. ``redirect_uri`` is bound in so
    the token exchange uses the exact value the authorization used.
    """

    state_hash: str
    nonce: str
    code_verifier: str
    binding_hash: str
    redirect_uri: str
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_token_hash(self.state_hash, "state_hash")
        _require_nonempty(self.nonce, "nonce")
        _require_nonempty(self.code_verifier, "code_verifier")
        # sha256 hex of the browser-binding secret (the raw secret lives only in
        # the login cookie); same 64-hex discipline as ``state_hash``.
        _require_token_hash(self.binding_hash, "binding_hash")
        # RFC 7636: a PKCE code_verifier is 43..128 chars of the unreserved set.
        # A stricter length floor here keeps a trivially weak verifier out of the
        # store (the generator produces a 256-bit S256 verifier).
        if not 43 <= len(self.code_verifier) <= 128:
            raise ValueError("code_verifier must be 43..128 characters (RFC 7636)")
        _require_nonempty(self.redirect_uri, "redirect_uri")
        _require_tz_aware(self.created_at, "created_at")
        _require_tz_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")

    def is_live(self, now: datetime) -> bool:
        """True iff the transaction has not yet expired at ``now``."""
        _require_tz_aware(now, "now")
        return self.expires_at > now


@dataclass(frozen=True)
class IssuedSession:
    """The one-time return value carrying a freshly minted plaintext bearer
    token. ``token`` is ``repr``-suppressed so logging the object never prints
    it. It exists once, in memory, at login / refresh -- the store only ever
    holds the sha256 hex of the token.
    """

    session_id: str
    user_email: str
    expires_at: datetime
    token: str = field(repr=False, default="")

    def __post_init__(self) -> None:
        _require_nonempty(self.session_id, "session_id")
        _require_nonempty(self.user_email, "user_email")
        _require_nonempty(self.token, "token")
        _require_tz_aware(self.expires_at, "expires_at")
