"""The authentication application service (M10 slice a).

``AuthService`` owns the unit-of-work over the auth persistence repositories and
implements local-password login + server-side sessions:

* ``set_password``      -- upsert a user's local password credential (the KDF
  runs here; only the encoded hash is ever stored).
* ``authenticate``      -- verify ``(email, password)`` and, on success, issue a
  fresh session; a wrong password OR an unknown email fails identically as a
  single :class:`InvalidCredentialsError` **after running the KDF** (the
  unknown-email path burns a comparison against a dummy hash so response timing
  never reveals whether an email exists -- a real past bug in the prototype
  dashboard).
* ``refresh``           -- rotate a live session (issue new, revoke old, link
  ``rotated_from``). Rotation happens ONLY here -- never on an ordinary request
  (the prototype rotated per-GET and self-DoS'd its own page polls).
* ``logout``            -- revoke a live session.
* ``resolve``           -- resolve a live bearer token to a
  :class:`ResolvedPrincipal` (subject + system roles + competition memberships);
  the interface layer maps it onto the API ``Principal``.
* ``bootstrap_admin`` / ``grant_system_role`` / ``revoke_system_role`` --
  deployment-global role management + the idempotent first-admin seed.

Secrets discipline (REQ-INV-011 / ADR-007): the raw session token is generated
here (``secrets.token_urlsafe`` -- 256 bits), returned ONCE inside the
``repr``-suppressed :class:`~ctf_generator.domain.auth.models.IssuedSession`, and
only its sha256 hex is persisted. This module logs nothing -- no password, no
token, no hash.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from ctf_generator.domain.auth.models import (
    AuthCredential,
    AuthSession,
    IssuedSession,
    SystemRoleAssignment,
)
from ctf_generator.domain.identity.models import User
from ctf_generator.infrastructure.database.auth_repository import (
    SqlAlchemyAuthCredentialRepository,
    SqlAlchemyAuthSessionRepository,
    SqlAlchemySystemRoleRepository,
)
from ctf_generator.infrastructure.database.membership_repository import (
    SqlAlchemyMembershipRepository,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.user_repository import (
    SqlAlchemyUserRepository,
)

from .hashing import PasswordHasher, default_password_hasher

# Default session lifetime. Short by design; a client refreshes explicitly via
# ``/auth/refresh`` (rotation) rather than the session sliding on every request.
DEFAULT_SESSION_TTL = timedelta(hours=12)

# Minimum acceptable password length. Full policy (composition, breach lists) is
# out of scope for slice a; this is the floor the register/bootstrap paths
# enforce so a trivially weak secret cannot be seeded.
MIN_PASSWORD_LENGTH = 8


class InvalidCredentialsError(Exception):
    """A login / session resolution failed. Deliberately undifferentiated -- the
    caller never learns whether the email exists, the password was wrong, or the
    session was expired / revoked. The interface layer maps this to 401."""


def validate_password_strength(password: str) -> None:
    """Reject an empty / too-short password (raises :class:`ValueError`)."""
    if not isinstance(password, str) or password == "":
        raise ValueError("password must be a non-empty string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )


@dataclass(frozen=True)
class ResolvedPrincipal:
    """The identity + authorization context resolved from a live session, in
    layer-neutral terms (the interface layer maps it onto the API ``Principal``
    via the existing ``ROLE_PERMISSIONS``). ``memberships`` is one tuple per
    competition role the user holds: ``(competition_id, role, team_name)``."""

    subject: str
    system_roles: frozenset[str]
    memberships: tuple[tuple[str, str, str | None], ...]


def _hash_token(token: str) -> str:
    """The sha256 hex of the opaque bearer token -- the only form ever stored /
    looked up. Never logs the token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthService:
    """Local-password authentication + server-side sessions (UoW-owning)."""

    def __init__(
        self,
        database: Database,
        *,
        hasher: PasswordHasher | None = None,
        session_ttl: timedelta = DEFAULT_SESSION_TTL,
    ) -> None:
        if session_ttl <= timedelta(0):
            raise ValueError("session_ttl must be positive")
        self._database = database
        self._hasher = hasher or default_password_hasher()
        self._session_ttl = session_ttl
        # Computed once (lazily) so the unknown-email login path can burn a KDF
        # against a real encoded hash with this hasher's parameters -- keeping
        # the timing indistinguishable from a wrong-password login.
        self._dummy_hash: str | None = None

    # -- password management -------------------------------------------------

    def set_password(self, email: str, password: str, now: datetime) -> None:
        """Create or rotate the user's local password credential (idempotent
        upsert). Fails loud (:class:`LookupError`) if the user does not exist."""
        validate_password_strength(password)
        encoded = self._hasher.hash(password)
        with self._database.session_scope() as session:
            repo = SqlAlchemyAuthCredentialRepository(session)
            existing = repo.get(email)
            if existing is None:
                repo.add(
                    AuthCredential(
                        user_email=email,
                        password_hash=encoded,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                repo.update(
                    AuthCredential(
                        user_email=existing.user_email,
                        password_hash=encoded,
                        created_at=existing.created_at,
                        updated_at=now,
                    )
                )

    # -- login / sessions ----------------------------------------------------

    def authenticate(
        self, email: str, password: str, now: datetime
    ) -> IssuedSession:
        """Verify ``(email, password)`` and issue a fresh session. A wrong
        password OR an unknown email raises a single
        :class:`InvalidCredentialsError` -- and the unknown-email path still runs
        the KDF (against a dummy hash) so response timing does not reveal whether
        the email exists."""
        with self._database.session_scope() as session:
            credential = SqlAlchemyAuthCredentialRepository(session).get(email)
            if credential is None:
                # Burn the KDF so a missing email is not distinguishable by
                # timing from a present email with a wrong password.
                self._hasher.verify(password, self._dummy())
                raise InvalidCredentialsError("invalid email or password")
            if not self._hasher.verify(password, credential.password_hash):
                raise InvalidCredentialsError("invalid email or password")
            # Transparent parameter upgrade: if the stored hash used weaker
            # parameters (or an older algorithm), re-hash under the current ones
            # now that we hold the plaintext.
            if self._hasher.needs_rehash(credential.password_hash):
                SqlAlchemyAuthCredentialRepository(session).update(
                    AuthCredential(
                        user_email=credential.user_email,
                        password_hash=self._hasher.hash(password),
                        created_at=credential.created_at,
                        updated_at=now,
                    )
                )
            return self._issue_session(session, credential.user_email, now)

    def refresh(self, token: str | None, now: datetime) -> IssuedSession:
        """Rotate a live session: issue a new token, revoke the presented one,
        and link the new session's ``rotated_from`` to the old. A missing /
        invalid / expired / revoked token raises
        :class:`InvalidCredentialsError`."""
        token_hash = self._require_token_hash(token)
        with self._database.session_scope() as session:
            repo = SqlAlchemyAuthSessionRepository(session)
            old = repo.get_by_token_hash(token_hash)
            if old is None or not old.is_live(now):
                raise InvalidCredentialsError("invalid or expired session")
            issued = self._issue_session(
                session, old.user_email, now, rotated_from=old.session_id
            )
            repo.revoke(old.session_id, now)
            return issued

    def logout(self, token: str | None, now: datetime) -> None:
        """Revoke the presented session. A missing / invalid / expired / revoked
        token raises :class:`InvalidCredentialsError`."""
        token_hash = self._require_token_hash(token)
        with self._database.session_scope() as session:
            repo = SqlAlchemyAuthSessionRepository(session)
            current = repo.get_by_token_hash(token_hash)
            if current is None or not current.is_live(now):
                raise InvalidCredentialsError("invalid or expired session")
            repo.revoke(current.session_id, now)

    def resolve(self, token: str | None, now: datetime) -> ResolvedPrincipal:
        """Resolve a live bearer token to the caller's identity + roles. Raises
        :class:`InvalidCredentialsError` for a missing / invalid / expired /
        revoked token (never leaking which)."""
        token_hash = self._require_token_hash(token)
        with self._database.session_scope() as session:
            current = SqlAlchemyAuthSessionRepository(session).get_by_token_hash(
                token_hash
            )
            if current is None or not current.is_live(now):
                raise InvalidCredentialsError("invalid or expired session")
            subject = current.user_email
            system_roles = SqlAlchemySystemRoleRepository(session).list_for_user(
                subject
            )
            memberships = SqlAlchemyMembershipRepository(session).list_for_user(
                subject
            )
        return ResolvedPrincipal(
            subject=subject,
            system_roles=frozenset(system_roles),
            memberships=tuple(
                (m.competition_id, m.role, m.team_name) for m in memberships
            ),
        )

    # -- system-role management ---------------------------------------------

    def grant_system_role(self, email: str, role: str) -> None:
        """Grant a deployment-global role (admin / support). Idempotent; a
        missing user fails loud (:class:`LookupError`); an invalid role raises
        :class:`ValueError` (domain invariant)."""
        with self._database.session_scope() as session:
            SqlAlchemySystemRoleRepository(session).grant(
                SystemRoleAssignment(user_email=email, role=role)
            )

    def revoke_system_role(self, email: str, role: str) -> bool:
        """Revoke a deployment-global role. Returns whether a grant was
        removed."""
        with self._database.session_scope() as session:
            return SqlAlchemySystemRoleRepository(session).revoke(email, role)

    def bootstrap_admin(
        self, email: str, display_name: str, password: str, now: datetime
    ) -> bool:
        """Idempotently seed the first admin. In ONE transaction: ensure the
        user exists, set a password credential IF none exists (never clobber an
        existing one), and grant the ``admin`` system role. Returns ``True`` iff
        a NEW credential was created (so a re-run is a safe no-op that does not
        reset a password). Never a hardcoded default password -- ``password`` is
        caller-supplied and strength-checked."""
        with self._database.session_scope() as session:
            users = SqlAlchemyUserRepository(session)
            if users.get(email) is None:
                users.add(User(email=email, display_name=display_name))
            credentials = SqlAlchemyAuthCredentialRepository(session)
            created = credentials.get(email) is None
            if created:
                validate_password_strength(password)
                credentials.add(
                    AuthCredential(
                        user_email=email,
                        password_hash=self._hasher.hash(password),
                        created_at=now,
                        updated_at=now,
                    )
                )
            SqlAlchemySystemRoleRepository(session).grant(
                SystemRoleAssignment(user_email=email, role="admin")
            )
            return created

    # -- internals -----------------------------------------------------------

    def _issue_session(
        self,
        session,
        email: str,
        now: datetime,
        *,
        rotated_from: str | None = None,
    ) -> IssuedSession:
        raw_token = secrets.token_urlsafe(32)  # 256 bits of entropy
        domain_session = AuthSession(
            session_id=str(uuid.uuid4()),
            user_email=email,
            token_hash=_hash_token(raw_token),
            issued_at=now,
            expires_at=now + self._session_ttl,
            rotated_from=rotated_from,
        )
        SqlAlchemyAuthSessionRepository(session).add(domain_session)
        return IssuedSession(
            session_id=domain_session.session_id,
            user_email=email,
            expires_at=domain_session.expires_at,
            token=raw_token,
        )

    def _require_token_hash(self, token: str | None) -> str:
        if not token:
            raise InvalidCredentialsError("missing session token")
        return _hash_token(token)

    def _dummy(self) -> str:
        if self._dummy_hash is None:
            self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(16))
        return self._dummy_hash
