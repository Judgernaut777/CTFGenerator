"""Concrete SQLAlchemy repositories for the authentication aggregates (M10a).

Three repositories over the ``auth_credentials`` / ``sessions`` /
``user_system_roles`` tables:

* ``SqlAlchemyAuthCredentialRepository`` -- one local password credential per
  user (``UNIQUE (user_id)``). MUTABLE in place (a password change rotates
  ``password_hash``); the store never holds a plaintext password.
* ``SqlAlchemyAuthSessionRepository`` -- server-side sessions, looked up by the
  sha256 hex of the presented token. Near-append-only: the only mutation is the
  ``revoked_at`` stamp (the ``auth_sessions_freeze`` trigger is the DB backstop);
  rotation inserts a new row and revokes the old.
* ``SqlAlchemySystemRoleRepository`` -- deployment-global (admin / support) role
  grants; revocable (a plain delete).

Each takes the caller's Session; FLUSH only, never commit/rollback. Domain
objects only ever cross the boundary; ORM rows never escape. Business keys
(email) resolve to surrogate uuids via :mod:`._resolve` and fail loud on a
dangling reference.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ctf_generator.domain.auth.models import (
    AuthCredential,
    AuthSession,
    SystemRoleAssignment,
)

from . import _resolve
from .mappers import (
    _as_uuid,
    auth_credential_from_orm,
    auth_credential_to_orm,
    auth_session_from_orm,
    auth_session_to_orm,
    to_utc,
)
from .models import AuthCredential as AuthCredentialRow
from .models import AuthSession as AuthSessionRow
from .models import UserSystemRole as UserSystemRoleRow


class SqlAlchemyAuthCredentialRepository:
    """One local password credential per user, keyed by ``user_email``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _row_for_user(self, user_uuid) -> AuthCredentialRow | None:
        return self._session.scalars(
            select(AuthCredentialRow).where(AuthCredentialRow.user_id == user_uuid)
        ).one_or_none()

    def add(self, credential: AuthCredential) -> None:
        """Insert the user's credential. Missing user -> LookupError; a second
        credential for the same user -> IntegrityError (the ``UNIQUE``)."""
        user_uuid = _resolve.user_uuid(self._session, credential.user_email)
        self._session.add(auth_credential_to_orm(credential, user_uuid))
        self._session.flush()

    def get(self, user_email: str) -> AuthCredential | None:
        try:
            user_uuid = _resolve.user_uuid(self._session, user_email)
        except LookupError:
            return None  # unknown user is a clean miss, not an error
        row = self._row_for_user(user_uuid)
        if row is None:
            return None
        # Return the CANONICAL stored email (not the caller's argument casing) so
        # the aggregate's identity is stable regardless of how it was looked up.
        canonical = _resolve.user_email(self._session, user_uuid)
        return auth_credential_from_orm(row, canonical)

    def update(self, credential: AuthCredential) -> None:
        """Rotate ``password_hash`` + ``updated_at`` in place, keyed by
        ``user_email``. LookupError if no credential exists."""
        user_uuid = _resolve.user_uuid(self._session, credential.user_email)
        row = self._row_for_user(user_uuid)
        if row is None:
            raise LookupError(
                f"credential not found for user: {credential.user_email!r}"
            )
        auth_credential_to_orm(credential, user_uuid, existing=row)
        self._session.flush()


class SqlAlchemyAuthSessionRepository:
    """Server-side sessions; near-append-only (revocation stamp is the single
    legal mutation, trigger-backstopped)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, session: AuthSession) -> None:
        """Insert a session. Missing user -> LookupError; duplicate token_hash
        -> IntegrityError."""
        user_uuid = _resolve.user_uuid(self._session, session.user_email)
        self._session.add(auth_session_to_orm(session, user_uuid))
        self._session.flush()

    def _map(self, row: AuthSessionRow) -> AuthSession:
        user_email = _resolve.user_email(self._session, row.user_id)
        return auth_session_from_orm(row, user_email)

    def get(self, session_id: str) -> AuthSession | None:
        try:
            key = _as_uuid(session_id)
        except (ValueError, AttributeError, TypeError):
            return None
        row = self._session.scalars(
            select(AuthSessionRow).where(AuthSessionRow.id == key)
        ).one_or_none()
        return self._map(row) if row is not None else None

    def get_by_token_hash(self, token_hash: str) -> AuthSession | None:
        row = self._session.scalars(
            select(AuthSessionRow).where(AuthSessionRow.token_hash == token_hash)
        ).one_or_none()
        return self._map(row) if row is not None else None

    def revoke(self, session_id: str, revoked_at: datetime) -> None:
        """Stamp ``revoked_at`` (idempotent on an already-revoked session).
        LookupError if the session is missing."""
        try:
            key = _as_uuid(session_id)
        except (ValueError, AttributeError, TypeError):
            raise LookupError(f"session not found: {session_id!r}") from None
        row = self._session.scalars(
            select(AuthSessionRow).where(AuthSessionRow.id == key).with_for_update()
        ).one_or_none()
        if row is None:
            raise LookupError(f"session not found: {session_id!r}")
        if row.revoked_at is None:
            row.revoked_at = to_utc(revoked_at)
            self._session.flush()


class SqlAlchemySystemRoleRepository:
    """Deployment-global (admin / support) system-role grants."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def grant(self, assignment: SystemRoleAssignment) -> None:
        """Grant a system role (idempotent). Missing user -> LookupError."""
        user_uuid = _resolve.user_uuid(self._session, assignment.user_email)
        existing = self._session.get(UserSystemRoleRow, (user_uuid, assignment.role))
        if existing is not None:
            return  # idempotent re-grant
        self._session.add(
            UserSystemRoleRow(user_id=user_uuid, role=assignment.role)
        )
        self._session.flush()

    def revoke(self, user_email: str, role: str) -> bool:
        """Revoke a system role. Returns whether a grant was removed."""
        try:
            user_uuid = _resolve.user_uuid(self._session, user_email)
        except LookupError:
            return False
        result = self._session.execute(
            delete(UserSystemRoleRow).where(
                UserSystemRoleRow.user_id == user_uuid,
                UserSystemRoleRow.role == role,
            )
        )
        self._session.flush()
        return result.rowcount > 0

    def list_for_user(self, user_email: str) -> frozenset[str]:
        """The set of system roles the user holds (empty if none / unknown)."""
        try:
            user_uuid = _resolve.user_uuid(self._session, user_email)
        except LookupError:
            return frozenset()
        rows = self._session.scalars(
            select(UserSystemRoleRow.role).where(
                UserSystemRoleRow.user_id == user_uuid
            )
        ).all()
        return frozenset(rows)
