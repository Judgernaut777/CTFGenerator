"""Concrete SQLAlchemy repository for the User aggregate.

Implements the domain :class:`ctf_generator.domain.repositories.UserRepository`
over the ``users`` table. Operates within the caller's
:class:`~sqlalchemy.orm.Session` (the unit-of-work boundary): it *flushes* to
assign PKs and surface constraint errors eagerly, but never commits or rolls
back. ORM objects never escape this module -- reads map rows back to the frozen
domain :class:`~ctf_generator.domain.identity.models.User` before returning.

Lookups are case-insensitive (over ``lower(email)``), matching the store's
functional unique index, so ``get('A@x.io')`` and ``get('a@x.io')`` resolve the
same row.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ctf_generator.domain.identity.models import User

from .mappers import user_from_orm, user_to_orm
from .models import User as UserRow


class SqlAlchemyUserRepository:
    """Persist and retrieve users, keyed by their (case-insensitive) email."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _row_for_email(self, email: str) -> UserRow | None:
        return self._session.scalars(
            select(UserRow).where(func.lower(UserRow.email) == email.lower())
        ).one_or_none()

    def add(self, user: User) -> None:
        """Insert a new user. A duplicate email (case-insensitively) raises the
        underlying :class:`~sqlalchemy.exc.IntegrityError` at flush time."""
        row = user_to_orm(user)
        self._session.add(row)
        self._session.flush()

    def get(self, email: str) -> User | None:
        """Fetch one user by email (case-insensitive), or ``None``."""
        row = self._row_for_email(email)
        return user_from_orm(row) if row is not None else None

    def list(self) -> list[User]:
        """Return every user as a domain object."""
        return [user_from_orm(row) for row in self._session.scalars(select(UserRow))]

    def update(self, user: User) -> None:
        """Update the mutable fields (``display_name``) of an existing user,
        keyed by ``email``. Raises :class:`LookupError` if no such row exists."""
        row = self._row_for_email(user.email)
        if row is None:
            raise LookupError(f"user not found: {user.email!r}")
        user_to_orm(user, existing=row)
        self._session.flush()
