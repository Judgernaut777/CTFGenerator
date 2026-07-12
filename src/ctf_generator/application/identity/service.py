"""Identity application service -- unit-of-work-owning facade over
:class:`~ctf_generator.infrastructure.database.user_repository.SqlAlchemyUserRepository`.

Users are keyed by their (case-insensitive) ``email``. ``register`` fails loud on
a duplicate email (the underlying :class:`~sqlalchemy.exc.IntegrityError` surfaces
for the interface layer to map to ``409 conflict``); reads return the frozen
domain :class:`~ctf_generator.domain.identity.models.User`. No credential/secret
is modelled here -- authentication storage is a separate axis owned by M10.
"""

from __future__ import annotations

from ctf_generator.domain.identity.models import User
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.user_repository import (
    SqlAlchemyUserRepository,
)


class IdentityService:
    """Register / read / list users, owning the transaction."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def register(self, user: User) -> User:
        """Persist a new user profile. A duplicate email (case-insensitively)
        surfaces the underlying :class:`~sqlalchemy.exc.IntegrityError`."""
        with self._database.session_scope() as session:
            repo = SqlAlchemyUserRepository(session)
            repo.add(user)
            stored = repo.get(user.email)
        assert stored is not None  # noqa: S101 - just inserted in this UoW
        return stored

    def get(self, email: str) -> User | None:
        with self._database.session_scope() as session:
            return SqlAlchemyUserRepository(session).get(email)

    def list_users(self) -> list[User]:
        with self._database.session_scope() as session:
            return SqlAlchemyUserRepository(session).list()
