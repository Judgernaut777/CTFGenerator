"""Identity application service -- unit-of-work-owning facade over
:class:`~ctf_generator.infrastructure.database.user_repository.SqlAlchemyUserRepository`.

Users are keyed by their (case-insensitive) ``email``. ``register`` fails loud on
a duplicate email (the underlying :class:`~sqlalchemy.exc.IntegrityError` surfaces
for the interface layer to map to ``409 conflict``); reads return the frozen
domain :class:`~ctf_generator.domain.identity.models.User`. No credential/secret
is modelled here -- authentication storage is a separate axis owned by M10.
"""

from __future__ import annotations

from ctf_generator.domain.identity.models import Membership, User
from ctf_generator.infrastructure.database.membership_repository import (
    SqlAlchemyMembershipRepository,
)
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

    def assign_membership(
        self,
        competition_id: str,
        user_email: str,
        role: str,
        team_name: str | None = None,
    ) -> Membership:
        """Assign (or re-assign) a user's role + team placement in one competition.

        Idempotent UPSERT keyed by ``(user_email, competition_id)``: creates the
        membership if absent, else updates its mutable fields (role, team). This is
        the operator path that turns a registered user into a competition
        participant (e.g. a ``player`` on a team) -- without it a user can be
        created but never granted a competition-scoped permission. ``Membership``'s
        own construction validates the role; the repository raises
        :class:`LookupError` if the user, competition, or team is unknown."""
        membership = Membership(
            user_email=user_email,
            competition_id=competition_id,
            role=role,
            team_name=team_name,
        )
        with self._database.session_scope() as session:
            repo = SqlAlchemyMembershipRepository(session)
            if repo.get(user_email, competition_id) is None:
                repo.add(membership)
            else:
                repo.update(membership)
            stored = repo.get(user_email, competition_id)
        if stored is None:  # pragma: no cover - just upserted in the same UoW
            raise LookupError(
                f"membership lost after upsert: {user_email!r} in {competition_id!r}"
            )
        return stored

    def list_memberships_for_competition(
        self, competition_id: str
    ) -> list[Membership]:
        """Every membership in ``competition_id`` (empty if the competition is
        unknown or has none). This is the application-layer read the contestant
        web roster consumes so an interface handler never touches the membership
        repository directly. Returns the frozen domain
        :class:`~ctf_generator.domain.identity.models.Membership` aggregates
        (``user_email`` / ``role`` / ``team_name`` -- no credential/secret); the
        caller is responsible for confining the result to the caller's tenancy
        scope (own team only) before rendering."""
        with self._database.session_scope() as session:
            return SqlAlchemyMembershipRepository(session).list_for_competition(
                competition_id
            )
