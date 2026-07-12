"""Concrete SQLAlchemy repository for the Membership aggregate.

Implements the domain
:class:`ctf_generator.domain.repositories.MembershipRepository` over the
``memberships`` table. A membership references a user, a competition, and
(optionally) a team by *business* identity; this repository resolves each to its
surrogate uuid and fails loudly (:class:`LookupError`) if any referent is
missing -- the domain never sees a surrogate key. On read it reconstructs those
business identities by joining the parent tables, so ORM objects never escape.

Operates within the caller's session (flush, never commit/rollback). The
store's ``UNIQUE (user_id, competition_id)`` and the composite FK
``(team_id, competition_id) -> teams(id, competition_id)`` are the last line of
defence for "one membership per user per competition" and "team belongs to the
same competition"; this code resolves keys and lets those constraints reject
violations at flush time.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ctf_generator.domain.identity.models import Membership

from .mappers import membership_from_orm, membership_to_orm
from .models import Competition
from .models import Membership as MembershipRow
from .models import Team as TeamRow
from .models import User as UserRow


class SqlAlchemyMembershipRepository:
    """Persist and retrieve memberships, keyed by ``(user_email, competition_id)``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # --- business-key -> surrogate-uuid resolution (fail loud) ----------

    def _user_uuid(self, email: str) -> uuid.UUID:
        result = self._session.scalars(
            select(UserRow.id).where(func.lower(UserRow.email) == email.lower())
        ).one_or_none()
        if result is None:
            raise LookupError(f"user not found: {email!r}")
        return result

    def _competition_uuid(self, competition_id: str) -> uuid.UUID:
        result = self._session.scalars(
            select(Competition.id).where(Competition.slug == competition_id)
        ).one_or_none()
        if result is None:
            raise LookupError(f"competition not found: {competition_id!r}")
        return result

    def _team_uuid(
        self, competition_uuid: uuid.UUID, team_name: str
    ) -> uuid.UUID:
        """Resolve a team by ``(competition, name)``. Scoping the lookup to the
        competition means a team from another competition simply isn't found --
        so a cross-competition placement fails here with a clear error rather
        than only at the composite FK."""
        result = self._session.scalars(
            select(TeamRow.id).where(
                TeamRow.competition_id == competition_uuid,
                TeamRow.name == team_name,
            )
        ).one_or_none()
        if result is None:
            raise LookupError(f"team not found in competition: {team_name!r}")
        return result

    # --- commands / queries ---------------------------------------------

    def add(self, membership: Membership) -> None:
        """Insert a new membership. Resolves the user, competition and optional
        team; raises :class:`LookupError` if any is missing. A second membership
        for the same ``(user, competition)`` raises
        :class:`~sqlalchemy.exc.IntegrityError` at flush time."""
        user_uuid = self._user_uuid(membership.user_email)
        competition_uuid = self._competition_uuid(membership.competition_id)
        team_uuid = (
            self._team_uuid(competition_uuid, membership.team_name)
            if membership.team_name is not None
            else None
        )
        row = membership_to_orm(membership, user_uuid, competition_uuid, team_uuid)
        self._session.add(row)
        self._session.flush()

    def get(self, user_email: str, competition_id: str) -> Membership | None:
        """Fetch one membership by ``(user_email, competition_id)``, or ``None``.
        Returns ``None`` (not an error) if the user or competition is unknown."""
        row = (
            self._session.execute(
                # Select the CANONICAL stored email (not the caller's argument) so
                # the returned aggregate's identity matches what list_for_competition
                # returns for the same row -- otherwise `get("A@X.io")` and the list
                # path would yield non-equal frozen dataclasses for one membership.
                select(MembershipRow, UserRow.email, TeamRow.name)
                .join(UserRow, MembershipRow.user_id == UserRow.id)
                .join(Competition, MembershipRow.competition_id == Competition.id)
                .outerjoin(TeamRow, MembershipRow.team_id == TeamRow.id)
                .where(
                    func.lower(UserRow.email) == user_email.lower(),
                    Competition.slug == competition_id,
                )
            )
            .one_or_none()
        )
        if row is None:
            return None
        membership_row, canonical_email, team_name = row
        return membership_from_orm(
            membership_row, canonical_email, competition_id, team_name
        )

    def list_for_competition(self, competition_id: str) -> list[Membership]:
        """Return every membership in the given competition as domain objects
        (empty if the competition is unknown or has none)."""
        rows = self._session.execute(
            select(MembershipRow, UserRow.email, TeamRow.name)
            .join(UserRow, MembershipRow.user_id == UserRow.id)
            .join(Competition, MembershipRow.competition_id == Competition.id)
            .outerjoin(TeamRow, MembershipRow.team_id == TeamRow.id)
            .where(Competition.slug == competition_id)
        ).all()
        return [
            membership_from_orm(membership_row, email, competition_id, team_name)
            for membership_row, email, team_name in rows
        ]

    def update(self, membership: Membership) -> None:
        """Update the mutable fields (role, team placement) of an existing
        membership, keyed by ``(user_email, competition_id)``. Raises
        :class:`LookupError` if the membership -- or any referent -- is missing."""
        user_uuid = self._user_uuid(membership.user_email)
        competition_uuid = self._competition_uuid(membership.competition_id)
        row = self._session.scalars(
            select(MembershipRow).where(
                MembershipRow.user_id == user_uuid,
                MembershipRow.competition_id == competition_uuid,
            )
        ).one_or_none()
        if row is None:
            raise LookupError(
                f"membership not found: {membership.user_email!r} "
                f"in {membership.competition_id!r}"
            )
        team_uuid = (
            self._team_uuid(competition_uuid, membership.team_name)
            if membership.team_name is not None
            else None
        )
        membership_to_orm(
            membership, user_uuid, competition_uuid, team_uuid, existing=row
        )
        self._session.flush()
