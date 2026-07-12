"""Shared business-key -> surrogate-uuid resolvers for the ledger repositories.

The ledger aggregates (submissions/solves/score_events) all reference the same
parents by business identity -- competition slug, team name, challenge
``(definition_slug, version_no)``, submitter email. These helpers resolve each to
its surrogate uuid within the caller's session and fail loudly
(:class:`LookupError`) on a dangling reference, so a ledger row is never written
against a non-existent parent. Infrastructure-only; ORM rows never escape.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import ChallengeDefinition, ChallengeVersion, Competition, Team, User


def competition_uuid(session: Session, competition_id: str) -> uuid.UUID:
    result = session.scalars(
        select(Competition.id).where(Competition.slug == competition_id)
    ).one_or_none()
    if result is None:
        raise LookupError(f"competition not found: {competition_id!r}")
    return result


def team_uuid(
    session: Session, competition_uuid_: uuid.UUID, team_name: str
) -> uuid.UUID:
    result = session.scalars(
        select(Team.id).where(
            Team.competition_id == competition_uuid_, Team.name == team_name
        )
    ).one_or_none()
    if result is None:
        raise LookupError(f"team not found in competition: {team_name!r}")
    return result


def version_uuid(
    session: Session, definition_slug: str, version_no: int
) -> uuid.UUID:
    result = session.scalars(
        select(ChallengeVersion.id)
        .join(ChallengeDefinition, ChallengeVersion.definition_id == ChallengeDefinition.id)
        .where(
            ChallengeDefinition.slug == definition_slug,
            ChallengeVersion.version_no == version_no,
        )
    ).one_or_none()
    if result is None:
        raise LookupError(
            f"challenge version not found: {definition_slug!r} v{version_no}"
        )
    return result


def user_uuid_optional(session: Session, email: str | None) -> uuid.UUID | None:
    """Resolve a submitter email to a user uuid, or ``None`` if no email is
    given. A given-but-unknown email fails loud."""
    if email is None:
        return None
    result = session.scalars(
        select(User.id).where(func.lower(User.email) == email.lower())
    ).one_or_none()
    if result is None:
        raise LookupError(f"user not found: {email!r}")
    return result
