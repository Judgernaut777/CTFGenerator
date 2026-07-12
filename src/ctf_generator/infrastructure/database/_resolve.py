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

from .models import (
    ChallengeDefinition,
    ChallengeVersion,
    Competition,
    Team,
    User,
    Worker,
)


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


def competition_uuid_optional(
    session: Session, competition_id: str | None
) -> uuid.UUID | None:
    """Resolve an optional competition slug (jobs audit linkage). ``None``
    passes through; a given-but-unknown slug fails loud."""
    if competition_id is None:
        return None
    return competition_uuid(session, competition_id)


def version_uuid_optional(
    session: Session, definition_slug: str | None, version_no: int | None
) -> uuid.UUID | None:
    """Resolve an optional challenge-version pair (jobs audit linkage). Both
    halves ``None`` passes through; a given-but-unknown pair fails loud."""
    if definition_slug is None and version_no is None:
        return None
    if definition_slug is None or version_no is None:
        raise LookupError(
            "definition_slug and version_no must be given together, got "
            f"({definition_slug!r}, {version_no!r})"
        )
    return version_uuid(session, definition_slug, version_no)


def worker_uuid(session: Session, worker_name: str) -> uuid.UUID:
    result = session.scalars(
        select(Worker.id).where(Worker.name == worker_name)
    ).one_or_none()
    if result is None:
        raise LookupError(f"worker not found: {worker_name!r}")
    return result


def worker_uuid_optional(
    session: Session, worker_name: str | None
) -> uuid.UUID | None:
    """Resolve an optional worker name to its uuid. ``None`` passes through; a
    given-but-unknown name fails loud."""
    if worker_name is None:
        return None
    return worker_uuid(session, worker_name)


# --- Reverse resolvers (surrogate uuid -> business key) ---------------------
#
# The instance-lifecycle repository reads a row's parent business keys back for
# ``*_from_orm`` the way the job queue's ``_audit_refs`` does. Each fails loud on
# a dangling surrogate (a corruption signal), never returns a silent ``None``.


def competition_slug(session: Session, competition_uuid_: uuid.UUID) -> str:
    result = session.scalars(
        select(Competition.slug).where(Competition.id == competition_uuid_)
    ).one_or_none()
    if result is None:
        raise LookupError(f"competition id not found: {competition_uuid_!r}")
    return result


def team_name(session: Session, team_uuid_: uuid.UUID) -> str:
    result = session.scalars(
        select(Team.name).where(Team.id == team_uuid_)
    ).one_or_none()
    if result is None:
        raise LookupError(f"team id not found: {team_uuid_!r}")
    return result


def version_business(
    session: Session, version_uuid_: uuid.UUID
) -> tuple[str, int]:
    row = session.execute(
        select(ChallengeDefinition.slug, ChallengeVersion.version_no)
        .join(ChallengeVersion, ChallengeVersion.definition_id == ChallengeDefinition.id)
        .where(ChallengeVersion.id == version_uuid_)
    ).one_or_none()
    if row is None:
        raise LookupError(f"challenge version id not found: {version_uuid_!r}")
    return row[0], row[1]


def worker_name(session: Session, worker_uuid_: uuid.UUID) -> str:
    result = session.scalars(
        select(Worker.name).where(Worker.id == worker_uuid_)
    ).one_or_none()
    if result is None:
        raise LookupError(f"worker id not found: {worker_uuid_!r}")
    return result


def worker_name_optional(
    session: Session, worker_uuid_: uuid.UUID | None
) -> str | None:
    if worker_uuid_ is None:
        return None
    return worker_name(session, worker_uuid_)
