"""Bidirectional mapping between domain aggregates and ORM rows.

Infrastructure-only. The domain never sees ORM objects; repositories call these
functions at the boundary. Mappers are pure (no session/IO) so they are trivial
to reason about and test.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ctf_generator.domain.challenges.models import CompetitionConfig
from ctf_generator.domain.identity.models import Membership, Team, User

from .models import Competition
from .models import Membership as MembershipRow
from .models import Team as TeamRow
from .models import User as UserRow


def _to_utc(value: datetime | None) -> datetime | None:
    """Coerce a datetime to an unambiguous UTC instant for persistence.

    A tz-aware value keeps its instant (converted to UTC). A naive value is
    assumed to already be UTC and is stamped with ``timezone.utc`` -- so the
    round-trip preserves the *instant* (as UTC), never the original named
    offset. ``None`` passes through.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def competition_to_orm(
    config: CompetitionConfig, existing: Competition | None = None
) -> Competition:
    """Map a domain ``CompetitionConfig`` onto an ORM ``Competition``.

    With ``existing is None`` a fresh row is built (new surrogate uuid via the
    column default, ``slug`` from ``competition_id``, ``status`` defaulting to
    'draft'). With ``existing`` given, only the mutable business fields are
    updated -- ``id``, ``slug``, ``created_at`` and ``status`` are left
    untouched, which is what the repository's ``update()`` relies on.

    ``default_scoring`` is not stored by this table; rather than silently drop
    it, a non-None value raises ``NotImplementedError`` until it lands with the
    ``competition_challenges`` normalization.
    """
    if config.default_scoring is not None:
        raise NotImplementedError(
            "default_scoring persistence lands with competition_challenges"
        )

    if existing is None:
        return Competition(
            slug=config.competition_id,
            name=config.name,
            start_time=_to_utc(config.start_time),
            end_time=_to_utc(config.end_time),
            scoring_start_at=_to_utc(config.scoring_start_time),
            freeze_time=_to_utc(config.freeze_time),
        )

    existing.name = config.name
    existing.start_time = _to_utc(config.start_time)
    existing.end_time = _to_utc(config.end_time)
    existing.scoring_start_at = _to_utc(config.scoring_start_time)
    existing.freeze_time = _to_utc(config.freeze_time)
    return existing


def competition_from_orm(row: Competition) -> CompetitionConfig:
    """Map an ORM ``Competition`` row back to a domain ``CompetitionConfig``.

    ``slug`` becomes ``competition_id``; ``scoring_start_at`` becomes
    ``scoring_start_time``. ORM-managed columns (``id``, ``status``,
    ``archived_at``, ``created_at``) have no domain counterpart and are dropped.
    ``default_scoring`` is always ``None`` -- it is not stored on this table.
    """
    return CompetitionConfig(
        competition_id=row.slug,
        name=row.name,
        start_time=row.start_time,
        end_time=row.end_time,
        scoring_start_time=row.scoring_start_at,
        freeze_time=row.freeze_time,
        default_scoring=None,
    )


# --- Identity aggregates -------------------------------------------------
#
# Users map purely. Teams and memberships reference other aggregates by
# surrogate uuid, which the domain never sees -- so their ``*_to_orm`` takes the
# already-resolved parent uuids (the repository looks them up by business key
# and fails loudly if absent) and their ``*_from_orm`` takes the parent business
# keys the repository read alongside the row. Mappers stay pure (no session/IO).


def user_to_orm(user: User, existing: UserRow | None = None) -> UserRow:
    """Map a domain ``User`` onto an ORM ``User`` row.

    Fresh row when ``existing is None`` (new surrogate uuid via the column
    default). With ``existing`` given, only the mutable ``display_name`` is
    updated -- ``id``, ``email`` and ``created_at`` are left untouched, which is
    what the repository's ``update()`` (keyed on the immutable email) relies on.
    """
    if existing is None:
        return UserRow(email=user.email, display_name=user.display_name)
    existing.display_name = user.display_name
    return existing


def user_from_orm(row: UserRow) -> User:
    """Map an ORM ``User`` row back to a domain ``User``. ORM-managed columns
    (``id``, ``archived_at``, ``created_at``) have no domain counterpart."""
    return User(email=row.email, display_name=row.display_name)


def team_to_orm(
    team: Team, competition_uuid: uuid.UUID, existing: TeamRow | None = None
) -> TeamRow:
    """Map a domain ``Team`` onto an ORM ``Team`` row.

    ``competition_uuid`` is the surrogate id of the owning competition, resolved
    by the repository from ``team.competition_id`` (the business slug). Teams are
    immutable in M6 (identity is ``(competition_id, name)`` and there are no
    other business fields), so ``existing`` is accepted only for symmetry and
    the mapper never mutates a passed row's identity.
    """
    if existing is not None:
        # Nothing mutable to update -- name/competition are the identity.
        return existing
    return TeamRow(competition_id=competition_uuid, name=team.name)


def team_from_orm(row: TeamRow, competition_slug: str) -> Team:
    """Map an ORM ``Team`` row back to a domain ``Team``.

    ``competition_slug`` is the owning competition's business id, read by the
    repository (the row itself only carries the surrogate ``competition_id``).
    """
    return Team(competition_id=competition_slug, name=row.name)


def membership_to_orm(
    membership: Membership,
    user_uuid: uuid.UUID,
    competition_uuid: uuid.UUID,
    team_uuid: uuid.UUID | None,
    existing: MembershipRow | None = None,
) -> MembershipRow:
    """Map a domain ``Membership`` onto an ORM ``Membership`` row.

    The three surrogate uuids are resolved by the repository from the
    membership's business identities (user email, competition slug, optional
    team name). ``team_uuid`` is ``None`` iff ``membership.team_name`` is ``None``
    -- the repository guarantees this pairing. With ``existing`` given, only the
    mutable ``role`` and ``team_id`` are updated (identity ``user_id`` /
    ``competition_id`` untouched), which ``update()`` relies on.
    """
    if existing is None:
        return MembershipRow(
            user_id=user_uuid,
            competition_id=competition_uuid,
            team_id=team_uuid,
            role=membership.role,
        )
    existing.role = membership.role
    existing.team_id = team_uuid
    return existing


def membership_from_orm(
    row: MembershipRow, user_email: str, competition_slug: str, team_name: str | None
) -> Membership:
    """Map an ORM ``Membership`` row back to a domain ``Membership``.

    The parent business identities (``user_email``, ``competition_slug``,
    optional ``team_name``) are read by the repository alongside the row; the
    row itself carries only surrogate uuids. ``team_name`` is ``None`` iff
    ``row.team_id`` is ``None`` -- asserted defensively below so a broken join
    contract fails loud here rather than yielding a silently wrong aggregate.
    """
    if (row.team_id is None) != (team_name is None):
        raise ValueError(
            "team_id/team_name inconsistency: resolved team name "
            f"{team_name!r} does not match row.team_id {row.team_id!r}"
        )
    return Membership(
        user_email=user_email,
        competition_id=competition_slug,
        role=row.role,
        team_name=team_name,
    )
