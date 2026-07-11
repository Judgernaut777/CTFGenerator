"""Bidirectional mapping between domain aggregates and ORM rows.

Infrastructure-only. The domain never sees ORM objects; repositories call these
functions at the boundary. Mappers are pure (no session/IO) so they are trivial
to reason about and test.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ctf_generator.domain.challenges.models import CompetitionConfig

from .models import Competition


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
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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
