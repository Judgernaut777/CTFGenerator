"""Public advisory-lock seam for competition-scoped serialization.

A single public entry point both the submission service and the scoreboard
projector program against, so application code never reaches into the private
``_resolve`` module or into a helper defined inside another application module.

``acquire_competition_lock`` resolves the competition's surrogate uuid
internally and takes a ``pg_advisory_xact_lock`` keyed by
``hashtextextended(uuid_text, 0)`` -- auto-released at commit/rollback. Hash
collisions across competitions only cause spurious serialization, never
incorrectness. Infrastructure-only; ORM rows never escape.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.orm import Session

from . import _resolve


def acquire_competition_lock(session: Session, competition_slug: str) -> None:
    """Take the competition-scoped transaction advisory lock. Raises
    :class:`LookupError` if the competition slug does not resolve."""
    competition_uuid = _resolve.competition_uuid(session, competition_slug)
    session.execute(
        sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": str(competition_uuid)},
    )
