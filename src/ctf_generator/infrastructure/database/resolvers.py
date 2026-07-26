"""Public resolver seam: business identifiers -> surrogate uuids.

Application code programs against THIS (mirroring the ``locks`` public seam)
instead of reaching into the private ``_resolve`` module, so a service can
resolve a scope's uuids ONCE and thread them into the append-only writes rather
than each repository re-resolving the same rows.

``resolve_submission_scope`` collapses the ``(competition, team, version)``
look-ups the submission path would otherwise perform 3x each (once inside
``submissions.add``, ``solves.add``, and ``ScoreLedger.append``). Infrastructure
only; ORM rows never escape.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from . import _resolve


def resolve_submission_scope(
    session: Session,
    competition_slug: str,
    team_name: str,
    definition_slug: str,
    version_no: int,
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Return ``(competition_uuid, team_uuid, version_uuid)`` for a submission's
    scope in one place. Raises :class:`LookupError` if any is unknown -- exactly
    the same failure the per-repository resolves it replaces would raise."""
    competition_uuid = _resolve.competition_uuid(session, competition_slug)
    team_uuid = _resolve.team_uuid(session, competition_uuid, team_name)
    version_uuid = _resolve.version_uuid(session, definition_slug, version_no)
    return competition_uuid, team_uuid, version_uuid
