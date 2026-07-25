"""Public advisory-lock seam for scoped serialization.

The public entry points here are what application code (the submission service,
the scoreboard projector) programs against, so it never reaches into the private
``_resolve`` module or into a helper defined inside another application module.

Both helpers take a ``pg_advisory_xact_lock`` keyed by ``hashtextextended(key, 0)``
-- auto-released at commit/rollback. A hash collision only causes spurious
serialization, never incorrectness. Infrastructure-only; ORM rows never escape.

Granularity matters for throughput. The competition-wide lock
(:func:`acquire_competition_lock`) serializes the projector's per-competition
refolds against each other. The submission path instead uses
:func:`acquire_submission_lock`, keyed at the ``(competition, team, challenge
version)`` grain, so submissions for DIFFERENT teams (or different challenges) --
and a concurrent projector refold -- never block each other. NEITHER lock is a
correctness dependency: the at-most-one-solve invariant is guaranteed by the
``uq_solves_*`` UNIQUE + the submission service's SAVEPOINT retry, and the
projector's ``as_of_seq`` UPSERT guard makes a refold idempotent. The locks are
pure throughput optimizations that keep those guards from churning under
contention -- so the submission lock can safely be far finer than the
competition-wide one it replaced on that path.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.orm import Session

from . import _resolve

# A separator that cannot appear in a uuid text / business identifier, so two
# distinct key tuples can never collide into the same composite string.
_KEY_SEP = "\x1f"


def acquire_competition_lock(session: Session, competition_slug: str) -> None:
    """Take the competition-scoped transaction advisory lock (serializes the
    projector's per-competition refolds). Raises :class:`LookupError` if the
    competition slug does not resolve."""
    competition_uuid = _resolve.competition_uuid(session, competition_slug)
    session.execute(
        sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": str(competition_uuid)},
    )


def acquire_submission_lock(
    session: Session,
    competition_slug: str,
    team_name: str,
    definition_slug: str,
    version_no: int,
) -> None:
    """Take the ``(competition, team, challenge-version)``-scoped transaction
    advisory lock the submission path uses instead of the competition-wide one.

    Two different teams -- or one team on two different challenges -- never
    serialize against each other, and neither blocks a concurrent projector
    refold; only a genuine same-team-same-challenge race serializes (and even that
    is a throughput nicety, not the correctness boundary -- see the module
    docstring). Resolves the competition uuid so an unknown competition still
    raises :class:`LookupError` here, exactly as the competition-wide lock did,
    and adds no extra round-trip beyond that one resolve. ``team_name`` /
    ``definition_slug`` / ``version_no`` are folded into the key as-is (business
    identifiers, already unique)."""
    competition_uuid = _resolve.competition_uuid(session, competition_slug)
    key = _KEY_SEP.join(
        (str(competition_uuid), team_name, definition_slug, str(version_no))
    )
    session.execute(
        sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": key},
    )
