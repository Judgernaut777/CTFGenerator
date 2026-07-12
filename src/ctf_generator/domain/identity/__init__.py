"""Identity domain: the people and grouping value types for a competition --
``User`` (a person/login identity), ``Team`` (a competition-scoped group), and
``Membership`` (a user's role and team placement within one competition).

These are pure, frozen domain aggregates keyed by *business* identity (email for
users, ``(competition_id, name)`` for teams). Surrogate uuid keys and the
lifecycle columns (``archived_at`` / ``created_at``) live in
``ctf_generator.infrastructure`` and never leak into the domain. See ``models``
for the canonical home and the invariants each type enforces.
"""

from .models import (
    VALID_ROLES,
    Membership,
    Team,
    User,
)

__all__ = ["VALID_ROLES", "Membership", "Team", "User"]
