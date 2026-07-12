"""Identity value types: ``User``, ``Team``, ``Membership``.

Pure domain aggregates -- frozen dataclasses over stdlib only, no framework,
I/O, or infrastructure imports. Each is keyed by its *business* identity, not a
surrogate uuid:

* ``User`` -- identified by ``email`` (case-insensitive; the store enforces
  uniqueness on ``lower(email)``). ``display_name`` is the only other business
  field. No credential/secret is modelled here (ADR-002: secrets never live in
  loggable domain state); authN storage is a separate axis.
* ``Team`` -- identified by ``(competition_id, name)``. A team belongs to
  exactly one competition (matching the per-competition ``team_id`` the scoring
  domain already uses).
* ``Membership`` -- a single row binding a user to a competition with a
  ``role`` and an optional ``team`` placement. ``team_name is None`` means the
  user is registered but unteamed (e.g. staff). At most one membership per
  ``(user_email, competition_id)`` is a store-level invariant.

Lifecycle columns (``archived_at``, ``created_at``) and surrogate uuid keys are
owned by the ORM and deliberately absent here -- the domain speaks only in
business identity and mutable business attributes.
"""

from __future__ import annotations

from dataclasses import dataclass

# The eight competition roles. A ``Membership.role`` outside this set is a
# domain error. The exact set is owned by the Authentication ADR and may be
# migrated; the store mirrors it as a CHECK constraint so the DB and domain
# agree. Kept as a frozenset for O(1) membership tests and immutability.
VALID_ROLES = frozenset(
    {
        "player",
        "captain",
        "author",
        "organizer",
        "admin",
        "observer",
        "judge",
        "support",
    }
)


def _require_nonempty(value: str, field: str) -> None:
    """Reject empty/whitespace-only business strings (the DB mirrors this with
    ``char_length(...) > 0`` CHECKs, so failing here keeps domain and store in
    agreement rather than deferring to a flush-time IntegrityError)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")


@dataclass(frozen=True)
class User:
    """A person / login identity. Keyed by ``email`` (case-insensitive).

    ``email`` is the stable business identity; ``display_name`` is a mutable
    business attribute (updatable via the repository). Case is preserved as
    given, but the store's uniqueness is over ``lower(email)`` -- so ``get`` is
    case-insensitive and two addresses differing only in case collide.
    """

    email: str
    display_name: str

    def __post_init__(self) -> None:
        _require_nonempty(self.email, "email")
        _require_nonempty(self.display_name, "display_name")
        # A minimal structural check -- full RFC validation is out of scope and
        # belongs to the interface layer; we only guarantee it is addressable
        # enough to be a key ("local@domain" shape).
        local, sep, domain = self.email.partition("@")
        if not sep or not local.strip() or "." not in domain:
            raise ValueError(f"email is not a valid address: {self.email!r}")


@dataclass(frozen=True)
class Team:
    """A competition-scoped group. Keyed by ``(competition_id, name)``.

    ``competition_id`` is the owning competition's business id (the domain
    ``CompetitionConfig.competition_id`` / ORM ``slug``). ``name`` is unique
    within that competition.
    """

    competition_id: str
    name: str

    def __post_init__(self) -> None:
        _require_nonempty(self.competition_id, "competition_id")
        _require_nonempty(self.name, "name")


@dataclass(frozen=True)
class Membership:
    """A user's role and team placement within one competition.

    References other aggregates by *business* identity: the user by
    ``user_email``, the competition by ``competition_id``, the team (optionally)
    by ``team_name`` scoped to the same competition. ``team_name is None`` means
    registered-but-unteamed. ``role`` must be one of :data:`VALID_ROLES`.

    ``role`` and ``team_name`` are the mutable attributes (a membership can be
    re-roled or moved between teams); ``(user_email, competition_id)`` is the
    immutable identity the repository keys ``update`` on.
    """

    user_email: str
    competition_id: str
    role: str
    team_name: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.user_email, "user_email")
        _require_nonempty(self.competition_id, "competition_id")
        if self.role not in VALID_ROLES:
            raise ValueError(
                f"role must be one of {sorted(VALID_ROLES)}, got {self.role!r}"
            )
        # team_name is optional, but if present it must be a real name (a team
        # is keyed by (competition_id, name)); an empty string is not "unteamed"
        # -- that is ``None`` -- so reject it explicitly rather than silently.
        if self.team_name is not None:
            _require_nonempty(self.team_name, "team_name")
