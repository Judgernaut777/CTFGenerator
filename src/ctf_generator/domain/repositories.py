"""Persistence and infrastructure *contracts* for the domain layer.

These are interface-only :class:`typing.Protocol` definitions -- forward
contracts the domain and application layers program against without knowing how
data is stored or work is dispatched. They reference domain value types only
(no framework, I/O, or infrastructure imports), so the architecture-boundary
test keeps this module domain-pure.

Concrete implementations (SQLAlchemy repositories, an object/artifact store, a
real worker queue) land in ``ctf_generator.infrastructure`` in M6/M7; nothing
here binds to a database, filesystem, or message broker.

Method shapes here are deliberately minimal (``get`` / ``add`` / ``list`` /
by-id lookups) -- enough to express the contract, not a frozen final API.
"""

from __future__ import annotations

from typing import Protocol

from .challenges.models import (
    ChallengeSpec,
    CompetitionConfig,
    ScoreboardSnapshot,
    Submission,
)
from .competitions.events import EventStore
from .identity.models import Membership, Team, User


class CompetitionRepository(Protocol):
    """Stores and retrieves competition configurations by id.

    Deliberately minimal (add / get / list / update): competitions are created,
    fetched, and have their mutable fields updated. No delete or archive method
    is exposed -- archival, when needed, is a status transition, not a row
    removal (see docs/architecture/persistence-design.md).
    """

    def add(self, competition: CompetitionConfig) -> None:
        ...

    def get(self, competition_id: str) -> CompetitionConfig | None:
        ...

    def list(self) -> list[CompetitionConfig]:
        ...

    def update(self, competition: CompetitionConfig) -> None:
        """Update the mutable fields of an existing competition, keyed by its
        (immutable) competition_id. Raises if the competition does not exist."""
        ...


class UserRepository(Protocol):
    """Stores and retrieves users, keyed by their (case-insensitive) email.

    Mirrors the Competition contract (add / get / list / update). ``get`` is
    case-insensitive -- the store's uniqueness is over ``lower(email)`` -- and
    ``update`` mutates only the mutable business fields (``display_name``),
    keyed by the immutable ``email`` identity. No delete/archive is exposed;
    archival, when needed, is a lifecycle transition, not a row removal.
    """

    def add(self, user: User) -> None:
        ...

    def get(self, email: str) -> User | None:
        ...

    def list(self) -> list[User]:
        ...

    def update(self, user: User) -> None:
        """Update the mutable fields of an existing user, keyed by ``email``.
        Raises if the user does not exist."""
        ...


class TeamRepository(Protocol):
    """Stores competition-scoped teams, keyed by ``(competition_id, name)``.

    A team belongs to exactly one competition. ``add`` fails loudly if the
    owning competition does not exist (the store's FK), and a duplicate
    ``(competition_id, name)`` is rejected. Listing is competition-scoped --
    teams are never enumerated across competitions.
    """

    def add(self, team: Team) -> None:
        ...

    def get(self, competition_id: str, name: str) -> Team | None:
        ...

    def list_for_competition(self, competition_id: str) -> list[Team]:
        ...


class MembershipRepository(Protocol):
    """Stores memberships -- a user's role and team placement in a competition.

    Keyed by ``(user_email, competition_id)`` (at most one per pair). ``add``
    resolves the referenced user, competition and (optional) team by their
    business identities and fails loudly if any is missing or if the team
    belongs to a different competition (the store enforces the latter with a
    composite FK). ``update`` changes only the mutable ``role`` / ``team``
    placement, keyed by the immutable ``(user_email, competition_id)``.
    """

    def add(self, membership: Membership) -> None:
        ...

    def get(self, user_email: str, competition_id: str) -> Membership | None:
        ...

    def list_for_competition(self, competition_id: str) -> list[Membership]:
        ...

    def update(self, membership: Membership) -> None:
        """Update the mutable fields (role, team placement) of an existing
        membership, keyed by ``(user_email, competition_id)``. Raises if it does
        not exist."""
        ...


class ChallengeRepository(Protocol):
    """Stores challenge definitions and their immutable versions.

    A *definition* is the logical challenge identity; each generated build is a
    *version* (a :class:`ChallengeSpec` stamped with its own seed/metadata),
    letting a competition pin an exact version while the definition evolves.
    """

    def add(self, challenge: ChallengeSpec) -> None:
        ...

    def get(self, challenge_id: str) -> ChallengeSpec | None:
        ...

    def list(self) -> list[ChallengeSpec]:
        ...

    def add_version(self, challenge_id: str, version: ChallengeSpec) -> None:
        ...

    def get_version(self, challenge_id: str, version_id: str) -> ChallengeSpec | None:
        ...

    def list_versions(self, challenge_id: str) -> list[ChallengeSpec]:
        ...


class SubmissionRepository(Protocol):
    """Stores flag submissions and supports lookup by id and by team."""

    def add(self, submission: Submission) -> None:
        ...

    def get(self, submission_id: str) -> Submission | None:
        ...

    def list_for_team(self, team_id: str) -> list[Submission]:
        ...


class ScoreEventStore(EventStore, Protocol):
    """Append-only store of competition scoring events.

    Extends the pure :class:`~ctf_generator.domain.competitions.events.EventStore`
    contract; a persistent implementation lives in infrastructure in M6.
    """

    def snapshot(self) -> ScoreboardSnapshot | None:
        ...


class ArtifactStore(Protocol):
    """Stores and retrieves opaque build artifacts (bytes) by key.

    Forward contract for M6/M7; concrete object-store/filesystem backends land
    in infrastructure.
    """

    def put(self, key: str, data: bytes) -> None:
        ...

    def get(self, key: str) -> bytes | None:
        ...

    def exists(self, key: str) -> bool:
        ...

    def list(self, prefix: str = "") -> list[str]:
        ...


class WorkerQueue(Protocol):
    """Dispatches and drains background work items.

    Forward contract for M6/M7; concrete broker/in-process backends land in
    infrastructure.
    """

    def enqueue(self, task_type: str, payload: dict) -> str:
        ...

    def dequeue(self) -> dict | None:
        ...

    def ack(self, task_id: str) -> None:
        ...
