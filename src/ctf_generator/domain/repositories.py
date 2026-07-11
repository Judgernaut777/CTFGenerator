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


class CompetitionRepository(Protocol):
    """Stores and retrieves competition configurations by id."""

    def add(self, competition: CompetitionConfig) -> None:
        ...

    def get(self, competition_id: str) -> CompetitionConfig | None:
        ...

    def list(self) -> list[CompetitionConfig]:
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
