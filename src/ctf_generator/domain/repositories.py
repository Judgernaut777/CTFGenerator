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

from datetime import datetime
from typing import Protocol

from .authoring.models import (
    ChallengeBuild,
    ChallengeDefinition,
    ChallengePublication,
    ChallengeVersion,
)
from .challenges.models import (
    ChallengeSpec,
    CompetitionConfig,
)
from .identity.models import Membership, Team, User
from .ledger.models import LedgerSubmission, ScoreEvent, Solve


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


class ChallengeDefinitionRepository(Protocol):
    """Stores challenge definitions (the stable identity across edits), keyed by
    ``slug``. ``title`` is mutable metadata; ``family``/``slug`` are identity."""

    def add(self, definition: ChallengeDefinition) -> None:
        ...

    def get(self, slug: str) -> ChallengeDefinition | None:
        ...

    def list(self) -> list[ChallengeDefinition]:
        ...

    def update(self, definition: ChallengeDefinition) -> None:
        """Update the mutable metadata (``title``) of an existing definition,
        keyed by ``slug``. Raises if it does not exist."""
        ...


class ChallengeVersionRepository(Protocol):
    """Stores immutable-once-published challenge versions under a definition.

    ``add`` inserts a version (typically ``draft``); ``(definition_slug,
    version_no)`` and ``(definition_slug, spec_sha256)`` are unique, so
    re-adding the identical spec is rejected (content dedup upholds
    determinism). State moves are explicit and forward-only: ``publish`` freezes
    a draft's content and stamps ``published_at``; ``archive`` retires a
    published version. There is no generic content ``update`` -- published
    content is immutable (and the store enforces it with a trigger).
    """

    def add(self, version: ChallengeVersion) -> None:
        """Insert a version. ``version_no`` is caller-assigned (monotonic per
        definition from 1); the store enforces ``(definition, version_no)`` and
        ``(definition, spec_sha256)`` uniqueness but does not allocate numbers or
        forbid gaps -- a concurrent duplicate resolves to one winner and one
        IntegrityError the caller handles."""
        ...

    def get(self, definition_slug: str, version_no: int) -> ChallengeVersion | None:
        ...

    def get_by_spec_sha256(
        self, definition_slug: str, spec_sha256: str
    ) -> ChallengeVersion | None:
        ...

    def list_for_definition(self, definition_slug: str) -> list[ChallengeVersion]:
        ...

    def publish(
        self, definition_slug: str, version_no: int, published_at: datetime
    ) -> None:
        """Transition a ``draft`` version to ``published`` (freezing content).
        Raises if the version is missing or not in ``draft``."""
        ...

    def archive(
        self, definition_slug: str, version_no: int, archived_at: datetime
    ) -> None:
        """Transition a ``published`` version to ``archived`` (retaining
        ``published_at``, stamping ``archived_at``). Raises if the version is
        missing or not ``published``."""
        ...


class ChallengeBuildRepository(Protocol):
    """Stores content-addressed, insert-only build artifacts, keyed by
    ``build_sha256``. Builds are never updated -- a new build is a new hash."""

    def add(self, build: ChallengeBuild) -> None:
        ...

    def get(self, build_sha256: str) -> ChallengeBuild | None:
        ...

    def list_for_version(
        self, definition_slug: str, version_no: int
    ) -> list[ChallengeBuild]:
        ...


class ChallengePublicationRepository(Protocol):
    """Attaches published versions to competitions with per-competition scoring
    config, keyed by ``(competition_id, definition_slug, version_no)``. Scoring
    fields are mutable via ``update``; a version appears at most once per
    competition.

    ``add`` requires the version to be ``published``. A version that is later
    ``archived`` in the catalog keeps its existing publications (a running
    competition must not lose a challenge because the authoring catalog moved
    on); ``update`` therefore does not re-check version state. Only *new*
    attachments require a currently-published version.
    """

    def add(self, publication: ChallengePublication) -> None:
        ...

    def get(
        self, competition_id: str, definition_slug: str, version_no: int
    ) -> ChallengePublication | None:
        ...

    def list_for_competition(
        self, competition_id: str
    ) -> list[ChallengePublication]:
        ...

    def update(self, publication: ChallengePublication) -> None:
        """Update the mutable scoring fields of an existing publication, keyed by
        ``(competition_id, definition_slug, version_no)``. Raises if missing."""
        ...


class LedgerSubmissionRepository(Protocol):
    """Append-only store of answer attempts, keyed by ``submission_id``.

    A submission's correctness is decided at insert and never edited; there is
    no ``update`` or ``delete`` (the store enforces append-only with a trigger).
    """

    def add(self, submission: LedgerSubmission) -> None:
        ...

    def get(self, submission_id: str) -> LedgerSubmission | None:
        ...

    def list_for_team(
        self, competition_id: str, team_name: str
    ) -> list[LedgerSubmission]:
        ...


class SolveRepository(Protocol):
    """Append-only store of accepted solves, at most one per ``(competition,
    team, challenge version)``.

    ``add`` resolves the referenced competition, team, version and source
    submission by business identity and fails loudly if any is missing; a second
    solve for the same ``(competition, team, version)`` raises the underlying
    integrity error (the schema's UNIQUE), and a solve referencing an incorrect
    or mismatched submission is rejected (composite FK + trigger).
    """

    def add(self, solve: Solve) -> None:
        ...

    def get(self, solve_id: str) -> Solve | None:
        ...

    def get_for_challenge(
        self, competition_id: str, team_name: str, definition_slug: str, version_no: int
    ) -> Solve | None:
        ...

    def list_for_competition(self, competition_id: str) -> list[Solve]:
        ...


class ScoreLedger(Protocol):
    """Append-only, event-sourced score ledger (the source of truth).

    ``append`` assigns a strictly monotonic ``seq`` (DB sequence) and returns the
    persisted event carrying it. ``since``/``latest_seq`` mirror the pure
    :class:`~ctf_generator.domain.competitions.events.EventStore` cursor
    contract. Entries are never updated or deleted (trigger-enforced).
    """

    def append(self, event: ScoreEvent) -> ScoreEvent:
        ...

    def since(self, seq: int) -> list[ScoreEvent]:
        ...

    def latest_seq(self) -> int:
        ...

    def list_for_competition(self, competition_id: str) -> list[ScoreEvent]:
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
