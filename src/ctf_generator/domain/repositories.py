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

from collections.abc import Mapping, Sequence
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
from .execution.models import Worker, WorkerCredential
from .identity.models import Membership, Team, User
from .instances.models import (
    HealthObservation,
    Instance,
    InstanceCredential,
    InstanceEndpoint,
    InstanceEvent,
    RuntimeResource,
)
from .ledger.models import (
    LedgerSubmission,
    ProjectionLag,
    ProjectionTask,
    ScoreboardProjectionRecord,
    ScoreEvent,
    Solve,
)
from .scheduling.models import (
    QuotaReservation,
    ResourceDemand,
    ResourceQuota,
    WorkerCandidate,
    WorkerRequirements,
)
from .work.models import Job, JobLease


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

    def remove(
        self, competition_id: str, definition_slug: str, version_no: int
    ) -> bool:
        """Detach a version from a competition. Returns ``True`` if a row was
        removed, ``False`` if the attachment did not exist; raises
        :class:`LookupError` if the competition or version are unknown."""
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

    def get_by_submission(self, submission_id: str) -> Solve | None:
        """The solve derived from ``submission_id``, if any (backed by the
        store's ``UNIQUE (submission_id)``). Used by the idempotent replay path
        of submission processing."""
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


class JobQueue(Protocol):
    """The durable PostgreSQL-backed job queue contract (ADR-003; supersedes
    the M6 ``WorkerQueue`` stub).

    NO business logic here -- the store enforces mechanics only. Error
    contract: a duplicate ``idempotency_key`` raises the underlying
    ``IntegrityError`` (the application layer collapses it to the existing
    job); a missing job, a stale/mismatched ``lease_token``, or an illegal
    source state raises :class:`LookupError` and changes nothing. Every
    *fenced* method (``start``/``heartbeat``/``complete``/``fail``) requires
    the ``lease_token`` minted at ``claim`` -- this is what makes duplicate
    delivery and zombie workers harmless. All ``now`` values are
    caller-passed (repositories stay clock-free; tests stay deterministic).
    """

    def enqueue(self, job: Job, now: datetime | None = None) -> Job:
        """Insert a ``queued`` job. Duplicate ``idempotency_key`` ->
        IntegrityError. Returns the persisted job. The enqueue transition is
        recorded at ``now`` (the enqueue instant); ``available_at`` is only the
        dispatch gate. ``now`` defaults to ``available_at``."""
        ...

    def get(self, job_id: str) -> Job | None:
        ...

    def get_by_idempotency_key(self, key: str) -> Job | None:
        ...

    def claim(
        self,
        worker_id: str,
        capabilities: frozenset[str],
        lease_seconds: int,
        now: datetime,
    ) -> JobLease | None:
        """Atomically claim the best available job whose
        ``required_capabilities`` the worker satisfies (``FOR UPDATE SKIP
        LOCKED``: at most one claimer per row, no blocking). ``None`` when
        nothing is claimable. Increments the attempt count and mints the
        fencing ``lease_token``.

        M8 OBLIGATION (INVARIANT). ``claim`` accepts a ``worker_id`` *string*
        with no ``workers``-table FK and consults NO trust/drain/quarantine/
        heartbeat state -- the queue enforces queue mechanics only. Therefore
        the M8 worker-facing API MUST expose only an application-layer
        ``WorkerJobService`` that, before EVERY queue verb (claim / heartbeat /
        complete / fail): (i) authenticates the presented credential,
        (ii) rejects a non-trusted / quarantined / draining / heartbeat-stale
        worker, and (iii) derives ``worker_id`` EXCLUSIVELY from the
        authenticated credential. Raw ``JobQueue.claim`` must never be
        reachable with a request-supplied ``worker_id``. (``Worker
        .drain_requested_at`` is currently dead state whose enforcement lands
        in M8.)"""
        ...

    def start(self, job_id: str, lease_token: str, now: datetime) -> None:
        """``claimed`` -> ``running`` (stamps ``started_at``). Fenced."""
        ...

    def heartbeat(
        self, job_id: str, lease_token: str, lease_seconds: int, now: datetime
    ) -> bool:
        """Extend the lease. Returns True iff cancellation has been requested
        (the cooperative-cancel signal). Fenced."""
        ...

    def complete(
        self,
        job_id: str,
        lease_token: str,
        result_json: Mapping[str, object] | None,
        result_ref: str | None,
        log_ref: str | None,
        now: datetime,
    ) -> None:
        """``running`` -> ``succeeded``. Results carry references/hashes only,
        never secrets. Fenced."""
        ...

    def fail(
        self,
        job_id: str,
        lease_token: str,
        error_class: str,
        error_detail: str | None,
        retryable: bool,
        now: datetime,
    ) -> Job:
        """Report a failure. ``retryable=False`` -> ``failed`` (permanent);
        ``retryable=True`` -> ``queued`` with exponential backoff, or
        ``dead_letter`` when the attempt budget is exhausted. As the one
        special case, ``error_class='cancelled'`` records a cooperative
        cancellation (-> ``cancelled``). ``error_detail`` must be sanitized --
        never secrets. Fenced. Returns the updated job."""
        ...

    def request_cancel(self, job_id: str, now: datetime) -> Job:
        """Cancel a ``queued`` job directly; for ``claimed``/``running`` jobs
        stamp ``cancel_requested_at`` (the worker observes it via
        ``heartbeat`` and cancels cooperatively). LookupError on a terminal
        job."""
        ...

    def reap_expired(self, now: datetime, limit: int = 100) -> list[Job]:
        """Requeue (with backoff) or dead-letter every ``claimed``/``running``
        job whose lease expired before ``now``. Same SKIP LOCKED discipline as
        ``claim``, so the sweeper and claimers never race on one row. Pure
        SQL -- safe to run on the control plane."""
        ...

    def list_dead_letter(self) -> list[Job]:
        ...

    def retry_dead_letter(self, job_id: str, now: datetime) -> Job:
        """Operator requeue of a ``dead_letter`` job with a fresh attempt
        budget. LookupError if the job is missing or not dead-lettered."""
        ...


class WorkerRegistry(Protocol):
    """Stores execution-plane worker identities, keyed by ``name``.

    State moves are explicit methods (publish/archive style) -- no generic
    state update. Each raises :class:`LookupError` on a missing worker or an
    illegal source state (e.g. ``approve`` on a non-pending worker, any
    transition out of ``revoked``).
    """

    def add(self, worker: Worker) -> None:
        """Insert a ``pending`` worker. Duplicate ``name`` -> IntegrityError."""
        ...

    def get(self, name: str) -> Worker | None:
        ...

    def list(self) -> list[Worker]:
        ...

    def update_profile(self, worker: Worker) -> None:
        """Update the mutable profile fields (runtime_type, architectures,
        capabilities, capacity, version), keyed by the immutable ``name``.
        Trust/drain/quarantine fields are NOT writable here."""
        ...

    def heartbeat(self, name: str, at: datetime) -> None:
        ...

    def approve(self, name: str) -> None:
        """``pending`` -> ``trusted``."""
        ...

    def revoke(self, name: str, revoked_at: datetime) -> None:
        """``pending``/``trusted`` -> ``revoked`` (terminal)."""
        ...

    def quarantine(self, name: str, at: datetime, reason: str) -> None:
        ...

    def clear_quarantine(self, name: str) -> None:
        ...

    def drain(self, name: str, at: datetime) -> None:
        ...

    def resume(self, name: str) -> None:
        ...


class WorkerCredentialRepository(Protocol):
    """Stores hashed, scoped worker credentials (near-append-only: the single
    legal mutation is stamping ``revoked_at``; the store's triggers enforce
    it). At most one live credential per worker (partial UNIQUE)."""

    def add(self, credential: WorkerCredential) -> None:
        """Insert. A second live credential for the same worker ->
        IntegrityError (the partial UNIQUE), which is what makes rotation
        race-proof."""
        ...

    def get(self, credential_id: str) -> WorkerCredential | None:
        ...

    def get_active_for_worker(self, worker_name: str) -> WorkerCredential | None:
        ...

    def list_for_worker(self, worker_name: str) -> list[WorkerCredential]:
        ...

    def revoke(self, credential_id: str, revoked_at: datetime) -> None:
        """Stamp ``revoked_at``. LookupError if missing or already revoked."""
        ...


class FlagVerifier(Protocol):
    """Decides whether a candidate flag is correct for a challenge version.

    A seam so verification policy can evolve (per-instance dynamic flags via
    ``instance_seed`` in M8) without touching the submission transaction
    script. Implementations must compare in constant time and must never log
    or persist the candidate or the expected flag.
    """

    def verify(
        self, version: ChallengeVersion, instance_seed: str | None, candidate: str
    ) -> bool:
        ...


class ScoreProjectionQueue(Protocol):
    """The transactional-outbox work queue feeding the scoreboard projector.

    Rows are inserted by a DB trigger in the same transaction as each
    ``score_events`` INSERT (never by application code), so a committed event
    always has an unprocessed outbox row -- the projector can never skip one.
    ``complete`` deletes rows only in the same transaction that folded them.
    """

    def pending_competitions(self, limit: int = 100) -> list[str]:
        """Distinct competition ids (slugs) with pending work (no locks)."""
        ...

    def claim_pending(
        self, limit: int, competition_id: str | None = None
    ) -> list[ProjectionTask]:
        """Lock (FOR UPDATE SKIP LOCKED) and return pending rows in seq order,
        optionally scoped to one competition."""
        ...

    def complete(self, seqs: Sequence[int]) -> None:
        ...

    def fail(self, seqs: Sequence[int], error: str) -> int:
        """Mark still-pending rows failed with a sanitized error (exception
        class + message only -- never payloads, never flags). Returns the
        number of rows marked."""
        ...

    def list_failed(self) -> list[ProjectionTask]:
        ...

    def requeue_all(self) -> int:
        """Re-enqueue an outbox row for every ledger event (rebuild support)
        and flip failed rows back to pending. Idempotent."""
        ...

    def pending_stats(self) -> ProjectionLag:
        ...


class QuotaPolicyRepository(Protocol):
    """Stores resource-quota *limits* keyed by ``(scope_type, scope_key,
    dimension)``. The ``reserved_value`` counter is owned by the
    :class:`QuotaLedger` (reserve/release increment it under a row lock); this
    repository sets and reads limits only.

    ``upsert_limit`` seeds or adjusts a limit without ever touching the live
    counter (so a limit reduction grandfathers current holds and simply blocks
    new reserves until the pool drains). A ceiling dimension's row is created
    with ``reserved_value`` fixed at 0.
    """

    def upsert_limit(self, quota: ResourceQuota) -> None:
        """Create the quota row or update its ``limit_value`` in place, keyed by
        ``(scope_type, scope_key, dimension)``. Never writes ``reserved_value``
        on an existing row."""
        ...

    def get(
        self, scope_type: str, scope_key: str, dimension: str
    ) -> ResourceQuota | None:
        ...

    def list_for_scope(
        self, scope_type: str, scope_key: str
    ) -> list[ResourceQuota]:
        ...


class QuotaLedger(Protocol):
    """The atomic reservation ledger over ``resource_quotas`` (counters) +
    ``quota_reservations`` (headers) + ``quota_reservation_items`` (append-only
    per-counter amounts).

    Error contract: a reserve that would push a pooled counter past its limit,
    or a ceiling request over its cap, raises
    :class:`~ctf_generator.domain.scheduling.models.QuotaExceededError` and
    changes nothing (the caller's unit of work rolls back). A duplicate
    ``reservation_id`` raises the underlying ``IntegrityError`` (the idempotent
    re-launch guard). A reserve against a missing quota row raises
    :class:`LookupError`. All ``now`` values are caller-passed.
    """

    def reserve(self, demand: ResourceDemand, now: datetime) -> QuotaReservation:
        """Atomically reserve every pooled amount in ``demand`` (each counter
        row ``SELECT ... FOR UPDATE`` locked in sorted order and incremented)
        and validate every ceiling. All-or-nothing: any overrun aborts the whole
        reservation with no partial increment."""
        ...

    def release(self, reservation_id: str, now: datetime) -> bool:
        """Idempotently release a held reservation: decrement each held
        counter and flip the header to ``released``. Returns True if it released
        a still-held reservation, False if it was already released / absent (a
        double release is a no-op)."""
        ...

    def reactivate(
        self, reservation_id: str, new_expires_at: datetime, now: datetime
    ) -> QuotaReservation:
        """Re-hold a previously *released* reservation in place (a relaunch of
        the same instance id): flip ``released -> held`` under a row lock and
        re-increment the counters for its original append-only items, extending
        the TTL to ``new_expires_at``. An already-``held`` reservation is
        returned unchanged (idempotent). ``LookupError`` if it does not exist;
        ``QuotaExceededError`` if a counter can no longer admit the hold."""
        ...

    def renew(
        self, reservation_id: str, new_expires_at: datetime, now: datetime
    ) -> None:
        """Extend a *held* reservation's TTL to ``new_expires_at`` (the
        instance-lifecycle owner keeps a running instance's hold alive so the
        ``release_expired`` safety sweep never reclaims it). ``LookupError`` if
        the reservation is missing or already released."""
        ...

    def get(self, reservation_id: str) -> QuotaReservation | None:
        ...

    def list_expired(self, now: datetime, limit: int = 100) -> list[QuotaReservation]:
        """Held reservations whose ``expires_at`` is before ``now`` -- the
        leaked-hold sweep input for ``release_expired``."""
        ...

    def reconcile_counters(self) -> int:
        """Recompute every quota's ``reserved_value`` as the sum of held
        reservation-item amounts (self-healing drift repair). Returns the number
        of quota rows whose counter changed."""
        ...


class SchedulerRepository(Protocol):
    """Read side of capability-aware worker selection.

    ``candidate_workers`` returns dispatch-eligible workers -- ``trusted`` AND
    not quarantined AND ``drain_requested_at`` null (this is what finally
    enforces that dead M7 state) AND heartbeat fresh -- that match the
    architecture / capabilities / runtime requirements AND have free capacity,
    ranked by image-cache affinity, then most free capacity, then oldest
    heartbeat. Interface-only: no state change.
    """

    def candidate_workers(
        self,
        requirements: WorkerRequirements,
        now: datetime,
        heartbeat_max_age_seconds: int,
        image_ref: str | None = None,
        limit: int = 20,
    ) -> list[WorkerCandidate]:
        ...

    def free_capacity(self, worker_name: str) -> int:
        """The worker's remaining concurrency (its ``(worker, active_instances)``
        quota ``limit - reserved``), or its declared capacity if no quota row
        exists yet. LookupError if the worker is unknown."""
        ...


class InstanceRepository(Protocol):
    """The instance-lifecycle aggregate store (M8 slice 1b).

    One repository covers the ``Instance`` root plus its runtime facts
    (endpoints / runtime resources / credentials) and the two append-only
    streams (health observations / audit events), the way the job queue folds
    ``job_transitions`` into ``SqlAlchemyJobQueue``. The ``Instance`` references
    its competition / team / challenge version and its assigned worker by
    BUSINESS identity; ``add`` resolves each to a surrogate uuid and fails loud
    (:class:`LookupError`) on a dangling reference, and a duplicate
    ``instance_id`` raises the underlying ``IntegrityError``.

    ``transition`` is the ONLY way ``state`` moves: it performs a guarded UPDATE
    (the store's plpgsql trigger rejects an illegal move as
    ``sqlalchemy.exc.ProgrammingError``) and appends an :class:`InstanceEvent`
    in the SAME transaction. Every ``now`` is caller-passed; the repository
    never reads a clock; ORM rows never escape.
    """

    def add(self, instance: Instance, now: datetime) -> Instance:
        """Insert a fresh instance (typically ``requested``) and its creation
        event (``from_state is None``). Duplicate ``instance_id`` ->
        IntegrityError; a missing competition/team/version/worker -> LookupError.
        """
        ...

    def get(self, instance_id: str) -> Instance | None:
        ...

    def list_reconcilable(self, limit: int = 500) -> list[Instance]:
        """Every non-archived instance -- the reconciler's desired-vs-observed
        scan input."""
        ...

    def list_all(self) -> list[Instance]:
        """Every instance (including archived), stable-sorted by ``(created_at,
        id)`` for the operator list view. The FULL ordered result set (no cap);
        the caller paginates over it with an opaque cursor."""
        ...

    def list_for_competition(self, competition_id: str) -> list[Instance]:
        """Every instance of one competition, stable-sorted like ``list_all``
        (the FULL result set, no cap); raises :class:`LookupError` on an unknown
        competition."""
        ...

    def transition(
        self,
        instance_id: str,
        to_state: str,
        *,
        reason: str,
        actor: str,
        now: datetime,
    ) -> Instance:
        """Guarded ``state`` change + append-only event in one transaction. An
        illegal move raises ``ProgrammingError`` (the trigger) and changes
        nothing; a missing instance raises LookupError."""
        ...

    def set_desired_state(
        self, instance_id: str, desired_state: str, now: datetime
    ) -> Instance:
        ...

    def set_assignment(
        self, instance_id: str, assigned_worker: str | None, now: datetime
    ) -> Instance:
        """Set (or clear, with ``None``) the assigned worker. A given-but-unknown
        worker name fails loud."""
        ...

    def bump_generation(self, instance_id: str, now: datetime) -> Instance:
        """Increment the fencing generation (reset/relaunch). Returns the
        updated instance carrying the new generation."""
        ...

    def fence_stale_worker(
        self,
        instance_id: str,
        *,
        expected_worker: str,
        expected_generation: int,
        now: datetime,
    ) -> Instance | None:
        """Atomic, precondition-checked evacuation off a dead worker: under a row
        lock, clear the assignment and bump the generation ONLY if the instance is
        still assigned to ``expected_worker`` at ``expected_generation``. Returns
        the updated instance, or ``None`` if a rival pass already converged."""
        ...

    def fence_missing_container(
        self, instance_id: str, *, expected_generation: int, now: datetime
    ) -> Instance | None:
        """Atomic, precondition-checked generation bump for missing-container
        recovery: under a row lock, increment the generation ONLY if it still
        equals ``expected_generation``. Returns the updated instance, or ``None``
        if a rival pass already bumped."""
        ...

    def set_runtime_facts(
        self,
        instance_id: str,
        now: datetime,
        *,
        image_ref: str | None = None,
        instance_seed: str | None = None,
        expires_at: datetime | None = None,
    ) -> Instance:
        """Partial update of placement/runtime references (only the keyword
        arguments that are passed are written)."""
        ...

    # -- runtime facts (worker-reported) -------------------------------------

    def record_endpoint(self, endpoint: InstanceEndpoint) -> None:
        """Upsert a team-facing endpoint keyed ``(instance_id, name)``."""
        ...

    def delete_endpoint(self, instance_id: str, name: str) -> bool:
        """Remove an endpoint (idempotent; returns whether a row was removed)."""
        ...

    def list_endpoints(self, instance_id: str) -> list[InstanceEndpoint]:
        ...

    def record_runtime_resource(self, resource: RuntimeResource) -> None:
        """Upsert a runtime resource keyed ``(instance_id, kind, external_ref)``."""
        ...

    def set_resource_state(
        self, instance_id: str, kind: str, external_ref: str, state: str, now: datetime
    ) -> bool:
        """Advance a runtime resource's lifecycle state (active -> releasing ->
        released). Returns whether a row matched."""
        ...

    def list_runtime_resources(self, instance_id: str) -> list[RuntimeResource]:
        ...

    def list_leaked_resources(self, limit: int = 500) -> list[RuntimeResource]:
        """Every ``active`` runtime resource whose owning instance is
        ``archived`` (terminal) -- a leak the reconciler must clean up."""
        ...

    def list_orphan_endpoints(self, limit: int = 500) -> list[InstanceEndpoint]:
        """Every endpoint whose owning instance is ``archived`` (terminal) -- an
        orphan the reconciler must delete."""
        ...

    def record_credential(self, credential: InstanceCredential) -> None:
        """Upsert an instance credential HANDLE keyed ``(instance_id, name)``
        (``secret_ref`` only -- never a secret value)."""
        ...

    def list_credentials(self, instance_id: str) -> list[InstanceCredential]:
        ...

    # -- append-only streams -------------------------------------------------

    def append_observation(self, observation: HealthObservation) -> HealthObservation:
        """Append a worker health observation; returns it carrying its assigned
        surrogate id."""
        ...

    def latest_observation(self, instance_id: str) -> HealthObservation | None:
        """The newest observation for an instance (by ``observed_at``)."""
        ...

    def list_events(self, instance_id: str) -> list[InstanceEvent]:
        """The append-only audit history for one instance, oldest first."""
        ...


class ScoreboardProjectionRepository(Protocol):
    """Stores the rebuildable scoreboard cache, one row per competition.

    ``upsert`` is guarded monotonic on ``as_of_seq`` (an older-snapshot fold
    can never overwrite a newer one). Never a source of truth.
    """

    def upsert(self, projection: ScoreboardProjectionRecord) -> None:
        ...

    def get(self, competition_id: str) -> ScoreboardProjectionRecord | None:
        ...

    def delete_all(self) -> int:
        """Delete every cached projection row (rebuild support). Returns the
        number of rows removed. The ledger remains the sole source of truth."""
        ...
