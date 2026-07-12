"""Scheduling & quota value types (M8).

Pure, frozen domain aggregates for capacity accounting and capability-aware
worker selection. No IO, no framework -- the concrete counter store, the
reservation ledger, and the SQL scheduler all live in infrastructure.

Two axes of a resource quota:

* POOLED dimensions (``cpu_millis`` / ``memory_mb`` / ``storage_mb`` /
  ``active_instances`` / ``build_concurrency`` / ``exposed_ports``) are
  *counter-tracked*: each launch reserves an integer amount against a single
  ``resource_quotas`` row, and the row's ``reserved_value`` is incremented under
  a ``SELECT ... FOR UPDATE`` lock. The N+1th concurrent launch over a saturated
  pool is rejected atomically -- there is never a partial increment.
* CEILING dimensions (``max_runtime_seconds``) are a scalar cap: the request's
  required value is compared to ``limit_value`` but nothing is counted, so the
  row's ``reserved_value`` is forced to 0 by a CHECK (and no reservation item is
  written for it).

A reservation is keyed by ``reservation_id`` (equal to the instance business id
supplied by the sibling instance-lifecycle slice), which makes a duplicate
``reserve`` an idempotent re-launch guard (surfaces as ``IntegrityError``) and
gives ``release`` / ``reconcile`` a stable, join-free key.

Secret-free by construction: reservations carry integer amounts and business-key
references only -- never flags, tokens, credentials, or provider keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

# The five quota scopes. ``platform`` is the global cap; a single sentinel key
# stands in for its (otherwise absent) business key so every row shares one
# ``(scope_type, scope_key, dimension)`` shape.
VALID_QUOTA_SCOPES = frozenset(
    {"platform", "competition", "team", "challenge", "worker"}
)

# The platform scope's sentinel business key (there is exactly one platform row
# per dimension). Chosen so it cannot collide with a real slug/name.
PLATFORM_SCOPE_KEY = "__platform__"

# Counter-tracked pool dimensions: reserve increments ``reserved_value``.
POOLED_DIMENSIONS = frozenset(
    {
        "cpu_millis",
        "memory_mb",
        "storage_mb",
        "active_instances",
        "build_concurrency",
        "exposed_ports",
    }
)

# Scalar ceiling dimensions: reserve compares against the cap, never counts.
CEILING_DIMENSIONS = frozenset({"max_runtime_seconds"})

VALID_DIMENSIONS = POOLED_DIMENSIONS | CEILING_DIMENSIONS

VALID_RESERVATION_STATES = frozenset({"held", "released"})


class QuotaExceededError(Exception):
    """A reserve request would push a pooled counter past its ``limit_value``,
    or a ceiling request exceeds its cap. The whole unit of work is rolled back
    -- there is never a partial increment (the N+1th concurrent launch over a
    saturated pool is rejected atomically).

    Carries the offending scope so the scheduler can tell a *full worker*
    (``scope_type == 'worker'`` -- retry the next candidate) from a *shared-pool
    overrun* (any other scope -- propagate: no other worker will help)."""

    def __init__(
        self,
        message: str,
        *,
        scope_type: str | None = None,
        scope_key: str | None = None,
        dimension: str | None = None,
    ) -> None:
        super().__init__(message)
        self.scope_type = scope_type
        self.scope_key = scope_key
        self.dimension = dimension


class NoEligibleWorkerError(Exception):
    """No dispatch-eligible worker satisfies the requirements (architecture /
    capabilities / runtime) with free capacity. Distinct from
    :class:`QuotaExceededError`: a shared-pool overrun propagates; a per-worker
    saturation is retried against the next candidate."""


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_tz_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")


def _require_scope(scope_type: str, scope_key: str, dimension: str) -> None:
    if scope_type not in VALID_QUOTA_SCOPES:
        raise ValueError(
            f"scope_type must be one of {sorted(VALID_QUOTA_SCOPES)}, "
            f"got {scope_type!r}"
        )
    _require_nonempty(scope_key, "scope_key")
    if dimension not in VALID_DIMENSIONS:
        raise ValueError(
            f"dimension must be one of {sorted(VALID_DIMENSIONS)}, got {dimension!r}"
        )


@dataclass(frozen=True)
class QuotaScope:
    """A ``(scope_type, scope_key)`` addressing pair (``platform`` uses the
    sentinel key)."""

    scope_type: str
    scope_key: str

    def __post_init__(self) -> None:
        if self.scope_type not in VALID_QUOTA_SCOPES:
            raise ValueError(
                f"scope_type must be one of {sorted(VALID_QUOTA_SCOPES)}, "
                f"got {self.scope_type!r}"
            )
        _require_nonempty(self.scope_key, "scope_key")


@dataclass(frozen=True)
class ResourceQuota:
    """One quota row: a limit on ``dimension`` for a ``(scope_type, scope_key)``
    plus its live ``reserved_value`` counter. A ceiling dimension always has
    ``reserved_value == 0`` (the store enforces it with a CHECK)."""

    scope_type: str
    scope_key: str
    dimension: str
    limit_value: int
    reserved_value: int = 0

    def __post_init__(self) -> None:
        _require_scope(self.scope_type, self.scope_key, self.dimension)
        if not isinstance(self.limit_value, int) or self.limit_value < 0:
            raise ValueError(
                f"limit_value must be an int >= 0, got {self.limit_value!r}"
            )
        if not isinstance(self.reserved_value, int) or self.reserved_value < 0:
            raise ValueError(
                f"reserved_value must be an int >= 0, got {self.reserved_value!r}"
            )
        if self.dimension in CEILING_DIMENSIONS and self.reserved_value != 0:
            raise ValueError(
                f"ceiling dimension {self.dimension!r} must have reserved_value 0, "
                f"got {self.reserved_value!r}"
            )

    @property
    def available(self) -> int:
        """Headroom left in the pool (``limit - reserved``). Non-negative for a
        well-formed row; a lowered limit can leave it 0 (holds are
        grandfathered, new reserves blocked until it drains)."""
        return max(self.limit_value - self.reserved_value, 0)


@dataclass(frozen=True)
class ReservationItem:
    """One pooled-counter increment inside a reservation (append-only). The
    amount is strictly positive; ceiling checks never produce an item."""

    scope_type: str
    scope_key: str
    dimension: str
    amount: int

    def __post_init__(self) -> None:
        _require_scope(self.scope_type, self.scope_key, self.dimension)
        if self.dimension not in POOLED_DIMENSIONS:
            raise ValueError(
                f"reservation items are pooled dimensions only, got {self.dimension!r}"
            )
        if not isinstance(self.amount, int) or self.amount <= 0:
            raise ValueError(f"amount must be an int >= 1, got {self.amount!r}")


@dataclass(frozen=True)
class CeilingRequirement:
    """A scalar ceiling check inside a demand: ``required_value`` must not exceed
    the quota's ``limit_value``. Nothing is counted."""

    scope_type: str
    scope_key: str
    dimension: str
    required_value: int

    def __post_init__(self) -> None:
        _require_scope(self.scope_type, self.scope_key, self.dimension)
        if self.dimension not in CEILING_DIMENSIONS:
            raise ValueError(
                f"ceiling requirements are ceiling dimensions only, "
                f"got {self.dimension!r}"
            )
        if not isinstance(self.required_value, int) or self.required_value < 0:
            raise ValueError(
                f"required_value must be an int >= 0, got {self.required_value!r}"
            )


@dataclass(frozen=True)
class ResourceDemand:
    """The atomic reserve request for one instance launch.

    ``items`` are the pooled increments (each locked and incremented in sorted
    order); ``ceilings`` are the scalar caps checked but not counted. The
    denormalized scope keys let release/reconcile/scheduling avoid a join.
    ``reservation_id`` equals the instance business id, so a duplicate reserve
    is an idempotent re-launch guard.
    """

    reservation_id: str
    worker_key: str
    expires_at: datetime
    items: tuple[ReservationItem, ...] = ()
    ceilings: tuple[CeilingRequirement, ...] = ()
    competition_key: str | None = None
    team_key: str | None = None
    challenge_key: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.reservation_id, "reservation_id")
        _require_nonempty(self.worker_key, "worker_key")
        _require_tz_aware(self.expires_at, "expires_at")
        if not isinstance(self.items, tuple):
            raise ValueError("items must be a tuple of ReservationItem")
        if not isinstance(self.ceilings, tuple):
            raise ValueError("ceilings must be a tuple of CeilingRequirement")
        if not self.items and not self.ceilings:
            raise ValueError("a demand must carry at least one item or ceiling")
        seen: set[tuple[str, str, str]] = set()
        for item in self.items:
            if not isinstance(item, ReservationItem):
                raise ValueError("items entries must be ReservationItem")
            key = (item.scope_type, item.scope_key, item.dimension)
            if key in seen:
                raise ValueError(f"duplicate reservation item for {key!r}")
            seen.add(key)
        for ceiling in self.ceilings:
            if not isinstance(ceiling, CeilingRequirement):
                raise ValueError("ceilings entries must be CeilingRequirement")
        for key_name, value in (
            ("competition_key", self.competition_key),
            ("team_key", self.team_key),
            ("challenge_key", self.challenge_key),
        ):
            if value is not None:
                _require_nonempty(value, key_name)

    def sorted_items(self) -> tuple[ReservationItem, ...]:
        """Items in a deterministic ``(scope_type, scope_key, dimension)`` order
        so every reserver locks the shared counter rows in the same sequence --
        this is what makes concurrent reserves deadlock-free."""
        return tuple(
            sorted(self.items, key=lambda i: (i.scope_type, i.scope_key, i.dimension))
        )


@dataclass(frozen=True)
class QuotaReservation:
    """A recorded reservation header: which instance holds capacity, until when,
    and whether it is still ``held`` or has been ``released``."""

    reservation_id: str
    worker_key: str
    expires_at: datetime
    state: str = "held"
    created_at: datetime | None = None
    released_at: datetime | None = None
    competition_key: str | None = None
    team_key: str | None = None
    challenge_key: str | None = None
    items: tuple[ReservationItem, ...] = ()

    def __post_init__(self) -> None:
        _require_nonempty(self.reservation_id, "reservation_id")
        _require_nonempty(self.worker_key, "worker_key")
        _require_tz_aware(self.expires_at, "expires_at")
        if self.state not in VALID_RESERVATION_STATES:
            raise ValueError(
                f"state must be one of {sorted(VALID_RESERVATION_STATES)}, "
                f"got {self.state!r}"
            )
        if (self.state == "released") != (self.released_at is not None):
            raise ValueError("released_at must be set iff state == 'released'")


@runtime_checkable
class FamilyMetadata(Protocol):
    """The minimal surface :func:`requirements_from_family` reads. Kept as a
    structural Protocol so the domain never imports the heavy ``families``
    module (which pulls in renderers and I/O)."""

    isolation_level: str
    supported_architectures: tuple[str, ...]


@dataclass(frozen=True)
class WorkerRequirements:
    """What a worker must satisfy to run a given instance: the target
    architecture, the capabilities it must advertise (job types + the isolation
    token), and optionally a specific runtime type (``None`` = any rootless
    runtime)."""

    architecture: str
    required_capabilities: frozenset[str]
    runtime_type: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.architecture, "architecture")
        if not isinstance(self.required_capabilities, frozenset):
            raise ValueError("required_capabilities must be a frozenset")
        for cap in self.required_capabilities:
            _require_nonempty(cap, "required_capabilities entry")
        if self.runtime_type is not None:
            _require_nonempty(self.runtime_type, "runtime_type")


@dataclass(frozen=True)
class WorkerCandidate:
    """A dispatch-eligible worker the scheduler considered, with its live
    capacity accounting and image-cache affinity (empty in slice 1)."""

    worker_name: str
    capacity: int
    reserved: int
    image_cached: bool = False

    def __post_init__(self) -> None:
        _require_nonempty(self.worker_name, "worker_name")
        if not isinstance(self.capacity, int) or self.capacity < 0:
            raise ValueError(f"capacity must be an int >= 0, got {self.capacity!r}")
        if not isinstance(self.reserved, int) or self.reserved < 0:
            raise ValueError(f"reserved must be an int >= 0, got {self.reserved!r}")

    @property
    def free_capacity(self) -> int:
        return max(self.capacity - self.reserved, 0)


# The isolation-token capability prefix. An instance whose family runs with
# ``isolation_level='container'`` requires a worker advertising the capability
# ``isolation:container`` -- so isolation matching rides the existing worker
# capability set (no ``workers`` schema change) and the scheduler's array
# containment check covers it for free.
ISOLATION_CAPABILITY_PREFIX = "isolation:"

# The base capability an instance-launching worker must advertise (a job type
# from ``VALID_JOB_TYPES``).
LAUNCH_CAPABILITY = "launch_instance"


def isolation_capability(isolation_level: str) -> str:
    """The capability token a worker advertises to run ``isolation_level``
    instances (e.g. ``isolation:container``)."""
    _require_nonempty(isolation_level, "isolation_level")
    return f"{ISOLATION_CAPABILITY_PREFIX}{isolation_level}"


def requirements_from_family(
    family: FamilyMetadata,
    architecture: str,
    *,
    extra_capabilities: frozenset[str] = frozenset(),
    runtime_type: str | None = None,
) -> WorkerRequirements:
    """Derive the worker requirements to launch one instance of ``family`` on
    ``architecture``. The architecture must be one the family supports;
    capabilities are ``launch_instance`` + the family's isolation token + any
    caller-supplied extras."""
    if architecture not in tuple(family.supported_architectures):
        raise ValueError(
            f"family does not support architecture {architecture!r}; "
            f"supported: {sorted(family.supported_architectures)}"
        )
    caps = {
        LAUNCH_CAPABILITY,
        isolation_capability(family.isolation_level),
        *extra_capabilities,
    }
    return WorkerRequirements(
        architecture=architecture,
        required_capabilities=frozenset(caps),
        runtime_type=runtime_type,
    )


def worker_matches(
    *,
    architectures: tuple[str, ...],
    capabilities: tuple[str, ...],
    runtime_type: str,
    requirements: WorkerRequirements,
) -> bool:
    """Pure capability match: does a worker with these declared
    ``architectures`` / ``capabilities`` / ``runtime_type`` satisfy
    ``requirements``? The SQL ``candidate_workers`` filter encodes exactly this
    predicate in the database (plus dispatch-eligibility and free capacity);
    this helper is the host-testable, side-effect-free specification."""
    if requirements.architecture not in architectures:
        return False
    if not requirements.required_capabilities <= set(capabilities):
        return False
    if requirements.runtime_type is not None and runtime_type != requirements.runtime_type:
        return False
    return True
