"""Instance-lifecycle value types (M8 slice 1b).

Six pure, frozen aggregates for a running challenge instance and the runtime
facts a worker reports about it:

* :class:`Instance` -- the lifecycle aggregate, keyed by ``instance_id`` (a
  caller-supplied uuid string that ALSO serves as the quota ``reservation_id``,
  so a relaunch of the same instance reuses its capacity hold). References its
  competition / team / challenge version by BUSINESS identity; the store resolves
  those to surrogate uuids and fails loud on a dangling reference. Its ``state``
  moves only along :data:`LEGAL_INSTANCE_TRANSITIONS` (a BEFORE UPDATE plpgsql
  trigger mirrors this matrix byte-equivalently), and ``generation`` fences stale
  worker observations.
* :class:`InstanceEndpoint` -- a team-facing connection address (host/port/url).
* :class:`RuntimeResource` -- a runtime-side object (container/network/volume/
  image) the reconciler tracks so a leak can be cleaned up.
* :class:`InstanceCredential` -- a contestant/instance access token *handle*
  (``secret_ref``), NEVER the secret value, and NEVER the flag.
* :class:`HealthObservation` -- APPEND-ONLY; a worker's report of what it sees,
  stamped with the ``generation`` it was acting on (older-generation reports are
  ignored for state decisions).
* :class:`InstanceEvent` -- APPEND-ONLY audit; one row per state change, written
  in the same transaction as the transition.

No IO, no framework -- the ORM, the transition trigger, the repositories, and the
reconciler live in infrastructure/application.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

# The fourteen instance lifecycle states. Stored as text + CHECK; the transition
# trigger mirrors LEGAL_INSTANCE_TRANSITIONS.
VALID_INSTANCE_STATES = frozenset(
    {
        "requested",
        "queued",
        "building",
        "ready",
        "starting",
        "healthy",
        "active",
        "degraded",
        "stopping",
        "stopped",
        "expired",
        "failed",
        "quarantined",
        "archived",
    }
)

# The operator/system *intent* for an instance -- what the reconciler steers the
# observed world toward. Distinct from ``state`` (the observed lifecycle point).
VALID_DESIRED_STATES = frozenset({"active", "stopped", "deleted"})

# ``archived`` is the sole terminal state (the store freezes an archived row).
TERMINAL_INSTANCE_STATES = frozenset({"archived"})

# Legal state transitions (from -> allowed targets). A self-transition
# (NEW.state == OLD.state) is a field update, not a transition, and is a no-op
# the application layer collapses; the store permits it for every non-terminal
# state and freezes terminal (``archived``) rows entirely.
LEGAL_INSTANCE_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "requested": frozenset({"queued", "failed", "quarantined"}),
    "queued": frozenset(
        {"building", "starting", "failed", "quarantined", "stopping"}
    ),
    "building": frozenset({"ready", "failed", "quarantined"}),
    "ready": frozenset({"starting", "failed", "quarantined", "stopping"}),
    "starting": frozenset({"healthy", "failed", "quarantined", "stopping"}),
    "healthy": frozenset(
        {"active", "degraded", "stopping", "expired", "quarantined", "failed"}
    ),
    "active": frozenset(
        {"degraded", "stopping", "expired", "quarantined", "failed"}
    ),
    "degraded": frozenset(
        {"healthy", "active", "stopping", "expired", "quarantined", "failed"}
    ),
    "stopping": frozenset({"stopped", "failed", "quarantined"}),
    "stopped": frozenset({"starting", "archived", "quarantined"}),
    "expired": frozenset({"stopping", "archived"}),
    "failed": frozenset({"starting", "archived", "quarantined"}),
    "quarantined": frozenset({"stopping", "archived"}),
    "archived": frozenset(),
}

# Runtime-resource kinds the reconciler tracks for leak cleanup.
VALID_RUNTIME_RESOURCE_KINDS = frozenset({"container", "network", "volume", "image"})

# Runtime-resource lifecycle (active -> releasing -> released).
VALID_RESOURCE_STATES = frozenset({"active", "releasing", "released"})

# What a worker may report observing. The coarse tokens ``absent`` / ``gone``
# augment the fourteen lifecycle states (the worker may report either a precise
# lifecycle point or a coarse phase).
VALID_OBSERVED_STATES = VALID_INSTANCE_STATES | frozenset({"absent", "gone"})

# Who caused an event (append-only audit provenance).
VALID_EVENT_ACTORS = frozenset({"system", "operator", "worker"})

# Observed tokens that mean "no live container exists" -- the reconciler treats
# these (and a missing/stale observation) as absent.
_OBSERVED_ABSENT_TOKENS = frozenset({"absent", "gone"})


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_tz_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")


def _require_positive(value: int, field_name: str) -> None:
    if not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be an int >= 1, got {value!r}")


def is_legal_instance_transition(from_state: str, to_state: str) -> bool:
    """Whether ``from_state -> to_state`` is a sanctioned move (a self-transition
    is always legal -- it is a field update, not a state change). The store's
    plpgsql guard encodes exactly this predicate."""
    if from_state == to_state:
        return True
    return to_state in LEGAL_INSTANCE_TRANSITIONS.get(from_state, frozenset())


def observed_is_absent(observed_state: str) -> bool:
    """Whether a worker's ``observed_state`` means no live container exists."""
    return observed_state in _OBSERVED_ABSENT_TOKENS


@dataclass(frozen=True)
class Instance:
    """One running (or to-be-run) challenge instance for a team.

    ``instance_id`` is the business key AND the quota ``reservation_id`` (a
    relaunch of the same instance reuses its hold). ``state`` is the observed
    lifecycle point; ``desired_state`` is the intent the reconciler steers
    toward. ``generation`` starts at 1 and is bumped on reset/relaunch so a
    worker observation carrying an older generation is ignored for state
    decisions (the fencing token). ``assigned_worker`` is a worker *name* (the
    repository resolves it to a surrogate uuid) or ``None`` when unplaced.
    ``image_ref`` / ``instance_seed`` are references only -- never a flag or a
    secret. ``expires_at`` is the scheduling TTL that keeps the quota hold alive.
    """

    instance_id: str
    competition_id: str
    team_name: str
    definition_slug: str
    version_no: int
    state: str = "requested"
    desired_state: str = "active"
    assigned_worker: str | None = None
    generation: int = 1
    image_ref: str | None = None
    expires_at: datetime | None = None
    instance_seed: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.instance_id, "instance_id")
        _require_nonempty(self.competition_id, "competition_id")
        _require_nonempty(self.team_name, "team_name")
        _require_nonempty(self.definition_slug, "definition_slug")
        if self.state not in VALID_INSTANCE_STATES:
            raise ValueError(
                f"state must be one of {sorted(VALID_INSTANCE_STATES)}, "
                f"got {self.state!r}"
            )
        if self.desired_state not in VALID_DESIRED_STATES:
            raise ValueError(
                f"desired_state must be one of {sorted(VALID_DESIRED_STATES)}, "
                f"got {self.desired_state!r}"
            )
        _require_positive(self.version_no, "version_no")
        _require_positive(self.generation, "generation")
        if self.assigned_worker is not None:
            _require_nonempty(self.assigned_worker, "assigned_worker")
        if self.image_ref is not None:
            _require_nonempty(self.image_ref, "image_ref")
        if self.instance_seed is not None:
            _require_nonempty(self.instance_seed, "instance_seed")
        if self.expires_at is not None:
            _require_tz_aware(self.expires_at, "expires_at")

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_INSTANCE_STATES

    def can_transition_to(self, to_state: str) -> bool:
        return is_legal_instance_transition(self.state, to_state)


@dataclass(frozen=True)
class InstanceEndpoint:
    """A team-facing connection address published for an instance, keyed by
    ``(instance_id, name)``. ``internal`` marks an address reachable only inside
    the isolation network (not published to contestants). Connection info only
    -- never a flag or a credential value."""

    instance_id: str
    name: str
    host: str
    port: int
    protocol: str
    url: str
    internal: bool = False

    def __post_init__(self) -> None:
        _require_nonempty(self.instance_id, "instance_id")
        _require_nonempty(self.name, "name")
        _require_nonempty(self.host, "host")
        _require_nonempty(self.protocol, "protocol")
        _require_nonempty(self.url, "url")
        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise ValueError(f"port must be 1..65535, got {self.port!r}")
        if not isinstance(self.internal, bool):
            raise ValueError("internal must be a bool")


@dataclass(frozen=True)
class RuntimeResource:
    """A runtime-side object that exists because of an instance, keyed by
    ``(instance_id, kind, external_ref)``. Tracked so the reconciler can detect
    and clean a leak (a resource with no owning non-terminal instance). Carries
    ``worker`` (the name of the host that owns it) and ``generation`` (the
    instance generation it was created under, so a post-reset leak of an
    old-generation resource is detectable). Its ``state`` runs
    ``active -> releasing -> released``."""

    instance_id: str
    kind: str
    external_ref: str
    worker: str
    generation: int = 1
    state: str = "active"

    def __post_init__(self) -> None:
        _require_nonempty(self.instance_id, "instance_id")
        _require_nonempty(self.external_ref, "external_ref")
        _require_nonempty(self.worker, "worker")
        if self.kind not in VALID_RUNTIME_RESOURCE_KINDS:
            raise ValueError(
                f"kind must be one of {sorted(VALID_RUNTIME_RESOURCE_KINDS)}, "
                f"got {self.kind!r}"
            )
        if self.state not in VALID_RESOURCE_STATES:
            raise ValueError(
                f"state must be one of {sorted(VALID_RESOURCE_STATES)}, "
                f"got {self.state!r}"
            )
        _require_positive(self.generation, "generation")


@dataclass(frozen=True)
class InstanceCredential:
    """A contestant/instance access token, keyed by ``(instance_id, name)``.

    ``secret_ref`` is a HANDLE to the secret (a vault key / storage reference),
    NEVER the secret value -- the value is injected by the worker from a scoped
    secret at launch, out of band of this persisted, operator-visible record.
    This is access data, NEVER the flag or the private solver."""

    instance_id: str
    name: str
    secret_ref: str
    scopes: tuple[str, ...] = ()
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.instance_id, "instance_id")
        _require_nonempty(self.name, "name")
        _require_nonempty(self.secret_ref, "secret_ref")
        if not isinstance(self.scopes, tuple):
            raise ValueError("scopes must be a tuple of strings")
        for scope in self.scopes:
            _require_nonempty(scope, "scopes entry")
        if self.expires_at is not None:
            _require_tz_aware(self.expires_at, "expires_at")


@dataclass(frozen=True)
class HealthObservation:
    """APPEND-ONLY worker report of what it observes about one instance.

    ``observed_state`` is the worker's view (a precise lifecycle state or a
    coarse ``absent``/``gone``); ``healthy`` is its liveness verdict; ``detail``
    is a small jsonb bag of references (never secrets). ``generation`` is the
    instance generation the worker was acting on -- the reconciler IGNORES an
    observation whose generation does not match the instance's current
    generation (the stale-fence). ``observation_id`` is a surrogate assigned by
    the store (``None`` before persistence)."""

    instance_id: str
    observed_state: str
    healthy: bool
    worker: str
    generation: int
    observed_at: datetime
    detail: Mapping[str, object] = field(default_factory=dict, compare=False)
    observation_id: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.instance_id, "instance_id")
        _require_nonempty(self.worker, "worker")
        if self.observed_state not in VALID_OBSERVED_STATES:
            raise ValueError(
                f"observed_state must be one of {sorted(VALID_OBSERVED_STATES)}, "
                f"got {self.observed_state!r}"
            )
        if not isinstance(self.healthy, bool):
            raise ValueError("healthy must be a bool")
        if not isinstance(self.detail, Mapping):
            raise ValueError("detail must be a mapping")
        _require_positive(self.generation, "generation")
        _require_tz_aware(self.observed_at, "observed_at")
        if self.observation_id is not None:
            _require_nonempty(self.observation_id, "observation_id")

    @property
    def observed_absent(self) -> bool:
        return observed_is_absent(self.observed_state)


@dataclass(frozen=True)
class InstanceEvent:
    """APPEND-ONLY audit row for one state change (``from_state is None`` marks
    the initial creation). Written in the same transaction as the transition, so
    the audit trail is transactional and restart-safe. ``actor`` records
    provenance; ``generation`` is the generation in force at the change."""

    instance_id: str
    from_state: str | None
    to_state: str
    reason: str
    actor: str
    generation: int
    occurred_at: datetime
    event_id: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.instance_id, "instance_id")
        _require_nonempty(self.reason, "reason")
        if self.from_state is not None and self.from_state not in VALID_INSTANCE_STATES:
            raise ValueError(
                f"from_state must be None or one of {sorted(VALID_INSTANCE_STATES)}, "
                f"got {self.from_state!r}"
            )
        if self.to_state not in VALID_INSTANCE_STATES:
            raise ValueError(
                f"to_state must be one of {sorted(VALID_INSTANCE_STATES)}, "
                f"got {self.to_state!r}"
            )
        if self.actor not in VALID_EVENT_ACTORS:
            raise ValueError(
                f"actor must be one of {sorted(VALID_EVENT_ACTORS)}, "
                f"got {self.actor!r}"
            )
        _require_positive(self.generation, "generation")
        _require_tz_aware(self.occurred_at, "occurred_at")
        if self.event_id is not None:
            _require_nonempty(self.event_id, "event_id")
