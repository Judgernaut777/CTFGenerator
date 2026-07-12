"""Job-queue value types: ``Job``, ``JobLease``, ``JobTransition``.

Pure, frozen domain aggregates for the durable PostgreSQL-backed work queue
(ADR-003). A ``Job`` is keyed by ``job_id`` (a caller-supplied uuid string that
becomes the row PK, like ``LedgerSubmission.submission_id``); its dedupe
*business* key is ``idempotency_key`` (UNIQUE in the store, so a duplicate
enqueue surfaces as an IntegrityError the application layer collapses).

State machine (single source of truth: :data:`LEGAL_JOB_TRANSITIONS`; the
store mirrors it byte-equivalently in a plpgsql trigger):

* ``queued``      -> ``claimed`` (a worker won the SKIP LOCKED claim) or
  ``cancelled`` (operator cancel before dispatch).
* ``claimed``     -> ``running`` (worker started), ``queued`` (lease expired,
  requeued with backoff), ``cancelled``, or ``dead_letter`` (lease expired
  with the attempt budget exhausted).
* ``running``     -> ``succeeded``, ``failed`` (permanent, non-retryable
  error), ``queued`` (retryable failure / lease expiry), ``cancelled``
  (cooperative cancel), or ``dead_letter`` (retryable attempts exhausted).
* ``dead_letter`` -> ``queued`` only via the explicit operator requeue
  (``retry_dead_letter``), which resets the attempt budget.
* ``succeeded`` / ``failed`` / ``cancelled`` are terminal and frozen.

``failed`` means a *permanent* (non-retryable) error; ``dead_letter`` means
retryable attempts were exhausted (including repeated lease loss).

Security invariant: ``payload`` / ``result_json`` / ``error_detail`` carry
references and hashes only (artifact keys, build hashes, instance ids) --
never flags, tokens, provider keys, or worker credentials. Job rows are
persisted, backed up, and operator-visible; the queue schema is secret-free
by construction and the application service is the guard.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

# The twelve job types the execution plane understands (ADR-003). Stored as
# text + CHECK so new types can be added by migration.
VALID_JOB_TYPES = frozenset(
    {
        "build_challenge",
        "validate_challenge",
        "launch_instance",
        "stop_instance",
        "restart_instance",
        "reset_instance",
        "run_health_check",
        "run_intended_solver",
        "collect_logs",
        "expire_instance",
        "delete_runtime_resources",
        "run_agent_evaluation",
    }
)

VALID_JOB_STATUSES = frozenset(
    {
        "queued",
        "claimed",
        "running",
        "succeeded",
        "failed",
        "cancelled",
        "dead_letter",
    }
)

# Structured classification of a failure (jobs columns hold the latest; the
# append-only job_transitions history holds every attempt's).
VALID_JOB_ERROR_CLASSES = frozenset(
    {
        "transient",
        "timeout",
        "infrastructure",
        "validation",
        "internal",
        "lease_expired",
        "cancelled",
    }
)

# Legal state transitions (from -> allowed targets). Self-transitions (e.g. a
# heartbeat refreshing the lease while ``running``) are field updates, not
# transitions, and are permitted by the store for every non-terminal status.
LEGAL_JOB_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "queued": frozenset({"claimed", "cancelled"}),
    "claimed": frozenset({"running", "queued", "cancelled", "dead_letter"}),
    "running": frozenset({"succeeded", "failed", "queued", "cancelled", "dead_letter"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
    # The one sanctioned exit from dead_letter: the operator requeue.
    "dead_letter": frozenset({"queued"}),
}

# Statuses that end a job's lifecycle. dead_letter is terminal for the *worker*
# path but re-enterable by the operator requeue above.
TERMINAL_JOB_STATUSES = frozenset({"succeeded", "failed", "cancelled", "dead_letter"})


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_tz_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")


@dataclass(frozen=True)
class Job:
    """A durable unit of background work, keyed by ``job_id``.

    ``priority`` is ascending (lower is claimed first, default 100).
    ``required_capabilities`` must be a subset of a worker's capabilities for
    the worker to claim the job. ``competition_id`` (slug) and the
    ``(definition_slug, version_no)`` pair are optional audit linkage -- both
    halves of the version pair must be present or absent together.

    The fencing ``lease_token`` is deliberately *not* a field here: it is
    minted at claim time and travels only inside :class:`JobLease`, so a job
    read back through ``get()`` can never leak another worker's fence.
    """

    job_id: str
    job_type: str
    idempotency_key: str
    available_at: datetime
    status: str = "queued"
    priority: int = 100
    payload: Mapping[str, object] = field(default_factory=dict, compare=False)
    required_capabilities: tuple[str, ...] = ()
    attempt_count: int = 0
    max_attempts: int = 3
    backoff_base_seconds: int = 30
    claimed_by: str | None = None
    heartbeat_at: datetime | None = None
    lease_expires_at: datetime | None = None
    cancel_requested_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_class: str | None = None
    error_detail: str | None = None
    result_json: Mapping[str, object] | None = field(default=None, compare=False)
    result_ref: str | None = None
    log_ref: str | None = None
    competition_id: str | None = None
    definition_slug: str | None = None
    version_no: int | None = None
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.job_id, "job_id")
        if self.job_type not in VALID_JOB_TYPES:
            raise ValueError(
                f"job_type must be one of {sorted(VALID_JOB_TYPES)}, "
                f"got {self.job_type!r}"
            )
        if self.status not in VALID_JOB_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(VALID_JOB_STATUSES)}, "
                f"got {self.status!r}"
            )
        _require_nonempty(self.idempotency_key, "idempotency_key")
        _require_tz_aware(self.available_at, "available_at")
        if not isinstance(self.priority, int) or self.priority < 0:
            raise ValueError(f"priority must be an int >= 0, got {self.priority!r}")
        if not isinstance(self.payload, Mapping):
            raise ValueError("payload must be a mapping")
        if not isinstance(self.required_capabilities, tuple):
            raise ValueError("required_capabilities must be a tuple of strings")
        for cap in self.required_capabilities:
            _require_nonempty(cap, "required_capabilities entry")
        if not isinstance(self.max_attempts, int) or self.max_attempts < 1:
            raise ValueError(
                f"max_attempts must be an int >= 1, got {self.max_attempts!r}"
            )
        if (
            not isinstance(self.attempt_count, int)
            or self.attempt_count < 0
            or self.attempt_count > self.max_attempts
        ):
            raise ValueError(
                "attempt_count must be an int in [0, max_attempts], "
                f"got {self.attempt_count!r}"
            )
        if not isinstance(self.backoff_base_seconds, int) or self.backoff_base_seconds < 1:
            raise ValueError(
                f"backoff_base_seconds must be an int >= 1, "
                f"got {self.backoff_base_seconds!r}"
            )
        if self.error_class is not None and self.error_class not in VALID_JOB_ERROR_CLASSES:
            raise ValueError(
                f"error_class must be None or one of {sorted(VALID_JOB_ERROR_CLASSES)}, "
                f"got {self.error_class!r}"
            )
        if self.result_json is not None and not isinstance(self.result_json, Mapping):
            raise ValueError("result_json must be a mapping or None")
        if self.competition_id is not None:
            _require_nonempty(self.competition_id, "competition_id")
        if (self.definition_slug is None) != (self.version_no is None):
            raise ValueError(
                "definition_slug and version_no must be given together or not at all"
            )
        if self.definition_slug is not None:
            _require_nonempty(self.definition_slug, "definition_slug")
        if self.version_no is not None and (
            not isinstance(self.version_no, int) or self.version_no < 1
        ):
            raise ValueError(f"version_no must be an int >= 1, got {self.version_no!r}")


@dataclass(frozen=True)
class JobLease:
    """A won claim: the job plus the fencing token every subsequent mutation
    (start/heartbeat/complete/fail) must present. A stale token -- the job was
    reclaimed after lease expiry -- is rejected by the store, which is what
    makes duplicate delivery and zombie workers harmless."""

    job: Job
    lease_token: str
    lease_expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.job, Job):
            raise ValueError("job must be a Job")
        _require_nonempty(self.lease_token, "lease_token")
        _require_tz_aware(self.lease_expires_at, "lease_expires_at")


@dataclass(frozen=True)
class JobTransition:
    """One append-only entry in a job's state history (``from_status is None``
    marks the enqueue). Written in the same transaction as every state change,
    so the audit trail is transactional and restart-safe."""

    job_id: str
    from_status: str | None
    to_status: str
    attempt: int
    occurred_at: datetime
    worker_id: str | None = None
    error_class: str | None = None
    error_detail: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.job_id, "job_id")
        if self.from_status is not None and self.from_status not in VALID_JOB_STATUSES:
            raise ValueError(
                f"from_status must be None or one of {sorted(VALID_JOB_STATUSES)}, "
                f"got {self.from_status!r}"
            )
        if self.to_status not in VALID_JOB_STATUSES:
            raise ValueError(
                f"to_status must be one of {sorted(VALID_JOB_STATUSES)}, "
                f"got {self.to_status!r}"
            )
        if not isinstance(self.attempt, int) or self.attempt < 0:
            raise ValueError(f"attempt must be an int >= 0, got {self.attempt!r}")
        _require_tz_aware(self.occurred_at, "occurred_at")
        if self.worker_id is not None:
            _require_nonempty(self.worker_id, "worker_id")
        if self.error_class is not None and self.error_class not in VALID_JOB_ERROR_CLASSES:
            raise ValueError(
                f"error_class must be None or one of {sorted(VALID_JOB_ERROR_CLASSES)}, "
                f"got {self.error_class!r}"
            )
