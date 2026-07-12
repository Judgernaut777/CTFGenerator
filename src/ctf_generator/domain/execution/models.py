"""Worker identity & trust value types: ``Worker``, ``WorkerCredential``,
``IssuedCredential``.

Pure, frozen domain aggregates. A ``Worker`` is keyed by its unique business
``name`` (an operator/self-assigned slug, like ``Team.name``). Trust is a
three-state machine on one axis -- ``pending`` -> ``trusted`` -> ``revoked``
(revoked terminal) -- while *drain* (stop claiming, finish leases) and
*quarantine* (fence immediately) are orthogonal, reversible operational
overlays expressed as timestamps. Dispatch eligibility is the conjunction:
``trusted`` AND not quarantined AND not draining AND heartbeat fresh.

``WorkerCredential`` is the short-lived scoped credential. Only the sha256
hex of a server-generated 256-bit secret is ever persisted (``token_hash``);
the plaintext exists once, in the :class:`IssuedCredential` return value,
whose ``secret`` field is ``repr``-suppressed so accidental logging never
prints it. The presented token has the form ``ctfw1.<credential_id>.<secret>``
-- the ``ctfw1.`` prefix guarantees a plaintext token can never satisfy the
store's 64-hex-chars CHECK on ``token_hash``, making the
"accidentally stored the plaintext" mistake structurally impossible.

Unsalted sha256 is sufficient *only* because secrets are server-generated
256-bit random values (machine secrets, not passwords); no API may ever accept
an operator-chosen token value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

VALID_TRUST_STATES = frozenset({"pending", "trusted", "revoked"})

# Container runtimes the execution plane supports (ADR-004: rootless only).
VALID_RUNTIME_TYPES = frozenset(
    {"docker-rootless", "podman-rootless", "buildkit-rootless"}
)

# Scopes a worker credential may carry. The vocabulary is intentionally small:
# workers claim jobs, keep leases alive, report results, and pull artifacts --
# nothing else. (``artifacts:pull`` reserves the vocabulary; per-job scoped
# artifact handles are an M8 slice.)
VALID_CREDENTIAL_SCOPES = frozenset(
    {"jobs:claim", "jobs:heartbeat", "jobs:complete", "artifacts:pull"}
)

# Prefix of the presented (plaintext) bearer token: ctfw1.<credential_id>.<secret>.
# (A format marker, not a secret -- the S105 lint is a false positive here.)
CREDENTIAL_TOKEN_PREFIX = "ctfw1"  # noqa: S105

_HEX64 = frozenset("0123456789abcdef")


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_tz_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")


@dataclass(frozen=True)
class Worker:
    """An execution-plane host identity, keyed by ``name``.

    ``capabilities`` are the job types the worker can execute;
    ``architectures`` the platforms it can build/run for. Both are non-empty
    tuples (stored as text[] in the schema). ``capacity`` is the number of
    concurrent jobs the worker advertises. Trust/drain/quarantine invariants
    mirror the store's CHECK constraints exactly.
    """

    name: str
    runtime_type: str
    architectures: tuple[str, ...]
    capabilities: tuple[str, ...]
    capacity: int
    version: str
    trust_state: str = "pending"
    revoked_at: datetime | None = None
    drain_requested_at: datetime | None = None
    quarantined_at: datetime | None = None
    quarantine_reason: str | None = None
    last_heartbeat_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.name, "name")
        if self.runtime_type not in VALID_RUNTIME_TYPES:
            raise ValueError(
                f"runtime_type must be one of {sorted(VALID_RUNTIME_TYPES)}, "
                f"got {self.runtime_type!r}"
            )
        if not isinstance(self.architectures, tuple) or not self.architectures:
            raise ValueError("architectures must be a non-empty tuple")
        for arch in self.architectures:
            _require_nonempty(arch, "architectures entry")
        if not isinstance(self.capabilities, tuple) or not self.capabilities:
            raise ValueError("capabilities must be a non-empty tuple")
        for cap in self.capabilities:
            _require_nonempty(cap, "capabilities entry")
        if not isinstance(self.capacity, int) or self.capacity < 1:
            raise ValueError(f"capacity must be an int >= 1, got {self.capacity!r}")
        _require_nonempty(self.version, "version")
        if self.trust_state not in VALID_TRUST_STATES:
            raise ValueError(
                f"trust_state must be one of {sorted(VALID_TRUST_STATES)}, "
                f"got {self.trust_state!r}"
            )
        if (self.trust_state == "revoked") != (self.revoked_at is not None):
            raise ValueError(
                "revoked_at must be set iff trust_state == 'revoked'"
            )
        if (self.quarantined_at is None) != (self.quarantine_reason is None):
            raise ValueError(
                "quarantined_at and quarantine_reason must be set together"
            )
        if self.quarantine_reason is not None:
            _require_nonempty(self.quarantine_reason, "quarantine_reason")


@dataclass(frozen=True)
class WorkerCredential:
    """A short-lived scoped bearer credential for one worker.

    Keyed by ``credential_id`` (application-assigned uuid string, the row PK).
    ``token_hash`` is the sha256 hex of the secret -- the plaintext is NEVER
    persisted. At most one credential per worker is live (``revoked_at IS
    NULL``); rotation revokes the old and inserts the new atomically.
    """

    credential_id: str
    worker_name: str
    token_hash: str
    scopes: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.credential_id, "credential_id")
        _require_nonempty(self.worker_name, "worker_name")
        if (
            not isinstance(self.token_hash, str)
            or len(self.token_hash) != 64
            or not set(self.token_hash) <= _HEX64
        ):
            raise ValueError(
                "token_hash must be 64 lowercase hex chars (sha256 of the secret; "
                "never store a plaintext token)"
            )
        if not isinstance(self.scopes, tuple) or not self.scopes:
            raise ValueError("scopes must be a non-empty tuple")
        for scope in self.scopes:
            if scope not in VALID_CREDENTIAL_SCOPES:
                raise ValueError(
                    f"scopes entries must be in {sorted(VALID_CREDENTIAL_SCOPES)}, "
                    f"got {scope!r}"
                )
        _require_tz_aware(self.issued_at, "issued_at")
        _require_tz_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")


@dataclass(frozen=True)
class IssuedCredential:
    """The one-time return value carrying a freshly minted plaintext secret.

    ``secret`` is ``repr``-suppressed so logging the object never prints it.
    ``token()`` renders the presented bearer form the worker stores.
    """

    credential_id: str
    worker_name: str
    scopes: tuple[str, ...]
    expires_at: datetime
    secret: str = field(repr=False, default="")

    def __post_init__(self) -> None:
        _require_nonempty(self.credential_id, "credential_id")
        _require_nonempty(self.worker_name, "worker_name")
        _require_nonempty(self.secret, "secret")

    def token(self) -> str:
        """The presented bearer token: ``ctfw1.<credential_id>.<secret>``."""
        return f"{CREDENTIAL_TOKEN_PREFIX}.{self.credential_id}.{self.secret}"
