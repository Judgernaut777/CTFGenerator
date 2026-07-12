"""Worker enrollment, trust, and credential lifecycle (application layer).

``WorkerEnrollmentService`` owns the multi-aggregate transactions over
``Database.session_scope()`` (repositories flush; the UoW commits once):

* ``register_worker``  -- persists the *pending* identity only. Registration
  itself is authenticated by an operator bootstrap enrollment token from the
  environment, validated at the (M8) API layer -- it is never stored in this
  schema.
* ``approve_worker``   -- flips ``pending`` -> ``trusted`` AND issues the
  first credential in one transaction, so "has a valid credential" implies
  "was human-approved".
* ``rotate_credential``-- revokes the active credential and inserts its
  replacement in one transaction: the old token is invalid at the exact
  instant the new one exists (the partial UNIQUE makes a racing double
  rotation resolve to one ``IntegrityError``, never two live tokens).
* ``revoke_worker``    -- revokes the worker AND its active credential in one
  transaction.
* ``authenticate``     -- constant-time verification of a presented token.

Secrets: the service generates 256-bit random secrets (``secrets.token_hex``)
and persists only their sha256 hex. The plaintext travels once, inside the
returned :class:`IssuedCredential` (``repr``-suppressed). The service API
never accepts a caller-provided secret -- accepting one would silently
degrade the hash-at-rest scheme to a crackable password hash. Workers receive
exactly one artifact -- the opaque scoped bearer token -- never the
control-plane DSN and never any signing key (none exists in this scheme).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from ctf_generator.domain.execution.models import (
    CREDENTIAL_TOKEN_PREFIX,
    VALID_CREDENTIAL_SCOPES,
    IssuedCredential,
    Worker,
    WorkerCredential,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.worker_repository import (
    SqlAlchemyWorkerCredentialRepository,
    SqlAlchemyWorkerRegistry,
)

DEFAULT_CREDENTIAL_TTL = timedelta(hours=24)

_DEFAULT_SCOPES = (
    "jobs:claim",
    "jobs:heartbeat",
    "jobs:complete",
    "artifacts:pull",
    "instances:report",
    "instances:transition",
)


@dataclass(frozen=True)
class AuthenticatedWorker:
    """The successful result of ``authenticate``: the verified worker plus the
    credential's identity and grant, so a caller (the M8 worker-facing API) can
    enforce per-verb scoping without re-reading the credential."""

    worker: Worker
    credential_id: str
    scopes: tuple[str, ...]
    expires_at: datetime


class ScopeError(PermissionError):
    """A required scope is not carried by the authenticated credential."""


def require_scope(auth: AuthenticatedWorker, scope: str) -> None:
    """Raise :class:`ScopeError` unless ``auth`` carries ``scope``. The M8 API
    calls this before each queue verb (``jobs:claim`` / ``jobs:heartbeat`` /
    ``jobs:complete``)."""
    if scope not in auth.scopes:
        raise ScopeError(f"credential lacks required scope {scope!r}")


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def parse_token(token: str) -> tuple[str, str] | None:
    """Split a presented ``ctfw1.<credential_id>.<secret>`` token into
    ``(credential_id, secret)``, or ``None`` if malformed. Never raises and
    never logs the token."""
    if not isinstance(token, str):
        return None
    parts = token.split(".", 2)
    if len(parts) != 3 or parts[0] != CREDENTIAL_TOKEN_PREFIX:
        return None
    credential_id, secret = parts[1], parts[2]
    if not credential_id or not secret:
        return None
    return credential_id, secret


class WorkerEnrollmentService:
    """Owns worker registration, approval, rotation, revocation, and
    credential verification."""

    def __init__(self, database: Database) -> None:
        self._database = database

    # -- lifecycle -----------------------------------------------------------

    def register_worker(self, worker: Worker) -> Worker:
        """Persist a *pending* worker identity (no credential is issued --
        a pending worker must never be dispatchable-by-accident)."""
        with self._database.session_scope() as session:
            registry = SqlAlchemyWorkerRegistry(session)
            registry.add(worker)
            registered = registry.get(worker.name)
        if registered is None:  # pragma: no cover - inserted in the same UoW
            raise LookupError(f"worker registration lost: {worker.name!r}")
        return registered

    def approve_worker(
        self,
        name: str,
        now: datetime,
        ttl: timedelta = DEFAULT_CREDENTIAL_TTL,
        scopes: tuple[str, ...] = _DEFAULT_SCOPES,
    ) -> IssuedCredential:
        """Operator approval: trust flip + first credential, one UoW."""
        with self._database.session_scope() as session:
            SqlAlchemyWorkerRegistry(session).approve(name)
            return self._issue(session, name, now, ttl, scopes)

    def rotate_credential(
        self,
        name: str,
        now: datetime,
        ttl: timedelta = DEFAULT_CREDENTIAL_TTL,
        scopes: tuple[str, ...] = _DEFAULT_SCOPES,
    ) -> IssuedCredential:
        """Revoke the active credential (if any) and insert its replacement in
        ONE transaction -- no window with zero or two valid credentials."""
        with self._database.session_scope() as session:
            # Only a trusted worker may hold a live credential -- mirror
            # approve_worker's guard so rotation cannot resurrect a credential
            # for a pending or revoked worker.
            worker = SqlAlchemyWorkerRegistry(session).get(name)
            if worker is None or worker.trust_state != "trusted":
                raise LookupError(
                    f"worker {name!r} is not trusted; cannot rotate credential"
                )
            credentials = SqlAlchemyWorkerCredentialRepository(session)
            active = credentials.get_active_for_worker(name)
            if active is not None:
                credentials.revoke(active.credential_id, now)
            return self._issue(session, name, now, ttl, scopes)

    def revoke_worker(self, name: str, now: datetime) -> None:
        """Revoke the worker (terminal) AND its active credential, one UoW."""
        with self._database.session_scope() as session:
            SqlAlchemyWorkerRegistry(session).revoke(name, now)
            credentials = SqlAlchemyWorkerCredentialRepository(session)
            active = credentials.get_active_for_worker(name)
            if active is not None:
                credentials.revoke(active.credential_id, now)

    # -- verification ----------------------------------------------------------

    def authenticate(self, token: str, now: datetime) -> AuthenticatedWorker | None:
        """Verify a presented bearer token: constant-time hash comparison,
        then revocation, expiry, and the owning worker's trust/quarantine
        state. Returns an :class:`AuthenticatedWorker` (worker + credential id +
        scopes + expiry) on success, ``None`` on any failure (the caller learns
        nothing about *which* check failed)."""
        parsed = parse_token(token)
        if parsed is None:
            return None
        credential_id, secret = parsed
        presented_hash = _hash_secret(secret)
        with self._database.session_scope() as session:
            credential = SqlAlchemyWorkerCredentialRepository(session).get(
                credential_id
            )
            if credential is None:
                # Burn the comparison anyway so a missing credential is not
                # distinguishable by timing from a bad secret.
                hmac.compare_digest(presented_hash, _hash_secret(""))
                return None
            if not hmac.compare_digest(presented_hash, credential.token_hash):
                return None
            if credential.revoked_at is not None:
                return None
            if credential.expires_at <= now:
                return None
            worker = SqlAlchemyWorkerRegistry(session).get(credential.worker_name)
        if worker is None:
            return None
        if worker.trust_state != "trusted" or worker.quarantined_at is not None:
            return None
        return AuthenticatedWorker(
            worker=worker,
            credential_id=credential.credential_id,
            scopes=tuple(credential.scopes),
            expires_at=credential.expires_at,
        )

    # -- internals -------------------------------------------------------------

    @staticmethod
    def _issue(
        session,
        name: str,
        now: datetime,
        ttl: timedelta,
        scopes: tuple[str, ...],
    ) -> IssuedCredential:
        for scope in scopes:
            if scope not in VALID_CREDENTIAL_SCOPES:
                raise ValueError(f"unknown credential scope: {scope!r}")
        if ttl <= timedelta(0):
            raise ValueError("credential ttl must be positive")
        # Defense in depth: never issue a credential for a worker that is not
        # trusted in this same UoW (approve flips pending->trusted before this
        # call; rotate guards explicitly). A pending/revoked worker must never
        # end up holding a live credential.
        worker = SqlAlchemyWorkerRegistry(session).get(name)
        if worker is None or worker.trust_state != "trusted":
            raise LookupError(
                f"worker {name!r} is not trusted; cannot issue credential"
            )
        credential_id = str(uuid.uuid4())
        secret = secrets.token_hex(32)  # 256-bit server-generated machine secret
        credential = WorkerCredential(
            credential_id=credential_id,
            worker_name=name,
            token_hash=_hash_secret(secret),
            scopes=scopes,
            issued_at=now,
            expires_at=now + ttl,
        )
        SqlAlchemyWorkerCredentialRepository(session).add(credential)
        return IssuedCredential(
            credential_id=credential_id,
            worker_name=name,
            scopes=scopes,
            expires_at=credential.expires_at,
            secret=secret,
        )
