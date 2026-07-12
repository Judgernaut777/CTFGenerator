"""Concrete SQLAlchemy repositories for worker identity & trust (M7).

``SqlAlchemyWorkerRegistry`` stores execution-plane worker identities keyed by
the business ``name``; all state moves (approve/revoke/quarantine/clear/drain/
resume) are explicit methods in the ChallengeVersionRepository publish/archive
style -- ``LookupError`` on a missing worker or an illegal source state.
``SqlAlchemyWorkerCredentialRepository`` stores hashed scoped credentials; the
partial UNIQUE index (one live credential per worker) makes rotation
race-proof, and the ``worker_credentials_freeze`` trigger is the DB backstop
for the revocation-stamp-only mutation rule.

Both take the caller's Session; FLUSH only, never commit/rollback. Domain
objects only ever cross the boundary.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.execution.models import Worker, WorkerCredential

from . import _resolve
from .mappers import (
    _as_uuid,
    to_utc,
    worker_credential_from_orm,
    worker_credential_to_orm,
    worker_from_orm,
    worker_to_orm,
)
from .models import Worker as WorkerRow
from .models import WorkerCredential as WorkerCredentialRow


class SqlAlchemyWorkerRegistry:
    """Worker identities with a 3-state trust axis plus drain/quarantine
    overlays. Explicit transitions only."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _row(self, name: str) -> WorkerRow:
        row = self._session.scalars(
            select(WorkerRow).where(WorkerRow.name == name)
        ).one_or_none()
        if row is None:
            raise LookupError(f"worker not found: {name!r}")
        return row

    def add(self, worker: Worker) -> None:
        """Insert a pending worker. Duplicate name -> IntegrityError."""
        self._session.add(worker_to_orm(worker))
        self._session.flush()

    def get(self, name: str) -> Worker | None:
        row = self._session.scalars(
            select(WorkerRow).where(WorkerRow.name == name)
        ).one_or_none()
        return worker_from_orm(row) if row is not None else None

    def list(self) -> list[Worker]:
        rows = self._session.scalars(
            select(WorkerRow).order_by(WorkerRow.name)
        ).all()
        return [worker_from_orm(row) for row in rows]

    def update_profile(self, worker: Worker) -> None:
        """Update the mutable profile fields, keyed by the immutable name.
        Trust/drain/quarantine are untouched (explicit transitions only)."""
        row = self._row(worker.name)
        worker_to_orm(worker, existing=row)
        self._session.flush()

    def heartbeat(self, name: str, at: datetime) -> None:
        row = self._row(name)
        row.last_heartbeat_at = to_utc(at)
        self._session.flush()

    def approve(self, name: str) -> None:
        row = self._row(name)
        if row.trust_state != "pending":
            raise LookupError(
                f"worker {name!r} is {row.trust_state!r}, not pending; cannot approve"
            )
        row.trust_state = "trusted"
        self._session.flush()

    def revoke(self, name: str, revoked_at: datetime) -> None:
        row = self._row(name)
        if row.trust_state == "revoked":
            raise LookupError(f"worker {name!r} is already revoked")
        row.trust_state = "revoked"
        row.revoked_at = to_utc(revoked_at)
        self._session.flush()

    def quarantine(self, name: str, at: datetime, reason: str) -> None:
        if not reason or not reason.strip():
            raise ValueError("quarantine reason must be a non-empty string")
        row = self._row(name)
        row.quarantined_at = to_utc(at)
        row.quarantine_reason = reason
        self._session.flush()

    def clear_quarantine(self, name: str) -> None:
        row = self._row(name)
        if row.quarantined_at is None:
            raise LookupError(f"worker {name!r} is not quarantined")
        row.quarantined_at = None
        row.quarantine_reason = None
        self._session.flush()

    def drain(self, name: str, at: datetime) -> None:
        row = self._row(name)
        row.drain_requested_at = to_utc(at)
        self._session.flush()

    def resume(self, name: str) -> None:
        row = self._row(name)
        if row.drain_requested_at is None:
            raise LookupError(f"worker {name!r} is not draining")
        row.drain_requested_at = None
        self._session.flush()


class SqlAlchemyWorkerCredentialRepository:
    """Hashed scoped worker credentials; near-append-only (revocation stamp is
    the single legal mutation, trigger-backstopped)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, credential: WorkerCredential) -> None:
        """Insert. A second live credential for the same worker raises
        IntegrityError via the partial UNIQUE (rotation race-proofing)."""
        worker_uuid = _resolve.worker_uuid(self._session, credential.worker_name)
        self._session.add(worker_credential_to_orm(credential, worker_uuid))
        self._session.flush()

    def _map(self, row: WorkerCredentialRow) -> WorkerCredential:
        worker_name = self._session.scalars(
            select(WorkerRow.name).where(WorkerRow.id == row.worker_id)
        ).one()
        return worker_credential_from_orm(row, worker_name)

    def get(self, credential_id: str) -> WorkerCredential | None:
        try:
            key = _as_uuid(credential_id)
        except (ValueError, AttributeError, TypeError):
            return None  # malformed id is a clean miss
        row = self._session.scalars(
            select(WorkerCredentialRow).where(WorkerCredentialRow.id == key)
        ).one_or_none()
        return self._map(row) if row is not None else None

    def get_active_for_worker(self, worker_name: str) -> WorkerCredential | None:
        worker_uuid = _resolve.worker_uuid(self._session, worker_name)
        row = self._session.scalars(
            select(WorkerCredentialRow).where(
                WorkerCredentialRow.worker_id == worker_uuid,
                WorkerCredentialRow.revoked_at.is_(None),
            )
        ).one_or_none()
        return worker_credential_from_orm(row, worker_name) if row is not None else None

    def list_for_worker(self, worker_name: str) -> list[WorkerCredential]:
        worker_uuid = _resolve.worker_uuid(self._session, worker_name)
        rows = self._session.scalars(
            select(WorkerCredentialRow)
            .where(WorkerCredentialRow.worker_id == worker_uuid)
            .order_by(WorkerCredentialRow.issued_at.asc())
        ).all()
        return [worker_credential_from_orm(row, worker_name) for row in rows]

    def revoke(self, credential_id: str, revoked_at: datetime) -> None:
        try:
            key = _as_uuid(credential_id)
        except (ValueError, AttributeError, TypeError):
            raise LookupError(f"credential not found: {credential_id!r}") from None
        row = self._session.scalars(
            select(WorkerCredentialRow)
            .where(WorkerCredentialRow.id == key)
            .with_for_update()
        ).one_or_none()
        if row is None:
            raise LookupError(f"credential not found: {credential_id!r}")
        if row.revoked_at is not None:
            raise LookupError(f"credential {credential_id!r} is already revoked")
        row.revoked_at = to_utc(revoked_at)
        self._session.flush()
