"""Concrete SQLAlchemy implementation of the durable job queue (ADR-003).

``SqlAlchemyJobQueue`` implements the domain ``JobQueue`` protocol over the
``jobs`` + ``job_transitions`` tables. Claiming uses ``SELECT ... LIMIT 1 FOR
UPDATE SKIP LOCKED`` inside the caller's session/transaction: the row lock
means a claimable row is visible to at most one uncommitted claimer, SKIP
LOCKED makes every rival skip rather than block or deadlock, and after commit
the row no longer satisfies ``status='queued'`` -- so a job can never be
handed out twice. The known SKIP LOCKED + ORDER BY caveat (a locked-and-
skipped row causes local priority reordering under contention) is a
scheduling-quality property, not a correctness one; no invariant depends on
strict priority order.

Every fenced method (``start``/``heartbeat``/``complete``/``fail``) requires
the ``lease_token`` minted at claim; a stale token raises ``LookupError`` and
changes nothing -- duplicate delivery becomes at-least-once execution with
exactly-once state transition. All ``now`` values are caller-passed (the
repository never reads a clock). Takes the caller's Session; FLUSH only, never
commit/rollback -- ``Database.session_scope()`` is the unit of work. Returns
domain objects only; ORM rows never escape.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from ctf_generator.domain.work.models import (
    VALID_JOB_ERROR_CLASSES,
    Job,
    JobLease,
    JobTransition,
)

from . import _resolve
from .mappers import (
    _as_uuid,
    job_from_orm,
    job_to_orm,
    job_transition_from_orm,
    job_transition_to_orm,
    to_utc,
)
from .models import (
    ChallengeDefinition as ChallengeDefinitionRow,
)
from .models import (
    ChallengeVersion as ChallengeVersionRow,
)
from .models import (
    Competition,
)
from .models import (
    Job as JobRow,
)
from .models import (
    JobTransition as JobTransitionRow,
)

# Requeue backoff is capped so an old job cannot exile itself for hours.
_MAX_BACKOFF_SECONDS = 3600


class SqlAlchemyJobQueue:
    """Durable PostgreSQL job queue: predicate-based claiming, fencing leases,
    exponential-backoff retries, dead-letter, and an append-only transition
    history written in the same transaction as every state change."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- helpers -------------------------------------------------------------

    def _audit_refs(
        self, row: JobRow
    ) -> tuple[str | None, str | None, int | None]:
        """Business keys for the optional audit linkage (two point lookups --
        claim/reap lock only the jobs row, so no join under FOR UPDATE)."""
        competition_slug: str | None = None
        definition_slug: str | None = None
        version_no: int | None = None
        if row.competition_id is not None:
            competition_slug = self._session.scalars(
                select(Competition.slug).where(Competition.id == row.competition_id)
            ).one()
        if row.challenge_version_id is not None:
            definition_slug, version_no = self._session.execute(
                select(ChallengeDefinitionRow.slug, ChallengeVersionRow.version_no)
                .join(
                    ChallengeVersionRow,
                    ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
                )
                .where(ChallengeVersionRow.id == row.challenge_version_id)
            ).one()
        return competition_slug, definition_slug, version_no

    def _to_domain(self, row: JobRow) -> Job:
        competition_slug, definition_slug, version_no = self._audit_refs(row)
        return job_from_orm(row, competition_slug, definition_slug, version_no)

    def _audit_refs_batch(
        self, rows: Sequence[JobRow]
    ) -> tuple[dict[uuid.UUID, str], dict[uuid.UUID, tuple[str, int]]]:
        """Batch form of ``_audit_refs``: resolves the audit-linkage business
        keys for many rows with two queries TOTAL (one ``IN`` per referenced
        table) instead of up to two point SELECTs per row -- avoids the N+1
        that list paths (``list_dead_letter``, ``reap_expired``) otherwise
        pay per row. The lookups still run as separate follow-up queries
        after the caller's locking SELECT has already fetched ``rows`` --
        claim/reap lock only the jobs row via FOR UPDATE, so no JOIN may be
        folded into that locking SELECT itself."""
        competition_ids = {
            row.competition_id for row in rows if row.competition_id is not None
        }
        version_ids = {
            row.challenge_version_id
            for row in rows
            if row.challenge_version_id is not None
        }
        competition_slugs: dict[uuid.UUID, str] = {}
        if competition_ids:
            competition_slugs = dict(
                self._session.execute(
                    select(Competition.id, Competition.slug).where(
                        Competition.id.in_(competition_ids)
                    )
                ).all()
            )
        version_refs: dict[uuid.UUID, tuple[str, int]] = {}
        if version_ids:
            version_refs = {
                version_id: (definition_slug, version_no)
                for definition_slug, version_no, version_id in self._session.execute(
                    select(
                        ChallengeDefinitionRow.slug,
                        ChallengeVersionRow.version_no,
                        ChallengeVersionRow.id,
                    )
                    .join(
                        ChallengeVersionRow,
                        ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
                    )
                    .where(ChallengeVersionRow.id.in_(version_ids))
                ).all()
            }
        return competition_slugs, version_refs

    def _to_domain_many(self, rows: Sequence[JobRow]) -> list[Job]:
        """Batch form of ``_to_domain`` for multi-row list paths -- resolves
        audit refs for every row with the two queries from
        ``_audit_refs_batch`` rather than the N+1 that per-row ``_to_domain``
        would issue."""
        competition_slugs, version_refs = self._audit_refs_batch(rows)
        result: list[Job] = []
        for row in rows:
            competition_slug = (
                competition_slugs[row.competition_id]
                if row.competition_id is not None
                else None
            )
            if row.challenge_version_id is not None:
                definition_slug, version_no = version_refs[row.challenge_version_id]
            else:
                definition_slug, version_no = None, None
            result.append(job_from_orm(row, competition_slug, definition_slug, version_no))
        return result

    def _record(
        self,
        row: JobRow,
        from_status: str | None,
        to_status: str,
        occurred_at: datetime,
        *,
        worker_id: str | None = None,
        error_class: str | None = None,
        error_detail: str | None = None,
    ) -> None:
        """Append the job_transitions row in the same transaction as the state
        change (the transactional, restart-safe audit trail)."""
        transition = JobTransition(
            job_id=str(row.id),
            from_status=from_status,
            to_status=to_status,
            attempt=row.attempt_count,
            occurred_at=occurred_at,
            worker_id=worker_id,
            error_class=error_class,
            error_detail=error_detail,
        )
        self._session.add(job_transition_to_orm(transition, row.id))

    def _fenced_row(self, job_id: str, lease_token: str) -> JobRow:
        """Lock and return the job row iff ``lease_token`` is the current
        fence. A missing job or a stale/mismatched token raises LookupError
        and changes nothing (the zombie-worker guarantee)."""
        try:
            job_key = _as_uuid(job_id)
            token_key = _as_uuid(lease_token)
        except (ValueError, AttributeError, TypeError):
            raise LookupError(f"no lease held for job {job_id!r}") from None
        row = self._session.scalars(
            select(JobRow)
            .where(JobRow.id == job_key, JobRow.lease_token == token_key)
            .with_for_update()
        ).one_or_none()
        if row is None:
            raise LookupError(f"no lease held for job {job_id!r} (stale token?)")
        return row

    def _locked_row(self, job_id: str) -> JobRow:
        try:
            job_key = _as_uuid(job_id)
        except (ValueError, AttributeError, TypeError):
            raise LookupError(f"job not found: {job_id!r}") from None
        row = self._session.scalars(
            select(JobRow).where(JobRow.id == job_key).with_for_update()
        ).one_or_none()
        if row is None:
            raise LookupError(f"job not found: {job_id!r}")
        return row

    @staticmethod
    def _clear_lease(row: JobRow) -> None:
        row.claimed_by = None
        row.lease_token = None
        row.lease_expires_at = None
        row.heartbeat_at = None

    @staticmethod
    def _backoff_seconds(row: JobRow) -> int:
        """Exponential backoff from the attempt just spent: base * 2^(n-1),
        capped at one hour."""
        exponent = max(row.attempt_count - 1, 0)
        return min(row.backoff_base_seconds * (2**exponent), _MAX_BACKOFF_SECONDS)

    def _requeue_or_dead_letter(
        self,
        row: JobRow,
        now: datetime,
        error_class: str,
        error_detail: str | None,
    ) -> None:
        """Shared retry path for retryable failures and lease expiry: requeue
        with backoff, or dead-letter when the attempt budget is exhausted.

        If a cancel was requested while the job was claimed/running, the cancel
        wins over any requeue/dead-letter (claimed->cancelled and
        running->cancelled are both legal): a cancel-requested job whose lease
        expires must not be re-dispatched."""
        from_status = row.status
        worker_id = row.claimed_by
        if row.cancel_requested_at is not None:
            row.status = "cancelled"
            row.finished_at = to_utc(now)
            row.error_class = error_class
            row.error_detail = error_detail
            self._clear_lease(row)
            self._record(
                row,
                from_status,
                "cancelled",
                now,
                worker_id=worker_id,
                error_class=error_class,
                error_detail=error_detail,
            )
            return
        if row.attempt_count >= row.max_attempts:
            row.status = "dead_letter"
            row.finished_at = to_utc(now)
            row.error_class = error_class
            row.error_detail = error_detail
            self._clear_lease(row)
            row.started_at = None
            self._record(
                row,
                from_status,
                "dead_letter",
                now,
                worker_id=worker_id,
                error_class=error_class,
                error_detail=error_detail,
            )
        else:
            row.status = "queued"
            row.available_at = to_utc(now) + timedelta(
                seconds=self._backoff_seconds(row)
            )
            row.error_class = error_class
            row.error_detail = error_detail
            self._clear_lease(row)
            row.started_at = None
            self._record(
                row,
                from_status,
                "queued",
                now,
                worker_id=worker_id,
                error_class=error_class,
                error_detail=error_detail,
            )

    # -- protocol ------------------------------------------------------------

    def enqueue(self, job: Job, now: datetime | None = None) -> Job:
        """Insert a ``queued`` job (duplicate ``idempotency_key`` ->
        IntegrityError at flush) and its enqueue transition.

        The enqueue transition is recorded at the caller-passed ``now`` (the
        instant the job was enqueued); ``available_at`` is only the dispatch
        gate, not the enqueue instant, so a future-dated ``available_at`` no
        longer back-dates the audit trail. ``now`` defaults to ``available_at``
        for backward compatibility."""
        competition_uuid = _resolve.competition_uuid_optional(
            self._session, job.competition_id
        )
        version_uuid = _resolve.version_uuid_optional(
            self._session, job.definition_slug, job.version_no
        )
        row = job_to_orm(job, competition_uuid, version_uuid)
        self._session.add(row)
        self._session.flush()
        self._record(row, None, "queued", now if now is not None else job.available_at)
        self._session.flush()
        return job_from_orm(
            row, job.competition_id, job.definition_slug, job.version_no
        )

    def get(self, job_id: str) -> Job | None:
        try:
            key = _as_uuid(job_id)
        except (ValueError, AttributeError, TypeError):
            return None  # malformed id is a clean miss
        row = self._session.scalars(
            select(JobRow).where(JobRow.id == key)
        ).one_or_none()
        return self._to_domain(row) if row is not None else None

    def get_by_idempotency_key(self, key: str) -> Job | None:
        row = self._session.scalars(
            select(JobRow).where(JobRow.idempotency_key == key)
        ).one_or_none()
        return self._to_domain(row) if row is not None else None

    def claim(
        self,
        worker_id: str,
        capabilities: frozenset[str],
        lease_seconds: int,
        now: datetime,
    ) -> JobLease | None:
        """Claim the best available job the worker can execute, or ``None``.

        The explicit CAST of the capability array is required: psycopg cannot
        infer the type of an empty Python list, so a capability-free worker
        would otherwise crash on claim.
        """
        caps_param = sa.cast(
            sa.literal(sorted(capabilities), type_=postgresql.ARRAY(sa.Text)),
            postgresql.ARRAY(sa.Text),
        )
        row = self._session.scalars(
            select(JobRow)
            .where(
                JobRow.status == "queued",
                JobRow.available_at <= to_utc(now),
                JobRow.required_capabilities.contained_by(caps_param),
                # Defense in depth: a cancel-requested queued job (a requeue
                # that raced a cancel stamp) must never be re-dispatched.
                JobRow.cancel_requested_at.is_(None),
            )
            .order_by(JobRow.priority.asc(), JobRow.available_at.asc(), JobRow.created_at.asc())
            .limit(1)
            .with_for_update(skip_locked=True)
        ).one_or_none()
        if row is None:
            return None
        lease_token = uuid.uuid4()
        expires = to_utc(now) + timedelta(seconds=lease_seconds)
        row.status = "claimed"
        row.claimed_by = worker_id
        row.lease_token = lease_token
        row.lease_expires_at = expires
        row.heartbeat_at = to_utc(now)
        row.attempt_count = row.attempt_count + 1
        self._record(row, "queued", "claimed", now, worker_id=worker_id)
        self._session.flush()
        return JobLease(
            job=self._to_domain(row),
            lease_token=str(lease_token),
            lease_expires_at=expires,
        )

    def start(self, job_id: str, lease_token: str, now: datetime) -> None:
        row = self._fenced_row(job_id, lease_token)
        if row.status != "claimed":
            raise LookupError(
                f"job {job_id!r} is {row.status!r}, not claimed; cannot start"
            )
        row.status = "running"
        row.started_at = to_utc(now)
        self._record(row, "claimed", "running", now, worker_id=row.claimed_by)
        self._session.flush()

    def heartbeat(
        self, job_id: str, lease_token: str, lease_seconds: int, now: datetime
    ) -> bool:
        row = self._fenced_row(job_id, lease_token)
        row.lease_expires_at = to_utc(now) + timedelta(seconds=lease_seconds)
        row.heartbeat_at = to_utc(now)
        self._session.flush()
        return row.cancel_requested_at is not None

    def complete(
        self,
        job_id: str,
        lease_token: str,
        result_json: dict | None,
        result_ref: str | None,
        log_ref: str | None,
        now: datetime,
    ) -> None:
        row = self._fenced_row(job_id, lease_token)
        if row.status != "running":
            raise LookupError(
                f"job {job_id!r} is {row.status!r}, not running; cannot complete"
            )
        worker_id = row.claimed_by
        row.status = "succeeded"
        row.finished_at = to_utc(now)
        row.result_json = dict(result_json) if result_json is not None else None
        row.result_ref = result_ref
        row.log_ref = log_ref
        self._clear_lease(row)
        self._record(row, "running", "succeeded", now, worker_id=worker_id)
        self._session.flush()

    def fail(
        self,
        job_id: str,
        lease_token: str,
        error_class: str,
        error_detail: str | None,
        retryable: bool,
        now: datetime,
    ) -> Job:
        if error_class not in VALID_JOB_ERROR_CLASSES:
            raise ValueError(
                f"error_class must be one of {sorted(VALID_JOB_ERROR_CLASSES)}, "
                f"got {error_class!r}"
            )
        row = self._fenced_row(job_id, lease_token)
        worker_id = row.claimed_by
        if error_class == "cancelled":
            # The cooperative-cancel acknowledgment: the worker observed the
            # cancel request (via heartbeat) and stopped. A worker that learns
            # of the cancel while still 'claimed' (before start) can also
            # acknowledge it, so both claimed->cancelled and running->cancelled
            # are accepted (matching the domain transition matrix).
            if row.status not in ("claimed", "running"):
                raise LookupError(
                    f"job {job_id!r} is {row.status!r}, not claimed/running; "
                    "cannot cancel"
                )
            from_status = row.status
            row.status = "cancelled"
            row.finished_at = to_utc(now)
            row.error_class = error_class
            row.error_detail = error_detail
            self._clear_lease(row)
            self._record(
                row,
                from_status,
                "cancelled",
                now,
                worker_id=worker_id,
                error_class=error_class,
                error_detail=error_detail,
            )
            self._session.flush()
            return self._to_domain(row)
        if row.status != "running":
            raise LookupError(
                f"job {job_id!r} is {row.status!r}, not running; cannot fail"
            )
        if not retryable:
            row.status = "failed"
            row.finished_at = to_utc(now)
            row.error_class = error_class
            row.error_detail = error_detail
            self._clear_lease(row)
            self._record(
                row,
                "running",
                "failed",
                now,
                worker_id=worker_id,
                error_class=error_class,
                error_detail=error_detail,
            )
        else:
            self._requeue_or_dead_letter(row, now, error_class, error_detail)
        self._session.flush()
        return self._to_domain(row)

    def request_cancel(self, job_id: str, now: datetime) -> Job:
        row = self._locked_row(job_id)
        if row.status == "queued":
            row.status = "cancelled"
            row.cancel_requested_at = to_utc(now)
            row.finished_at = to_utc(now)
            self._record(row, "queued", "cancelled", now)
        elif row.status in ("claimed", "running"):
            # Cooperative: the worker learns of it from heartbeat()'s return
            # value and transitions to cancelled itself.
            row.cancel_requested_at = to_utc(now)
        else:
            raise LookupError(
                f"job {job_id!r} is {row.status!r}; cannot cancel a terminal job"
            )
        self._session.flush()
        return self._to_domain(row)

    def reap_expired(self, now: datetime, limit: int = 100) -> list[Job]:
        rows = self._session.scalars(
            select(JobRow)
            .where(
                JobRow.status.in_(("claimed", "running")),
                JobRow.lease_expires_at < to_utc(now),
            )
            .order_by(JobRow.lease_expires_at.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).all()
        for row in rows:
            self._requeue_or_dead_letter(row, now, "lease_expired", None)
        self._session.flush()
        return self._to_domain_many(rows)

    def list_dead_letter(self) -> list[Job]:
        rows = self._session.scalars(
            select(JobRow)
            .where(JobRow.status == "dead_letter")
            .order_by(JobRow.finished_at.asc())
        ).all()
        return self._to_domain_many(rows)

    def retry_dead_letter(self, job_id: str, now: datetime) -> Job:
        row = self._locked_row(job_id)
        if row.status != "dead_letter":
            raise LookupError(
                f"job {job_id!r} is {row.status!r}, not dead_letter; cannot retry"
            )
        row.status = "queued"
        row.attempt_count = 0  # the operator requeue resets the attempt budget
        row.available_at = to_utc(now)
        row.finished_at = None
        row.error_class = None
        row.error_detail = None
        # The operator requeue also clears any prior cancel signal, so a
        # requeued job is genuinely re-dispatchable rather than silently
        # cancel-blocked.
        row.cancel_requested_at = None
        self._record(row, "dead_letter", "queued", now)
        self._session.flush()
        return self._to_domain(row)

    # -- audit ---------------------------------------------------------------

    def list_transitions(self, job_id: str) -> list[JobTransition]:
        """The append-only per-attempt history for one job, oldest first."""
        try:
            key = _as_uuid(job_id)
        except (ValueError, AttributeError, TypeError):
            return []
        rows = self._session.scalars(
            select(JobTransitionRow)
            .where(JobTransitionRow.job_id == key)
            .order_by(JobTransitionRow.occurred_at.asc(), JobTransitionRow.created_at.asc())
        ).all()
        return [job_transition_from_orm(row) for row in rows]
