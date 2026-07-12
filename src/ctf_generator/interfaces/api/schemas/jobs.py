"""Job DTOs + mappers (ops observability + control).

CRITICAL SECRET BOUNDARY. A :class:`Job` carries ``payload`` / ``result_json`` /
``error_detail`` / ``result_ref`` / ``log_ref`` -- fields that, while secret-free
*by convention* in the queue, are exactly where a flag, seed, or credential would
land if that convention were ever violated. The API therefore refuses to surface
any of them: the DTO exposes only the job's TYPE, lifecycle STATE, attempt
accounting, timestamps, audit linkage, and the structured ``error_class``
SUMMARY. The raw payload and any free-form detail are never mapped, so they can
never leak through a response.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ctf_generator.domain.work.models import Job


class JobListItem(BaseModel):
    job_id: str
    job_type: str
    status: str
    priority: int
    attempt_count: int
    max_attempts: int
    available_at: str
    created_at: str | None = None
    error_class: str | None = None
    competition_id: str | None = None
    definition_slug: str | None = None
    version_no: int | None = None


class JobResponse(JobListItem):
    started_at: str | None = None
    finished_at: str | None = None
    heartbeat_at: str | None = None
    lease_expires_at: str | None = None
    cancel_requested_at: str | None = None
    claimed_by: str | None = None


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def job_to_list_item(job: Job) -> dict[str, Any]:
    """Map a job to its public projection -- NEVER the payload, result_json,
    error_detail, or any ref (those may carry a flag/seed/credential)."""
    return {
        "job_id": job.job_id,
        "job_type": job.job_type,
        "status": job.status,
        "priority": job.priority,
        "attempt_count": job.attempt_count,
        "max_attempts": job.max_attempts,
        "available_at": job.available_at.isoformat(),
        "created_at": _iso(job.created_at),
        "error_class": job.error_class,
        "competition_id": job.competition_id,
        "definition_slug": job.definition_slug,
        "version_no": job.version_no,
    }


def job_to_response(job: Job) -> dict[str, Any]:
    body = job_to_list_item(job)
    body.update(
        started_at=_iso(job.started_at),
        finished_at=_iso(job.finished_at),
        heartbeat_at=_iso(job.heartbeat_at),
        lease_expires_at=_iso(job.lease_expires_at),
        cancel_requested_at=_iso(job.cancel_requested_at),
        claimed_by=job.claimed_by,
    )
    return body


def job_concurrency_payload(job: Job) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "status": job.status,
        "attempt_count": job.attempt_count,
    }
