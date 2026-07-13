"""Control-plane eval-run service: request an eval + record its ADVISORY result.

``EvalRunService`` owns the unit of work. ``request_eval`` validates that the
target version EXISTS and is PUBLISHED, creates a PENDING :class:`EvalRun`
platform record, and enqueues a durable ``run_agent_evaluation`` job (idempotent,
references-only payload) that a worker (slice 15b) claims with scoped
credentials. The control plane NEVER runs the effectful eval (no Docker / LLM /
agent import here).

``record_result`` is the SECRET-FREE PROJECTION guard: it accepts ONLY the
advisory outcome subset (or a failure) via :class:`EvalResultInput`, constructs
the stored ``EvalRun`` from that allowlist ALONE, and SANITIZES free-text
notes/error so a ``ctf{...}``-like token can never be persisted -- even if a
caller plants one. A terminal record is frozen (re-record is a conflict).

ADVISORY / NEVER-GATES: nothing here (or anywhere) lets an ``EvalRun`` block
publication or a competition. ``record_result`` never raises "not allowed to
publish"; a ``succeeded`` run with ``solved=True`` is just a record.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.exc import IntegrityError

from ctf_generator.domain.evaluation.models import (
    TERMINAL_EVAL_RUN_STATUSES,
    VALID_EVAL_PROFILES,
    EvalRun,
)
from ctf_generator.domain.work.models import Job
from ctf_generator.infrastructure.database.challenge_version_repository import (
    SqlAlchemyChallengeVersionRepository,
)
from ctf_generator.infrastructure.database.eval_run_repository import (
    SqlAlchemyEvalRunRepository,
)
from ctf_generator.infrastructure.database.session import Database

from ..jobs.service import JobService

_EVAL_JOB_TYPE = "run_agent_evaluation"


def eval_job_idempotency_key(
    definition_slug: str, version_no: int, profile: str, adversarial: bool
) -> str:
    """The idempotency key naming the ``run_agent_evaluation`` job for exactly
    one (version, profile, adversarial) request. Shared by ``request_eval`` (the
    enqueue) and the :class:`EvalResultProjector` (which matches a non-terminal
    run back to its completed job) so the two can never drift out of format."""
    return f"eval:{definition_slug}:v{version_no}:{profile}:{adversarial}"

# Free-text notes/error reported by a (15b) worker are the ONLY vector by which a
# secret could reach this otherwise secret-free record, so redact defensively. Two
# secret classes named by the job invariant: (1) challenge FLAGS -- ctf{...}/
# FLAG{...}/key{...}, INCLUDING flags with spaces/newlines inside the braces (the
# `[^}]` class, not the old `[^{}\s]`, so a multi-word flag is caught); (2) provider
# API keys / bearer tokens (an LLM SDK exception repr can embed an sk-ant-.../sk-...
# key or an Authorization header). Kept local (the service must not import the
# effectful agent_eval engine, which owns the canonical FLAG_PATTERN).
_SECRET_PATTERNS = (
    re.compile(r"(?i)(?:ctf|flag|key|secret|pass|pwd)\{[^}]{0,400}\}"),
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{8,}"),
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{8,}=*"),
    re.compile(r"(?i)authorization[:=]\s*\S+"),
)
_REDACTED = "[redacted]"


class EvalVersionNotPublishedError(Exception):
    """The requested version exists but is not ``published`` -- an eval is only
    run against published content, never silently against a draft."""


class EvalRunConflictError(Exception):
    """A ``record_result`` arrived for an already-terminal (succeeded/failed)
    eval run. A terminal record is frozen; a silent overwrite would be a
    correctness hazard, so this surfaces as a conflict."""


def _sanitize_text(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    return text


def _sanitize_notes(notes: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_sanitize_text(note) for note in notes)


@dataclass(frozen=True)
class EvalResultInput:
    """The ALLOWLISTED advisory projection a completed eval reports back.

    This is the ONLY shape ``record_result`` accepts -- by being a fixed typed
    record it cannot smuggle a flag/token/answer field, and its free-text
    ``notes``/``error`` are sanitized before persistence. ``error`` set marks a
    failure (the numeric result is then ignored)."""

    solved: bool | None = None
    steps: int | None = None
    success_dropped: bool | None = None
    step_delta: int | None = None
    blended_score: float | None = None
    notes: tuple[str, ...] = ()
    error: str | None = None

    @property
    def is_failure(self) -> bool:
        return self.error is not None


class EvalRunService:
    """Request eval-run records + record their advisory results. Owns the UoW;
    the control plane never runs the eval."""

    def __init__(self, database: Database, *, jobs: JobService) -> None:
        self._database = database
        self._jobs = jobs

    # -- request -------------------------------------------------------------

    def request_eval(
        self,
        definition_slug: str,
        version_no: int,
        profile: str,
        *,
        adversarial: bool = False,
        now: datetime,
    ) -> tuple[EvalRun, bool]:
        """Create a PENDING eval-run record for a PUBLISHED version and enqueue
        the ``run_agent_evaluation`` job (references-only payload). Returns
        ``(eval_run, created)``: ``created`` is False when an identical prior
        request already made the record (idempotent -- no duplicate record, no
        second job). Raises :class:`LookupError` (missing version),
        :class:`EvalVersionNotPublishedError` (draft/archived), or
        :class:`ValueError` (unknown profile). Nothing is enqueued on any of
        those errors."""
        if profile not in VALID_EVAL_PROFILES:
            raise ValueError(
                f"unknown eval profile: {profile!r}; "
                f"choices: {sorted(VALID_EVAL_PROFILES)}"
            )

        eval_run_id = str(uuid.uuid4())
        candidate = EvalRun(
            eval_run_id=eval_run_id,
            definition_slug=definition_slug,
            version_no=version_no,
            profile=profile,
            adversarial=adversarial,
            status="pending",
            requested_at=now,
        )
        created = False
        try:
            with self._database.session_scope() as session:
                version = SqlAlchemyChallengeVersionRepository(session).get(
                    definition_slug, version_no
                )
                if version is None:
                    raise LookupError(
                        f"challenge version not found: "
                        f"{definition_slug!r} v{version_no}"
                    )
                if version.state != "published":
                    raise EvalVersionNotPublishedError(
                        f"challenge version {definition_slug!r} v{version_no} is "
                        f"{version.state!r}, not published; cannot evaluate"
                    )
                repo = SqlAlchemyEvalRunRepository(session)
                existing = repo.get_for_version(
                    definition_slug, version_no, profile, adversarial
                )
                if existing is not None:
                    stored = existing
                else:
                    repo.add(candidate)
                    stored = repo.get(eval_run_id)
                    created = True
        except IntegrityError:
            # Lost a concurrent create race: the record now exists (the winner's).
            with self._database.session_scope() as session:
                stored = SqlAlchemyEvalRunRepository(session).get_for_version(
                    definition_slug, version_no, profile, adversarial
                )
            assert stored is not None  # noqa: S101 - the collision proves it exists

        assert stored is not None  # noqa: S101

        # (Re-)assert the durable eval job for ANY non-terminal record, on EVERY
        # code path (fresh create, idempotent re-request, race-recovery). The row
        # insert and the enqueue are separate transactions, so a crash between them
        # could leave a PENDING record with no queued job; because enqueue_idempotent
        # collapses on the idempotency_key (same key + payload -> the existing job,
        # created=False), re-asserting here is a safe no-op when the job already
        # exists AND self-heals an orphaned run whose job was lost. A TERMINAL record
        # (the eval already ran) is never re-enqueued. Payload carries REFERENCES
        # ONLY (the job secret-free invariant) -- never a flag/seed/answer.
        if stored.status in {"pending", "running"}:
            job = Job(
                job_id=str(uuid.uuid4()),
                job_type=_EVAL_JOB_TYPE,
                idempotency_key=eval_job_idempotency_key(
                    definition_slug, version_no, profile, adversarial
                ),
                available_at=now,
                required_capabilities=(_EVAL_JOB_TYPE,),
                payload={
                    "eval_run_id": stored.eval_run_id,
                    "definition_slug": definition_slug,
                    "version_no": version_no,
                    "profile": profile,
                    "adversarial": adversarial,
                },
                definition_slug=definition_slug,
                version_no=version_no,
            )
            self._jobs.enqueue_idempotent(job, now)
        return stored, created

    # -- record result -------------------------------------------------------

    def record_result(
        self, eval_run_id: str, result: EvalResultInput, now: datetime
    ) -> EvalRun:
        """Project a completed eval's ADVISORY result onto its record.

        Transitions ``pending``/``running`` -> ``succeeded`` (with the
        allowlisted advisory subset) or ``failed`` (with a sanitized error).
        Constructs the stored record from the allowlist + sanitized notes/error
        ALONE -- a planted ``ctf{...}`` token is redacted and never persisted. A
        terminal record raises :class:`EvalRunConflictError` (no silent
        overwrite). NEVER blocks anything (advisory only)."""
        with self._database.session_scope() as session:
            repo = SqlAlchemyEvalRunRepository(session)
            current = repo.get(eval_run_id)
            if current is None:
                raise LookupError(f"eval run not found: {eval_run_id!r}")
            if current.status in TERMINAL_EVAL_RUN_STATUSES:
                raise EvalRunConflictError(
                    f"eval run {eval_run_id!r} is already {current.status!r} "
                    "(terminal); it cannot be re-recorded"
                )

            sanitized_notes = _sanitize_notes(result.notes)
            if result.is_failure:
                terminal = EvalRun(
                    eval_run_id=current.eval_run_id,
                    definition_slug=current.definition_slug,
                    version_no=current.version_no,
                    profile=current.profile,
                    adversarial=current.adversarial,
                    status="failed",
                    requested_at=current.requested_at,
                    completed_at=now,
                    notes=sanitized_notes,
                    error=_sanitize_text(result.error or "eval failed"),
                )
            else:
                terminal = EvalRun(
                    eval_run_id=current.eval_run_id,
                    definition_slug=current.definition_slug,
                    version_no=current.version_no,
                    profile=current.profile,
                    adversarial=current.adversarial,
                    status="succeeded",
                    requested_at=current.requested_at,
                    completed_at=now,
                    solved=result.solved,
                    steps=result.steps,
                    success_dropped=result.success_dropped,
                    step_delta=result.step_delta,
                    blended_score=result.blended_score,
                    notes=sanitized_notes,
                )
            repo.update(terminal)
            stored = repo.get(eval_run_id)
        assert stored is not None  # noqa: S101 - just updated in this UoW
        return stored

    # -- reads ---------------------------------------------------------------

    def get(self, eval_run_id: str) -> EvalRun | None:
        with self._database.session_scope() as session:
            return SqlAlchemyEvalRunRepository(session).get(eval_run_id)

    def list_for_version(
        self, definition_slug: str, version_no: int
    ) -> list[EvalRun]:
        with self._database.session_scope() as session:
            return SqlAlchemyEvalRunRepository(session).list_for_version(
                definition_slug, version_no
            )

    def list_non_terminal(self) -> list[EvalRun]:
        """Every eval run still awaiting a result (``pending``/``running``).
        Drives the :class:`EvalResultProjector` drain."""
        with self._database.session_scope() as session:
            return SqlAlchemyEvalRunRepository(session).list_non_terminal()
