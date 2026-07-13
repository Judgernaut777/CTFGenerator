"""Control-plane projector: fold a completed eval JOB's result onto its EvalRun.

WORKER vs CONTROL PLANE (ADR-001, M15b). The effectful eval runs on the WORKER,
which reports a SECRET-FREE advisory ``result_json`` on the ``run_agent_evaluation``
job (the allowlisted subset only). This projector is the CONTROL-PLANE fold: for
each still-non-terminal :class:`EvalRun` whose job has reached a terminal outcome,
it projects that outcome through :meth:`EvalRunService.record_result` -- which
RE-SANITIZES defensively (a planted ``ctf{...}`` is redacted a second time) and
freezes the record. It NEVER imports ``agent_eval``, never touches Docker, never
runs challenge code: it only moves an already-computed, secret-free result from
the operator-visible job row onto the EvalRun.

Wiring (narrowest correct). It is a STANDALONE service with a
:meth:`process_completed_eval_jobs` drain, mirroring the M7 score projector --
NOT folded into ``WorkerJobService.complete`` (that generic queue verb must stay
job-type-agnostic and free of eval semantics). A control-plane loop / CLI runs
the drain. It is driven by the set of non-terminal EvalRuns (there is no cursor);
each run is matched to its job by the deterministic idempotency key the service
minted at enqueue, so the mapping never drifts.

Idempotent + restart-safe. ``record_result`` freezes a terminal EvalRun, so a
second drain over the same completed job raises :class:`EvalRunConflictError` and
is skipped. All state is in the DB. ADVISORY: nothing here gates publication or a
competition (``record_result`` never blocks anything).
"""

from __future__ import annotations

from datetime import UTC, datetime

from ctf_generator.application.jobs.service import JobService
from ctf_generator.domain.work.models import Job

from .service import (
    EvalResultInput,
    EvalRunConflictError,
    EvalRunService,
    eval_job_idempotency_key,
)


def _default_clock() -> datetime:
    return datetime.now(UTC)


class EvalResultProjector:
    """Drain completed ``run_agent_evaluation`` jobs onto their EvalRuns."""

    def __init__(
        self,
        eval_runs: EvalRunService,
        jobs: JobService,
        *,
        clock=_default_clock,
    ) -> None:
        self._eval_runs = eval_runs
        self._jobs = jobs
        self._clock = clock

    def process_completed_eval_jobs(self) -> int:
        """One drain pass: for every non-terminal EvalRun whose job has reached a
        terminal outcome, project that outcome via ``record_result``. Returns the
        number of runs newly recorded (terminalized). A run whose job is still
        in flight is left for a later pass; an already-terminal run (raced by a
        concurrent drain) is skipped."""
        recorded = 0
        for run in self._eval_runs.list_non_terminal():
            key = eval_job_idempotency_key(
                run.definition_slug, run.version_no, run.profile, run.adversarial
            )
            job = self._jobs.get_by_idempotency_key(key)
            if job is None:
                continue  # self-healing enqueue may re-create it; try next pass
            result = self._result_input(job)
            if result is None:
                continue  # job not yet in a terminal outcome we can project
            try:
                self._eval_runs.record_result(run.eval_run_id, result, self._clock())
                recorded += 1
            except EvalRunConflictError:
                # Raced to terminal by a concurrent drain -- idempotent skip.
                continue
            except LookupError:
                # The run vanished between listing and recording; ignore.
                continue
        return recorded

    @staticmethod
    def _result_input(job: Job) -> EvalResultInput | None:
        """Map a terminal job to the allowlisted advisory input, or ``None`` when
        the job is not yet projectable.

        * ``succeeded`` -> the worker-reported secret-free ``result_json`` (an
          ``error`` field marks an advisory eval failure; otherwise the advisory
          scalars). ``record_result`` re-sanitizes ``notes``/``error``.
        * ``failed`` / ``dead_letter`` / ``cancelled`` -> a terminal non-success
          (queue-level failure or operator cancellation), not an eval measurement:
          record an advisory failure so the run RESOLVES (never wedges pending).
        * ``queued`` / ``claimed`` / ``running`` -> not ready.
        """
        if job.status == "succeeded":
            result_json = dict(job.result_json or {})
            notes = result_json.get("notes") or ()
            return EvalResultInput(
                solved=result_json.get("solved"),
                steps=result_json.get("steps"),
                success_dropped=result_json.get("success_dropped"),
                step_delta=result_json.get("step_delta"),
                blended_score=result_json.get("blended_score"),
                notes=tuple(notes),
                error=result_json.get("error"),
            )
        if job.status in ("failed", "dead_letter", "cancelled"):
            # A terminal, non-succeeded job (queue-level failure OR an operator
            # cancellation) resolves the run to a `failed` EvalRun so it can never
            # wedge as `pending` forever -- ``cancelled`` is terminal too, and
            # enqueue_idempotent would collide on the same key rather than re-queue,
            # so an unresolved run would be unrecoverable.
            return EvalResultInput(
                error=job.error_detail or f"eval job {job.status}"
            )
        return None
