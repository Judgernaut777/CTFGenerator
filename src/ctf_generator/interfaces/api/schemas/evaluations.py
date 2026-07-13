"""Eval-run DTOs + mappers (M15 evaluation lab).

An eval run is the durable, operator-visible record of one agent-evaluation of a
challenge version. These read DTOs expose the run's identity, target version,
lifecycle status, and the ADVISORY outcome subset (solved / steps /
success_dropped / step_delta / blended_score) plus sanitized notes/error.

SECRET-FREE: there is no flag/token/answer to surface -- the aggregate has none.
The DTO maps only the advisory fields, so nothing sensitive can leak here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ctf_generator.domain.evaluation.models import EvalRun


class EvalRunListItem(BaseModel):
    eval_run_id: str
    definition_slug: str
    version_no: int
    profile: str
    adversarial: bool
    status: str
    requested_at: str
    completed_at: str | None = None
    solved: bool | None = None


class EvalRunResponse(EvalRunListItem):
    steps: int | None = None
    success_dropped: bool | None = None
    step_delta: int | None = None
    blended_score: float | None = None
    notes: list[str] = []
    error: str | None = None


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def eval_run_to_list_item(run: EvalRun) -> dict[str, Any]:
    return {
        "eval_run_id": run.eval_run_id,
        "definition_slug": run.definition_slug,
        "version_no": run.version_no,
        "profile": run.profile,
        "adversarial": run.adversarial,
        "status": run.status,
        "requested_at": run.requested_at.isoformat(),
        "completed_at": _iso(run.completed_at),
        "solved": run.solved,
    }


def eval_run_to_response(run: EvalRun) -> dict[str, Any]:
    body = eval_run_to_list_item(run)
    body.update(
        {
            "steps": run.steps,
            "success_dropped": run.success_dropped,
            "step_delta": run.step_delta,
            "blended_score": run.blended_score,
            "notes": list(run.notes),
            "error": run.error,
        }
    )
    return body


def eval_run_concurrency_payload(run: EvalRun) -> dict[str, Any]:
    # The status + completion instant advance monotonically; the pair is a stable
    # ETag input for a record that only ever moves pending -> terminal.
    return {"eval_run_id": run.eval_run_id, "status": run.status}
