"""Evaluation value types: ``EvalRun``.

The durable, operator-visible PLATFORM RECORD of one agent-evaluation of a
challenge version (M15 slice 15a). Today an eval is CLI-only throwaway JSON;
this aggregate turns a *request* to evaluate into a first-class record that a
worker (slice 15b) later completes with an ADVISORY result.

Keyed by ``eval_run_id`` (a caller-supplied uuid string that becomes the row
PK, like ``Job.job_id`` / ``LedgerSubmission.submission_id``). Its dedupe
*business* key is ``(definition_slug, version_no, profile, adversarial)`` --
one live run per (version, profile, adversarial), matching the enqueue
idempotency key, so a re-request collapses to the existing record.

SECRET-FREE BY CONSTRUCTION. This aggregate has NO flag / token / candidate-
answer / expected-flag field -- none exists to be populated. The only result
fields are the advisory outcome subset (solved / steps / success_dropped /
step_delta / blended_score) plus sanitized free-text ``notes`` / ``error``.
Even a completed run that solved the challenge stores only ``solved=True`` --
never *how*, never the flag. Eval-run rows are persisted, backed up, and
operator-visible; the schema is secret-free by construction and the
application service (which allowlists + redacts on ``record_result``) is the
guard.

ADVISORY / NEVER-GATES. An ``EvalRun`` is a record, not a gate. Nothing in the
domain, the service, or anywhere consumes an ``EvalRun`` to block publication
or a competition. A ``succeeded`` run with ``solved=True`` is just a data
point.

State machine (single source of truth: :data:`LEGAL_EVAL_TRANSITIONS`):

* ``pending``   -> ``running`` (a worker started) or straight to
  ``succeeded`` / ``failed`` (a synchronous completion).
* ``running``   -> ``succeeded`` (advisory result recorded) or ``failed``
  (a sanitized error recorded).
* ``succeeded`` / ``failed`` are terminal and frozen (re-record is a
  conflict, never a silent overwrite).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

# The named agent-eval configurations an EvalRun may target. A FROZEN COPY of
# the keys of ``ctf_generator.agent_eval.EVAL_PROFILES`` -- kept here (stdlib
# only) because the domain must never import the effectful ``agent_eval`` engine
# (architecture-boundary test). A host test asserts this set stays equal to
# ``agent_eval.EVAL_PROFILES`` so the two cannot silently drift.
VALID_EVAL_PROFILES = frozenset(
    {
        "one_shot_prompt",
        "writeup_replay",
        "tool_using_agent",
        "llm_agent",
    }
)

VALID_EVAL_RUN_STATUSES = frozenset({"pending", "running", "succeeded", "failed"})

# Statuses that end an eval run's lifecycle -- a terminal record is frozen.
TERMINAL_EVAL_RUN_STATUSES = frozenset({"succeeded", "failed"})

# Legal state transitions (from -> allowed targets). A self-transition is not a
# transition. The service is the primary guard; a BEFORE-UPDATE DB trigger is
# the backstop that forbids leaving a terminal state.
LEGAL_EVAL_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "pending": frozenset({"running", "succeeded", "failed"}),
    "running": frozenset({"succeeded", "failed"}),
    "succeeded": frozenset(),
    "failed": frozenset(),
}


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_tz_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")


@dataclass(frozen=True)
class EvalRun:
    """One agent-evaluation platform record, keyed by ``eval_run_id``.

    ``profile`` names one of :data:`VALID_EVAL_PROFILES`. ``adversarial`` marks
    the live-adversarial (scenario-engine-on) delta run. The advisory RESULT
    fields are all ``None`` until the run ``succeeded``; a ``failed`` run
    carries a sanitized ``error`` instead. ``completed_at`` is set iff the run
    is terminal. There is deliberately NO flag / token / answer field.
    """

    eval_run_id: str
    definition_slug: str
    version_no: int
    profile: str
    adversarial: bool
    status: str
    requested_at: datetime
    completed_at: datetime | None = None
    # -- advisory result (all None unless status == 'succeeded') --------------
    solved: bool | None = None
    steps: int | None = None
    success_dropped: bool | None = None
    step_delta: int | None = None
    blended_score: float | None = None
    notes: tuple[str, ...] = ()
    # -- failure (set only when status == 'failed'; sanitized, secret-free) ----
    error: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.eval_run_id, "eval_run_id")
        _require_nonempty(self.definition_slug, "definition_slug")
        if not isinstance(self.version_no, int) or self.version_no < 1:
            raise ValueError(f"version_no must be an int >= 1, got {self.version_no!r}")
        if self.profile not in VALID_EVAL_PROFILES:
            raise ValueError(
                f"profile must be one of {sorted(VALID_EVAL_PROFILES)}, "
                f"got {self.profile!r}"
            )
        if not isinstance(self.adversarial, bool):
            raise ValueError("adversarial must be a bool")
        if self.status not in VALID_EVAL_RUN_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(VALID_EVAL_RUN_STATUSES)}, "
                f"got {self.status!r}"
            )
        _require_tz_aware(self.requested_at, "requested_at")

        is_terminal = self.status in TERMINAL_EVAL_RUN_STATUSES
        # completed_at is set iff the record is terminal.
        if is_terminal == (self.completed_at is None):
            raise ValueError(
                "completed_at must be set iff status is terminal "
                f"(status={self.status!r}, completed_at={self.completed_at!r})"
            )
        if self.completed_at is not None:
            _require_tz_aware(self.completed_at, "completed_at")

        # The advisory result exists ONLY on a succeeded run. A pending/running/
        # failed run carries none of it (a failed run carries `error` instead).
        result_fields = {
            "solved": self.solved,
            "steps": self.steps,
            "success_dropped": self.success_dropped,
            "step_delta": self.step_delta,
            "blended_score": self.blended_score,
        }
        if self.status != "succeeded":
            populated = [name for name, value in result_fields.items() if value is not None]
            if populated:
                raise ValueError(
                    "advisory result fields are only set on a 'succeeded' run; "
                    f"status={self.status!r} but populated: {sorted(populated)}"
                )
        if self.solved is not None and not isinstance(self.solved, bool):
            raise ValueError("solved must be a bool or None")
        if self.steps is not None and (not isinstance(self.steps, int) or self.steps < 0):
            raise ValueError(f"steps must be an int >= 0 or None, got {self.steps!r}")
        if self.success_dropped is not None and not isinstance(self.success_dropped, bool):
            raise ValueError("success_dropped must be a bool or None")
        if self.step_delta is not None and not isinstance(self.step_delta, int):
            raise ValueError("step_delta must be an int or None")
        if self.blended_score is not None and not isinstance(
            self.blended_score, (int, float)
        ):
            raise ValueError("blended_score must be a number or None")

        if not isinstance(self.notes, tuple):
            raise ValueError("notes must be a tuple of strings")
        for note in self.notes:
            if not isinstance(note, str):
                raise ValueError("notes entries must be strings")

        # `error` is a failure record: present only on a failed run.
        if self.status == "failed":
            _require_nonempty(self.error, "error")
        elif self.error is not None:
            raise ValueError(
                f"error is only set on a 'failed' run; status={self.status!r}"
            )

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_EVAL_RUN_STATUSES
