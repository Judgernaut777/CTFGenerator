"""Evaluation application services (M15): request an eval-run platform record
and record its ADVISORY result. The control plane NEVER runs the effectful eval
(Docker/LLM/agent) -- it enqueues a ``run_agent_evaluation`` job the worker
(slice 15b) claims with scoped credentials."""

from .service import (
    EvalResultInput,
    EvalRunConflictError,
    EvalRunService,
    EvalVersionNotPublishedError,
)

__all__ = [
    "EvalResultInput",
    "EvalRunConflictError",
    "EvalRunService",
    "EvalVersionNotPublishedError",
]
