"""Operator/author-facing REPORTS: validation, build, competition-run, eval.

A report is a read-only VIEW computed from already-persisted data (challenge
versions + specs, the build-image registry, the score ledger + scoreboard, and
eval runs). A :class:`~ctf_generator.domain.reports.models.ReportSnapshot`
freezes one such view at a moment so it becomes an immutable, auditable record
(the "run report" a competition archives). No new source of truth -- reports
never author state, they only summarise it.
"""

from .models import (
    VALID_REPORT_TYPES,
    ReportSnapshot,
    report_subject,
)

__all__ = [
    "VALID_REPORT_TYPES",
    "ReportSnapshot",
    "report_subject",
]
