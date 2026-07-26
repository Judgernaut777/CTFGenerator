"""Report domain value types (pure; no SQLAlchemy, no I/O).

A report is a read-only summary computed from already-persisted data. Four kinds
ship:

* ``validation``      -- a challenge version's static-validation summary.
* ``build``           -- a version's build-image registry state (primary + stack).
* ``competition_run`` -- a competition's final standings + solve timeline.
* ``eval``            -- a version's agent-evaluation run results.

A :class:`ReportSnapshot` is one such summary FROZEN at a moment: an immutable,
append-only record (the tamper-evident ``reject_mutation`` trigger backs it in
the store). ``payload`` is the report body -- a plain JSON-able mapping, secret-
free by construction (references / hashes / counts only, never a flag or token).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

# The closed set of report kinds. Single source of truth for the ORM CHECK and
# the migration SQL (both render from this) and for the service dispatch.
VALID_REPORT_TYPES = frozenset(
    {"validation", "build", "competition_run", "eval"}
)

# Report kinds keyed by a challenge VERSION (definition_slug + version_no) vs by a
# COMPETITION. Used to validate a snapshot's scope columns.
_VERSION_SCOPED = frozenset({"validation", "build", "eval"})
_COMPETITION_SCOPED = frozenset({"competition_run"})


def report_subject(
    report_type: str,
    *,
    definition_slug: str | None = None,
    version_no: int | None = None,
    competition_id: str | None = None,
) -> str:
    """A stable, human-readable subject key for a report, so snapshots of the same
    logical subject group together (``version:<slug>:<n>`` or
    ``competition:<id>``). Raises :class:`ValueError` if the scope does not match
    the report kind."""
    if report_type in _VERSION_SCOPED:
        if not definition_slug or not isinstance(version_no, int):
            raise ValueError(
                f"{report_type!r} report needs definition_slug + version_no"
            )
        return f"version:{definition_slug}:{version_no}"
    if report_type in _COMPETITION_SCOPED:
        if not competition_id:
            raise ValueError(f"{report_type!r} report needs competition_id")
        return f"competition:{competition_id}"
    raise ValueError(
        f"report_type must be one of {sorted(VALID_REPORT_TYPES)}, got {report_type!r}"
    )


@dataclass(frozen=True)
class ReportSnapshot:
    """One report FROZEN at ``created_at`` -- an immutable, append-only record.

    ``subject`` groups snapshots of one logical subject (see :func:`report_subject`).
    Exactly one scope is set: ``(definition_slug, version_no)`` for a version-scoped
    kind, ``competition_id`` for a competition-scoped one. ``payload`` is the report
    body (JSON-able, secret-free). ``created_by`` is the actor that took the
    snapshot. ``report_id`` is a caller-supplied uuid string."""

    report_id: str
    report_type: str
    subject: str
    # Excluded from equality/hash (``compare=False``): a jsonb round-trip coerces
    # tuples->lists etc., so two snapshots with the same identity but a re-read
    # payload must still compare equal (mirrors ``ChallengeVersion.spec``). The
    # immutable ``report_id`` is the authoritative identity.
    payload: Mapping[str, object] = field(compare=False)
    created_by: str
    created_at: datetime
    definition_slug: str | None = None
    version_no: int | None = None
    competition_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.report_id, str) or not self.report_id.strip():
            raise ValueError("report_id must be a non-empty string")
        if self.report_type not in VALID_REPORT_TYPES:
            raise ValueError(
                f"report_type must be one of {sorted(VALID_REPORT_TYPES)}, "
                f"got {self.report_type!r}"
            )
        if not isinstance(self.subject, str) or not self.subject.strip():
            raise ValueError("subject must be a non-empty string")
        if not isinstance(self.payload, Mapping):
            raise ValueError("payload must be a mapping")
        if not isinstance(self.created_by, str) or not self.created_by.strip():
            raise ValueError("created_by must be a non-empty string")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.report_type in _VERSION_SCOPED:
            if not self.definition_slug or not isinstance(self.version_no, int):
                raise ValueError(
                    f"{self.report_type!r} snapshot needs definition_slug + version_no"
                )
        if self.report_type in _COMPETITION_SCOPED and not self.competition_id:
            raise ValueError(
                f"{self.report_type!r} snapshot needs competition_id"
            )
