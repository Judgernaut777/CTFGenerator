"""Report computation + snapshotting.

A report is a read-only summary computed from already-persisted data; snapshotting
freezes one as an immutable, append-only record. Four kinds:

* ``validation``      -- the version spec's STATIC validation (``validate_spec``;
  pure, no Docker). Runtime/sibling/replay validation is a separate Docker-gated
  concern and is NOT part of this summary.
* ``build``           -- the version's build-image registry state (primary image
  + any per-service stack images).
* ``eval``            -- the version's agent-evaluation runs (allowlisted, secret-
  free advisory fields only -- never a flag/candidate/credential).
* ``competition_run`` -- a competition's final standings + solve timeline.

Every payload is JSON-able and secret-free by construction (references / hashes /
counts / booleans only). All reads are pure DB (ADR-001; no Docker, no challenge
code). Snapshots persist through the append-only ``report_snapshots`` table.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime

from ctf_generator.application.scoring.scoreboard_service import ScoreboardService
from ctf_generator.domain.reports.models import (
    VALID_REPORT_TYPES,
    ReportSnapshot,
    report_subject,
)
from ctf_generator.infrastructure.database.challenge_build_image_repository import (
    SqlAlchemyChallengeBuildImageRepository,
)
from ctf_generator.infrastructure.database.challenge_build_stack_image_repository import (
    SqlAlchemyChallengeBuildStackImageRepository,
)
from ctf_generator.infrastructure.database.challenge_version_repository import (
    SqlAlchemyChallengeVersionRepository,
)
from ctf_generator.infrastructure.database.eval_run_repository import (
    SqlAlchemyEvalRunRepository,
)
from ctf_generator.infrastructure.database.report_snapshot_repository import (
    SqlAlchemyReportSnapshotRepository,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.solve_repository import (
    SqlAlchemySolveRepository,
)
from ctf_generator.spec_generator import spec_from_dict, validate_spec

# The version-scoped report kinds each carry a per-type read permission at the
# API edge; this service is permission-agnostic (the router gates).
_VERSION_KINDS = ("validation", "build", "eval")


class ReportNotAvailableError(LookupError):
    """The subject a report is requested for does not exist (404)."""


class ReportService:
    """Compute read-only reports and freeze them as immutable snapshots."""

    def __init__(self, database: Database, *, clock=None) -> None:
        self._database = database
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- compute (read-only; no persistence) --------------------------------

    def compute_validation(self, definition_slug: str, version_no: int) -> dict:
        with self._database.session_scope() as session:
            version = SqlAlchemyChallengeVersionRepository(session).get(
                definition_slug, version_no
            )
            if version is None:
                raise ReportNotAvailableError(
                    f"challenge version not found: {definition_slug!r} v{version_no}"
                )
            spec = spec_from_dict(dict(version.spec))
            errors = validate_spec(spec)
        return {
            "definition_slug": definition_slug,
            "version_no": version_no,
            "state": version.state,
            "spec_sha256": version.spec_sha256,
            "family": spec.family,
            "family_version": version.family_version,
            "mode": version.mode,
            "valid": not errors,
            "error_count": len(errors),
            "errors": list(errors),
        }

    def compute_build(self, definition_slug: str, version_no: int) -> dict:
        with self._database.session_scope() as session:
            if SqlAlchemyChallengeVersionRepository(session).get(
                definition_slug, version_no
            ) is None:
                raise ReportNotAvailableError(
                    f"challenge version not found: {definition_slug!r} v{version_no}"
                )
            builds = SqlAlchemyChallengeBuildImageRepository(session)
            image_ref = builds.latest_image_ref_for_version(
                definition_slug, version_no
            )
            digest = (
                builds.digest_for_version_image(
                    definition_slug, version_no, image_ref
                )
                if image_ref
                else None
            )
            stack = (
                SqlAlchemyChallengeBuildStackImageRepository(
                    session
                ).stack_for_primary_image(definition_slug, version_no, image_ref)
                if image_ref
                else ()
            )
        return {
            "definition_slug": definition_slug,
            "version_no": version_no,
            "built": image_ref is not None,
            "image_ref": image_ref,
            "image_digest": digest,
            "is_stack": bool(stack),
            "services": [
                {
                    "service_name": s.service_name,
                    "image_ref": s.image_ref,
                    "image_digest": s.image_digest,
                    "is_primary": s.is_primary,
                    "depends_on": list(s.depends_on),
                    "expose": list(s.expose),
                }
                for s in stack
            ],
        }

    def compute_eval(self, definition_slug: str, version_no: int) -> dict:
        with self._database.session_scope() as session:
            if SqlAlchemyChallengeVersionRepository(session).get(
                definition_slug, version_no
            ) is None:
                raise ReportNotAvailableError(
                    f"challenge version not found: {definition_slug!r} v{version_no}"
                )
            runs = SqlAlchemyEvalRunRepository(session).list_for_version(
                definition_slug, version_no
            )
        # Allowlisted, secret-free advisory fields only -- never notes (redacted
        # advisory text is not needed for a summary) or any flag/candidate.
        run_views = [
            {
                "eval_run_id": r.eval_run_id,
                "profile": r.profile,
                "adversarial": r.adversarial,
                "status": r.status,
                "solved": r.solved,
                "steps": r.steps,
                "success_dropped": r.success_dropped,
                "step_delta": r.step_delta,
                "requested_at": r.requested_at.isoformat(),
                "completed_at": (
                    r.completed_at.isoformat() if r.completed_at else None
                ),
            }
            for r in runs
        ]
        return {
            "definition_slug": definition_slug,
            "version_no": version_no,
            "run_count": len(run_views),
            "runs": run_views,
        }

    def compute_competition_run(self, competition_id: str) -> dict:
        standings = ScoreboardService(self._database).standings(competition_id)
        with self._database.session_scope() as session:
            solves = SqlAlchemySolveRepository(session).list_for_competition(
                competition_id
            )
        timeline = sorted(
            (
                {
                    "team": s.team_name,
                    "definition_slug": s.definition_slug,
                    "version_no": s.version_no,
                    "solved_at": s.solved_at.isoformat(),
                }
                for s in solves
            ),
            key=lambda e: e["solved_at"],
        )
        # First blood per challenge = earliest solve of that (slug, version).
        first_blood: dict[tuple[str, int], dict] = {}
        for entry in timeline:
            key = (entry["definition_slug"], entry["version_no"])
            if key not in first_blood:
                first_blood[key] = entry
        return {
            "competition_id": competition_id,
            "team_count": len(standings),
            "solve_count": len(timeline),
            "standings": standings,
            "first_bloods": list(first_blood.values()),
            "timeline": timeline,
        }

    # -- snapshot (compute + persist) ---------------------------------------

    def snapshot(
        self,
        report_type: str,
        actor: str,
        *,
        definition_slug: str | None = None,
        version_no: int | None = None,
        competition_id: str | None = None,
        now: datetime | None = None,
    ) -> ReportSnapshot:
        """Compute a report and FREEZE it as an immutable snapshot. Raises
        :class:`ValueError` for an unknown report_type / mismatched scope and
        :class:`ReportNotAvailableError` if the subject does not exist."""
        if report_type not in VALID_REPORT_TYPES:
            raise ValueError(
                f"report_type must be one of {sorted(VALID_REPORT_TYPES)}, "
                f"got {report_type!r}"
            )
        stamp = now or self._clock()
        if report_type in _VERSION_KINDS:
            payload = self._compute_version(report_type, definition_slug, version_no)
            subject = report_subject(
                report_type, definition_slug=definition_slug, version_no=version_no
            )
        else:  # competition_run
            payload = self.compute_competition_run(competition_id)
            subject = report_subject(report_type, competition_id=competition_id)

        snapshot = ReportSnapshot(
            report_id=str(_uuid.uuid4()),
            report_type=report_type,
            subject=subject,
            payload=payload,
            created_by=actor,
            created_at=stamp,
            definition_slug=definition_slug if report_type in _VERSION_KINDS else None,
            version_no=version_no if report_type in _VERSION_KINDS else None,
            competition_id=competition_id if report_type == "competition_run" else None,
        )
        with self._database.session_scope() as session:
            SqlAlchemyReportSnapshotRepository(session).add(snapshot)
        return snapshot

    def _compute_version(
        self, report_type: str, definition_slug: str | None, version_no: int | None
    ) -> dict:
        if not definition_slug or not isinstance(version_no, int):
            raise ValueError(
                f"{report_type!r} report needs definition_slug + version_no"
            )
        if report_type == "validation":
            return self.compute_validation(definition_slug, version_no)
        if report_type == "build":
            return self.compute_build(definition_slug, version_no)
        return self.compute_eval(definition_slug, version_no)

    # -- read ----------------------------------------------------------------

    def get_snapshot(self, report_id: str) -> ReportSnapshot | None:
        with self._database.session_scope() as session:
            return SqlAlchemyReportSnapshotRepository(session).get(report_id)

    def latest(self, report_type: str, subject: str) -> ReportSnapshot | None:
        with self._database.session_scope() as session:
            return SqlAlchemyReportSnapshotRepository(session).latest_for_subject(
                report_type, subject
            )

    def list_snapshots(self, report_type: str, subject: str) -> list[ReportSnapshot]:
        with self._database.session_scope() as session:
            return SqlAlchemyReportSnapshotRepository(session).list_for_subject(
                report_type, subject
            )
