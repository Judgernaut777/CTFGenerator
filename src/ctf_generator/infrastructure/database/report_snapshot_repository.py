"""SQLAlchemy repository for the ``report_snapshots`` registry.

Persists + reads immutable report snapshots. Writes are plain INSERTs (the row is
append-only; the DB ``reject_mutation`` trigger is the backstop). Reads resolve
the latest snapshot for a subject, or one by id, or a subject's history. ORM rows
never escape -- they are mapped to/from the domain :class:`ReportSnapshot`.
References/hashes/counts only; never a flag or secret.
"""

from __future__ import annotations

import uuid as _uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.reports.models import ReportSnapshot

from .models import ReportSnapshot as ReportSnapshotRow


def _to_domain(row: ReportSnapshotRow) -> ReportSnapshot:
    return ReportSnapshot(
        report_id=str(row.id),
        report_type=row.report_type,
        subject=row.subject,
        payload=dict(row.payload or {}),
        created_by=row.created_by,
        created_at=row.created_at,
        definition_slug=row.definition_slug,
        version_no=row.version_no,
        competition_id=row.competition_id,
    )


class SqlAlchemyReportSnapshotRepository:
    """Persist + read immutable report snapshots."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, snapshot: ReportSnapshot) -> None:
        """Insert a snapshot (append-only). The ``reject_mutation`` trigger makes
        the row immutable thereafter."""
        self._session.add(
            ReportSnapshotRow(
                id=_uuid.UUID(snapshot.report_id),
                report_type=snapshot.report_type,
                subject=snapshot.subject,
                definition_slug=snapshot.definition_slug,
                version_no=snapshot.version_no,
                competition_id=snapshot.competition_id,
                payload=dict(snapshot.payload),
                created_by=snapshot.created_by,
                created_at=snapshot.created_at,
            )
        )

    def get(self, report_id: str) -> ReportSnapshot | None:
        """One snapshot by its id, or ``None``."""
        try:
            pk = _uuid.UUID(report_id)
        except (ValueError, AttributeError):
            return None
        row = self._session.get(ReportSnapshotRow, pk)
        return _to_domain(row) if row is not None else None

    def latest_for_subject(
        self, report_type: str, subject: str
    ) -> ReportSnapshot | None:
        """The most recent snapshot for ``(report_type, subject)``, or ``None``.
        Newest wins (``created_at`` desc, then a stable ``id`` tiebreak)."""
        row = self._session.scalars(
            select(ReportSnapshotRow)
            .where(
                ReportSnapshotRow.report_type == report_type,
                ReportSnapshotRow.subject == subject,
            )
            .order_by(
                ReportSnapshotRow.created_at.desc(), ReportSnapshotRow.id.desc()
            )
            .limit(1)
        ).first()
        return _to_domain(row) if row is not None else None

    def list_for_subject(
        self, report_type: str, subject: str
    ) -> list[ReportSnapshot]:
        """Every snapshot for ``(report_type, subject)``, newest first."""
        rows = self._session.scalars(
            select(ReportSnapshotRow)
            .where(
                ReportSnapshotRow.report_type == report_type,
                ReportSnapshotRow.subject == subject,
            )
            .order_by(
                ReportSnapshotRow.created_at.desc(), ReportSnapshotRow.id.desc()
            )
        )
        return [_to_domain(r) for r in rows]
