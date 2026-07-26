"""Pure unit tests for the report domain value types (no DB, no I/O).

Locks the closed report-kind set, the subject-key convention, and the snapshot
invariants (scope columns match the kind; identity ignores payload re-reads).
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctf_generator.domain.reports.models import (
    VALID_REPORT_TYPES,
    ReportSnapshot,
    report_subject,
)

_NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)


class ReportSubjectTests(unittest.TestCase):
    def test_valid_report_types_is_the_closed_set(self) -> None:
        self.assertEqual(
            VALID_REPORT_TYPES,
            frozenset({"validation", "build", "competition_run", "eval"}),
        )

    def test_version_scoped_subject_key(self) -> None:
        for kind in ("validation", "build", "eval"):
            self.assertEqual(
                report_subject(kind, definition_slug="sqli", version_no=3),
                "version:sqli:3",
            )

    def test_competition_scoped_subject_key(self) -> None:
        self.assertEqual(
            report_subject("competition_run", competition_id="spring-2026"),
            "competition:spring-2026",
        )

    def test_version_kind_needs_slug_and_version(self) -> None:
        with self.assertRaises(ValueError):
            report_subject("validation", definition_slug="sqli")  # missing version
        with self.assertRaises(ValueError):
            report_subject("build", version_no=1)  # missing slug

    def test_competition_kind_needs_competition_id(self) -> None:
        with self.assertRaises(ValueError):
            report_subject("competition_run")

    def test_unknown_kind_rejected(self) -> None:
        with self.assertRaises(ValueError):
            report_subject("nonsense", competition_id="x")


class ReportSnapshotTests(unittest.TestCase):
    def _version_snap(self, **over) -> ReportSnapshot:
        kwargs = {
            "report_id": "id-1",
            "report_type": "validation",
            "subject": "version:sqli:1",
            "payload": {"valid": True},
            "created_by": "org-user",
            "created_at": _NOW,
            "definition_slug": "sqli",
            "version_no": 1,
        }
        kwargs.update(over)
        return ReportSnapshot(**kwargs)

    def test_valid_version_snapshot(self) -> None:
        snap = self._version_snap()
        self.assertEqual(snap.subject, "version:sqli:1")
        self.assertIsNone(snap.competition_id)

    def test_valid_competition_snapshot(self) -> None:
        snap = ReportSnapshot(
            report_id="id-2",
            report_type="competition_run",
            subject="competition:spring",
            payload={"team_count": 2},
            created_by="org-user",
            created_at=_NOW,
            competition_id="spring",
        )
        self.assertEqual(snap.competition_id, "spring")

    def test_version_kind_requires_scope_columns(self) -> None:
        with self.assertRaises(ValueError):
            self._version_snap(definition_slug=None)
        with self.assertRaises(ValueError):
            self._version_snap(version_no=None)

    def test_competition_kind_requires_competition_id(self) -> None:
        with self.assertRaises(ValueError):
            ReportSnapshot(
                report_id="id-3",
                report_type="competition_run",
                subject="competition:x",
                payload={},
                created_by="u",
                created_at=_NOW,
            )

    def test_empty_report_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._version_snap(report_id="  ")

    def test_empty_created_by_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._version_snap(created_by="")

    def test_naive_created_at_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._version_snap(created_at=datetime(2026, 7, 26, 12, 0))  # noqa: DTZ001

    def test_unknown_report_type_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._version_snap(report_type="bogus")

    def test_identity_ignores_payload_reread(self) -> None:
        # A jsonb round-trip coerces tuples->lists; two snapshots with the same
        # identity but a re-read payload must still compare equal.
        a = self._version_snap(payload={"services": ("web",)})
        b = self._version_snap(payload={"services": ["web"]})
        self.assertEqual(a, b)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
