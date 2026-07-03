from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ctf_generator import cli, report_index, report_writer


def _envelope(command, identifier, result, status="passed", timestamp=None, commit="abcdef1234567890"):
    ts = timestamp or datetime(2026, 7, 3, 14, 25, 30, tzinfo=timezone.utc)
    return report_writer.build_report(
        command,
        {"type": "challenge", "identifier": identifier},
        result,
        status,
        timestamp=ts,
        git_commit_value=commit,
    )


class RowFromReportTests(unittest.TestCase):
    def test_score_payload_extracts_total(self) -> None:
        report = _envelope("score", "my-challenge", {"total": 87.5, "band": "strong"})
        row = report_index.row_from_report(report, "r1.json")
        self.assertEqual(row.command, "score")
        self.assertEqual(row.status, "passed")
        self.assertEqual(row.subject_type, "challenge")
        self.assertEqual(row.subject_identifier, "my-challenge")
        self.assertEqual(row.timestamp, "2026-07-03T14:25:30+00:00")
        self.assertEqual(row.git_commit_short, "abcdef123456")
        self.assertEqual(row.score_total, 87.5)
        self.assertEqual(row.source, "r1.json")

    def test_validate_payload_has_no_score(self) -> None:
        report = _envelope("validate", "x", {"errors": [], "warnings": []})
        row = report_index.row_from_report(report, "r.json")
        self.assertIsNone(row.score_total)

    def test_empty_dict_is_defensive(self) -> None:
        row = report_index.row_from_report({}, "empty.json")
        self.assertEqual(row.command, "")
        self.assertEqual(row.subject_type, "")
        self.assertEqual(row.subject_identifier, "")
        self.assertEqual(row.git_commit_short, "-")
        self.assertIsNone(row.score_total)

    def test_missing_or_none_subject_and_nondict_result(self) -> None:
        row = report_index.row_from_report(
            {"command": "score", "subject": None, "result": "nope"}, "s.json"
        )
        self.assertEqual(row.subject_identifier, "")
        self.assertIsNone(row.score_total)

    def test_empty_git_commit_renders_dash(self) -> None:
        report = _envelope("validate", "x", {"errors": []}, commit="")
        row = report_index.row_from_report(report, "r.json")
        self.assertEqual(row.git_commit_short, "-")

    def test_bool_total_is_not_a_score(self) -> None:
        row = report_index.row_from_report(
            {"command": "x", "result": {"total": True}}, "b.json"
        )
        self.assertIsNone(row.score_total)


class LoadIndexTests(unittest.TestCase):
    def test_missing_directory_returns_empty(self) -> None:
        index = report_index.load_index(Path("/nonexistent/does/not/exist"))
        self.assertEqual(index.rows, [])
        self.assertEqual(index.skipped, [])

    def test_empty_directory_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            index = report_index.load_index(Path(td))
            self.assertEqual(index.rows, [])

    def test_skips_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "bad.json").write_text("{ not json", encoding="utf-8")
            report_writer.write_report(d, _envelope("score", "ok", {"total": 50.0}))
            index = report_index.load_index(d)
            self.assertEqual(len(index.rows), 1)
            self.assertIn("bad.json", index.skipped)

    def test_skips_non_object_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "list.json").write_text("[1, 2, 3]", encoding="utf-8")
            index = report_index.load_index(d)
            self.assertEqual(index.rows, [])
            self.assertIn("list.json", index.skipped)

    def test_rows_sorted_by_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            report_writer.write_report(
                d,
                _envelope(
                    "score", "later", {"total": 1.0},
                    timestamp=datetime(2026, 7, 3, 20, 0, 0, tzinfo=timezone.utc),
                ),
            )
            report_writer.write_report(
                d,
                _envelope(
                    "score", "earlier", {"total": 2.0},
                    timestamp=datetime(2026, 7, 3, 8, 0, 0, tzinfo=timezone.utc),
                ),
            )
            index = report_index.load_index(d)
            self.assertEqual([r.subject_identifier for r in index.rows], ["earlier", "later"])


class RenderTableTests(unittest.TestCase):
    def test_table_contains_row_values(self) -> None:
        index = report_index.ReportIndex(
            rows=[report_index.row_from_report(_envelope("score", "chal-x", {"total": 87.5}), "r.json")]
        )
        out = report_index.render_table(index)
        self.assertIn("command", out)
        self.assertIn("score", out)
        self.assertIn("passed", out)
        self.assertIn("chal-x", out)
        self.assertIn("abcdef123456", out)
        self.assertIn("87.5", out)

    def test_empty_table(self) -> None:
        out = report_index.render_table(report_index.ReportIndex())
        self.assertEqual(out, "No reports found.")

    def test_empty_table_notes_skipped(self) -> None:
        out = report_index.render_table(report_index.ReportIndex(skipped=["bad.json"]))
        self.assertIn("No reports found.", out)
        self.assertIn("skipped", out)


class RenderHtmlTests(unittest.TestCase):
    def test_self_contained_document(self) -> None:
        index = report_index.ReportIndex(
            rows=[report_index.row_from_report(_envelope("score", "chal-x", {"total": 87.5}), "r.json")]
        )
        out = report_index.render_html(index)
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", out)
        self.assertIn("87.5", out)
        self.assertIn("chal-x", out)
        for forbidden in ("http://", "https://", "<script", "src=", "<link"):
            self.assertNotIn(forbidden, out)

    def test_empty_html_has_empty_state(self) -> None:
        out = report_index.render_html(report_index.ReportIndex())
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("No reports found.", out)

    def test_html_escapes_subject_identifier(self) -> None:
        payload = "<img src=x onerror=1>"
        index = report_index.ReportIndex(
            rows=[report_index.row_from_report(_envelope("validate", payload, {"errors": []}), "r.json")]
        )
        out = report_index.render_html(index)
        self.assertNotIn("<img src=x onerror=1>", out)
        self.assertIn("&lt;img", out)


class CliTests(unittest.TestCase):
    def test_cli_prints_table(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            report_writer.write_report(d, _envelope("score", "chal-cli", {"total": 72.0}))
            rc = cli.main(["report-index", str(d)])
            self.assertEqual(rc, 0)

    def test_cli_writes_html(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            report_writer.write_report(d, _envelope("score", "chal-cli", {"total": 72.0}))
            html_path = d / "dash" / "index.html"
            rc = cli.main(["report-index", str(d), "--html", str(html_path)])
            self.assertEqual(rc, 0)
            self.assertTrue(html_path.exists())
            content = html_path.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("chal-cli", content)
            self.assertIn("72.0", content)

    def test_cli_missing_dir_returns_zero(self) -> None:
        rc = cli.main(["report-index", "/nonexistent/report/dir"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
