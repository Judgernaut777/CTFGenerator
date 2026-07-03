from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from ctf_generator import __version__, report_writer
from ctf_generator.replay_validator import ReplayReport
from ctf_generator.runtime_validator import RuntimeValidationReport
from ctf_generator.sibling_validator import SiblingValidationReport
from ctf_generator.validator import ValidationReport


FILENAME_PATTERN = re.compile(
    r"^\d{8}T\d{6}Z-[a-z0-9-]+-[a-z0-9._-]*-[0-9a-f]{8}(?:-\d+)?\.json$"
)


class BuildReportTests(unittest.TestCase):
    def test_build_report_shape_and_determinism(self) -> None:
        ts = datetime(2026, 7, 3, 14, 25, 30, tzinfo=timezone.utc)
        subject = {"type": "challenge", "identifier": "my-challenge"}
        result = {"errors": [], "warnings": ["w"]}

        report = report_writer.build_report(
            "validate",
            subject,
            result,
            "passed",
            timestamp=ts,
            git_commit_value="abc123",
        )

        for key in (
            "schema_version",
            "generator_version",
            "command",
            "subject",
            "timestamp",
            "git_commit",
            "status",
            "result",
        ):
            self.assertIn(key, report)
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["generator_version"], __version__)
        self.assertEqual(report["command"], "validate")
        self.assertEqual(report["git_commit"], "abc123")
        self.assertEqual(report["timestamp"], ts.isoformat())

        again = report_writer.build_report(
            "validate",
            subject,
            result,
            "passed",
            timestamp=ts,
            git_commit_value="abc123",
        )
        self.assertEqual(report, again)


class GitCommitTests(unittest.TestCase):
    def test_git_commit_missing_returns_empty_string(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(report_writer.git_commit(Path(temp_dir)), "")

    def test_git_commit_success_is_stripped(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git", "rev-parse", "HEAD"],
            returncode=0,
            stdout="deadbeef1234\n",
            stderr="",
        )
        with mock.patch.object(report_writer.subprocess, "run", return_value=completed):
            self.assertEqual(report_writer.git_commit(), "deadbeef1234")

    def test_git_commit_missing_binary_returns_empty_string(self) -> None:
        for exc in (FileNotFoundError(), subprocess.TimeoutExpired("git", 5)):
            with mock.patch.object(report_writer.subprocess, "run", side_effect=exc):
                self.assertEqual(report_writer.git_commit(), "")


class WriteReportTests(unittest.TestCase):
    def _report(self) -> dict:
        ts = datetime(2026, 7, 3, 14, 25, 30, tzinfo=timezone.utc)
        return report_writer.build_report(
            "score",
            {"type": "challenge", "identifier": "my-challenge"},
            {"total": 90.0},
            "passed",
            timestamp=ts,
            git_commit_value="",
        )

    def test_write_report_creates_dir_and_returns_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_dir = Path(temp_dir) / "nested" / "reports"
            path = report_writer.write_report(report_dir, self._report())

            self.assertTrue(path.exists())
            self.assertTrue(path.parent == report_dir)
            self.assertRegex(path.name, FILENAME_PATTERN)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["command"], "score")

    def test_write_report_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_dir = Path(temp_dir)
            report = self._report()
            first = report_writer.write_report(report_dir, report)
            second = report_writer.write_report(report_dir, report)

            self.assertNotEqual(first, second)
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())
            self.assertTrue(second.name.endswith("-1.json"))

    def test_filename_timestamp_matches_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = report_writer.write_report(Path(temp_dir), self._report())
            # Envelope timestamp is 2026-07-03T14:25:30Z; filename must match it
            # rather than a fresh clock read.
            self.assertTrue(path.name.startswith("20260703T142530Z-"))


class SerializeTests(unittest.TestCase):
    def test_serialize_validation(self) -> None:
        report = ValidationReport(errors=["e1"], warnings=["w1", "w2"])
        result = report_writer.serialize_validation(report)
        self.assertEqual(result["errors"], ["e1"])
        self.assertEqual(result["warnings"], ["w1", "w2"])
        json.dumps(result)  # must not raise

    def test_serialize_runtime(self) -> None:
        report = RuntimeValidationReport(errors=["boom"], logs=["$ cmd\nout"])
        result = report_writer.serialize_runtime(report)
        self.assertEqual(result["errors"], ["boom"])
        self.assertEqual(result["logs"], ["$ cmd\nout"])
        json.dumps(result)  # must not raise

    def test_serialize_replay(self) -> None:
        report = ReplayReport(
            errors=["a-solver-vs-b: command failed"],
            logs=["$ solver\nno flag"],
            solver_dir=Path("/tmp/sibling-a"),
            target_dir=Path("/tmp/sibling-b"),
            success=False,
        )
        result = report_writer.serialize_replay(report)
        self.assertEqual(result["solver_dir"], "/tmp/sibling-a")
        self.assertEqual(result["target_dir"], "/tmp/sibling-b")
        self.assertFalse(result["success"])
        json.dumps(result)  # must not raise

        empty = report_writer.serialize_replay(ReplayReport())
        self.assertIsNone(empty["solver_dir"])
        self.assertIsNone(empty["target_dir"])
        json.dumps(empty)  # must not raise

    def test_serialize_siblings_paths_are_json_safe(self) -> None:
        report = SiblingValidationReport(
            sibling_a=Path("/tmp/a"),
            sibling_b=Path("/tmp/b"),
            changed_tokens=["routes.x"],
        )
        result = report_writer.serialize_siblings(report)
        self.assertEqual(result["sibling_a"], "/tmp/a")
        self.assertEqual(result["sibling_b"], "/tmp/b")
        json.dumps(result)  # must not raise

        empty = report_writer.serialize_siblings(SiblingValidationReport())
        self.assertIsNone(empty["sibling_a"])
        self.assertIsNone(empty["sibling_b"])
        json.dumps(empty)  # must not raise


class StatusOfTests(unittest.TestCase):
    def test_status_of(self) -> None:
        self.assertEqual(report_writer.status_of([]), "passed")
        self.assertEqual(report_writer.status_of(["e"]), "failed")


if __name__ == "__main__":
    unittest.main()
