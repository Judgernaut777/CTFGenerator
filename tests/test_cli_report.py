from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_generator import report_writer
from ctf_generator.cli import main
from ctf_generator.generator import create_challenge


def _generate(temp_dir: str) -> Path:
    output = Path(temp_dir) / "challenge"
    create_challenge(
        output_dir=output,
        seed="report-seed",
        title="Invoice Drift",
        difficulty="medium",
        family="web_business_logic_tenant_export",
    )
    return output


def _reports(report_dir: Path) -> list[Path]:
    return sorted(report_dir.glob("*.json"))


class ScoreReportCliTests(unittest.TestCase):
    def test_score_writes_report_when_report_dir_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _generate(temp_dir)
            report_dir = Path(temp_dir) / "reports"
            code = main(["score", str(challenge), "--report-dir", str(report_dir)])
            self.assertEqual(code, 0)

            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "score")
            self.assertEqual(payload["status"], "passed")
            self.assertEqual(payload["schema_version"], "1.0")

    def test_score_below_min_writes_failed_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _generate(temp_dir)
            report_dir = Path(temp_dir) / "reports"
            code = main(
                [
                    "score",
                    str(challenge),
                    "--min-score",
                    "999",
                    "--report-dir",
                    str(report_dir),
                ]
            )
            self.assertEqual(code, 1)

            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "failed")

    def test_no_report_dir_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _generate(temp_dir)
            report_dir = Path(temp_dir) / "reports"
            code = main(["score", str(challenge)])
            self.assertEqual(code, 0)
            # No report artifact directory should have been created.
            self.assertFalse(report_dir.exists())

    def test_score_error_path_writes_failed_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _generate(temp_dir)
            (challenge / "private/variant.json").unlink()
            report_dir = Path(temp_dir) / "reports"
            code = main(["score", str(challenge), "--report-dir", str(report_dir)])
            self.assertEqual(code, 1)

            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "score")
            self.assertEqual(payload["status"], "failed")

    def test_report_write_failure_is_non_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _generate(temp_dir)
            report_dir = Path(temp_dir) / "reports"
            with mock.patch.object(
                report_writer, "write_report", side_effect=OSError("disk full")
            ):
                code = main(["score", str(challenge), "--report-dir", str(report_dir)])
            # Report-write failure must never change the command's exit code.
            self.assertEqual(code, 0)
            self.assertFalse(_reports(report_dir))


class ValidateReportCliTests(unittest.TestCase):
    def test_validate_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _generate(temp_dir)
            report_dir = Path(temp_dir) / "reports"
            code = main(["validate", str(challenge), "--report-dir", str(report_dir)])
            self.assertEqual(code, 0)

            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "validate")
            self.assertEqual(payload["status"], "passed")
            self.assertIn("errors", payload["result"])
            self.assertIn("warnings", payload["result"])


class SiblingsReportCliTests(unittest.TestCase):
    def test_validate_siblings_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "siblings"
            report_dir = Path(temp_dir) / "reports"
            code = main(
                [
                    "validate-siblings",
                    "--output",
                    str(output),
                    "--seed",
                    "demo-xyz",
                    "--report-dir",
                    str(report_dir),
                ]
            )
            self.assertEqual(code, 0)

            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "validate-siblings")
            self.assertIsInstance(payload["result"]["sibling_a"], str)
            self.assertIsInstance(payload["result"]["sibling_b"], str)


if __name__ == "__main__":
    unittest.main()
