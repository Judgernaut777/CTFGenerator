from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from ctf_generator.generator import create_challenge
from ctf_generator.runtime_validator import validate_runtime


class RuntimeValidatorTests(unittest.TestCase):
    def test_runtime_validator_runs_expected_commands(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "invoice-drift"
            create_challenge(
                output_dir=output,
                seed="test-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
            )

            report = validate_runtime(output, timeout_seconds=1, runner=runner)

        self.assertEqual(report.errors, [])
        self.assertEqual(calls[0][:4], ["docker", "compose", "-p", "ctfgen-invoice-drift"])
        self.assertIn("build", calls[0])
        self.assertIn("up", calls[1])
        self.assertIn("tests/healthcheck.py", calls[2])
        self.assertIn("private/solver.py", calls[3])
        self.assertIn("down", calls[4])


if __name__ == "__main__":
    unittest.main()
