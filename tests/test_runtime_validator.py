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
        # Default (non-sandbox): scripts run on the host interpreter.
        self.assertNotIn("docker", calls[2][0])
        self.assertNotIn("docker", calls[3][0])

    def test_sandbox_runs_bundle_scripts_in_a_container(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "challenge"
            create_challenge(
                output_dir=out,
                seed="rt-sandbox",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
            )
            report = validate_runtime(out, runner=runner, sandbox=True)

        self.assertEqual(report.errors, [])
        # Health (calls[2]) and solve (calls[3]) run inside docker, read-only.
        for call in (calls[2], calls[3]):
            self.assertEqual(call[0], "docker")
            self.assertIn("--network", call)
            self.assertTrue(any(part.endswith(":ro") for part in call))
            self.assertIn("python:3.11-slim", call)
        self.assertIn("tests/healthcheck.py", calls[2])
        self.assertIn("private/solver.py", calls[3])


if __name__ == "__main__":
    unittest.main()
