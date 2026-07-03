from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ctf_generator.generator import create_challenge
from ctf_generator.replay_validator import cross_replay


def _make_challenge(root: Path, name: str, seed: str) -> Path:
    output = root / name
    create_challenge(
        output_dir=output,
        seed=seed,
        title="Invoice Drift",
        difficulty="medium",
        family="web_business_logic_tenant_export",
    )
    return output


class CrossReplayTests(unittest.TestCase):
    def test_cross_replay_runs_solver_a_against_target_b(self) -> None:
        calls: list[tuple[list[str], Path]] = []

        def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            calls.append((command, cwd))
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            solver = _make_challenge(root, "sibling-a", "seed:a")
            target = _make_challenge(root, "sibling-b", "seed:b")

            report = cross_replay(
                solver,
                target,
                base_url="http://127.0.0.1:9000",
                timeout_seconds=1,
                runner=runner,
            )

        self.assertEqual(report.errors, [])
        self.assertTrue(report.success)

        commands = [command for command, _ in calls]
        # Build + launch the TARGET.
        self.assertEqual(commands[0][:4], ["docker", "compose", "-p", "ctfgen-replay-sibling-b"])
        self.assertIn("build", commands[0])
        self.assertIn("up", commands[1])
        # Health check runs against the target dir.
        self.assertIn("tests/healthcheck.py", commands[2])
        self.assertEqual(calls[2][1], target)
        # Solver command is A's solver, pointed at the target base URL, cwd = solver dir.
        solver_command, solver_cwd = calls[3]
        self.assertEqual(
            solver_command,
            [sys.executable, str(solver / "private" / "solver.py"), "--base-url", "http://127.0.0.1:9000"],
        )
        self.assertEqual(solver_cwd, solver)
        # Cleanup tears the target down.
        self.assertIn("down", commands[4])
        self.assertEqual(calls[4][1], target)

    def test_cross_replay_reports_failure_from_runner(self) -> None:
        def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            if any(arg.endswith("solver.py") for arg in command):
                raise subprocess.CalledProcessError(1, command, output="", stderr="no flag\n")
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            solver = _make_challenge(root, "sibling-a", "seed:a")
            target = _make_challenge(root, "sibling-b", "seed:b")

            report = cross_replay(solver, target, timeout_seconds=1, runner=runner)

        self.assertFalse(report.success)
        self.assertTrue(report.errors)


if __name__ == "__main__":
    unittest.main()
