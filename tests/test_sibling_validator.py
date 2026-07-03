from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from ctf_generator.sibling_validator import validate_siblings


class SiblingValidatorTests(unittest.TestCase):
    def test_sibling_validator_generates_distinct_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "siblings"
            report = validate_siblings(output_dir=output, seed="test-seed")

            self.assertEqual(report.errors, [])
            self.assertTrue((output / "sibling-a" / "private" / "variant.json").exists())
            self.assertTrue((output / "sibling-b" / "private" / "variant.json").exists())
            self.assertGreaterEqual(len(report.changed_tokens), 4)

    def test_sibling_validator_refuses_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "siblings"
            output.mkdir()
            report = validate_siblings(output_dir=output, seed="test-seed")

            self.assertNotEqual(report.errors, [])

    def test_runtime_and_cross_replay_use_injected_runner(self) -> None:
        commands: list[list[str]] = []

        def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "siblings"
            report = validate_siblings(
                output_dir=output,
                seed="test-seed",
                runtime=True,
                cross_replay=True,
                timeout_seconds=1,
                runner=runner,
            )

        self.assertEqual(report.errors, [])
        # Runtime validation launched both siblings and cross-replay pointed each
        # sibling's solver at the other sibling's instance.
        joined = [" ".join(c) for c in commands]
        self.assertTrue(any("ctfgen-sibling-a" in c and "build" in c for c in joined))
        self.assertTrue(any("ctfgen-sibling-b" in c and "build" in c for c in joined))
        self.assertTrue(any("ctfgen-replay-sibling-b" in c for c in joined))
        self.assertTrue(any("ctfgen-replay-sibling-a" in c for c in joined))
        # A solver from sibling-a is executed against the sibling-b target.
        solver_a = str(output / "sibling-a" / "private" / "solver.py")
        self.assertTrue(any(solver_a in c for c in joined))


if __name__ == "__main__":
    unittest.main()
