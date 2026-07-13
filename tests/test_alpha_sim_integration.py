"""PG-gated assertions over the internal-alpha exit simulation (M21 stream A).

Drives ``scripts/alpha_sim.run_simulation`` against a live PostgreSQL and asserts
the exit-scenario invariants: EXACTLY ONE solve, the scoreboard reflects it, the
published version is content-addressed + immutable, re-folding is append-only
consistent, and -- the S5 check -- neither the intended flag nor a bearer token
leaks into the simulation's own captured log.

Skips cleanly without ``CTFGEN_TEST_DATABASE_URL`` or the ``[api]``/``[db]``
extras: it never silently passes.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_alpha_sim_integration
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "scripts" / "alpha_sim.py"

# Load scripts/alpha_sim.py by path (scripts/ is not an importable package). The
# module MUST be registered in sys.modules before ``exec_module`` so its
# ``@dataclass`` annotations resolve (dataclasses looks the owning module up by
# name to evaluate field types).
_spec = importlib.util.spec_from_file_location("alpha_sim", _SCRIPT)
assert _spec and _spec.loader
alpha_sim = importlib.util.module_from_spec(_spec)
sys.modules["alpha_sim"] = alpha_sim
_spec.loader.exec_module(alpha_sim)

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_ENABLED = alpha_sim.IMPORT_ERROR is None and bool(_TEST_URL)
_SKIP_REASON = (
    f"[api]/[db] not importable ({alpha_sim.IMPORT_ERROR})"
    if alpha_sim.IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class AlphaExitSimulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # One end-to-end run; every test asserts a facet of the same result.
        cls.res = alpha_sim.run_simulation(_TEST_URL)

    def test_every_step_passed(self) -> None:
        failed = [s.name for s in self.res.steps if not s.ok]
        self.assertEqual(failed, [], f"steps failed: {failed}")
        self.assertTrue(self.res.passed)

    def test_exactly_one_solve(self) -> None:
        self.assertTrue(self.res.invariants["single_solve"])

    def test_scoreboard_reflects_the_solve(self) -> None:
        self.assertTrue(self.res.invariants["scoreboard_reflects_solve"])

    def test_scoreboard_is_append_only_consistent(self) -> None:
        self.assertTrue(self.res.invariants["append_only_consistent"])

    def test_published_version_is_content_addressed_and_immutable(self) -> None:
        self.assertTrue(
            self.res.invariants["published_content_addressed_immutable"]
        )
        # The content identity is a real sha256 hex digest.
        self.assertIsNotNone(self.res.spec_sha256)
        self.assertRegex(self.res.spec_sha256, r"\A[0-9a-f]{64}\Z")

    def test_no_secret_leaks_into_the_sim_log(self) -> None:
        # S5: the simulation's OWN captured output carries neither the intended
        # flag nor any bearer token. (Bearer tokens are opaque; assert the flag
        # literal and the "Bearer " prefix never appear in the log.)
        blob = "\n".join(self.res.log)
        self.assertNotIn("CTF{internal-alpha-secret-flag}", blob)
        self.assertNotIn("Bearer ", blob)
        self.assertTrue(
            self.res.invariants["flag_absent_from_contestant_surfaces"]
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
