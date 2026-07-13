"""PostgreSQL integration test for the closed-beta EXIT simulation (M21, stream B).

Asserts the two mechanizable closed-beta exit invariants that ``scripts/beta_sim.py``
proves over a REAL PostgreSQL through the production HTTP edge + scoring fold:

  * AT-MOST-ONE-SOLVE UNDER CONCURRENCY: N simultaneous correct submissions of the
    same flag for one (competition, team, challenge) yield EXACTLY ONE solve + one
    ``solve`` score event, all N accepted -- no double-count.
  * SCOREBOARD RECONSTRUCTED FROM PERSISTED SCORE EVENTS == LIVE STATE: the live
    projection cache (built by the real ``ScoreProjector`` via the 0008 outbox) is
    byte-equal to a from-scratch refold of the append-only ``score_events``.

Docker/PG-gated: SKIPS cleanly without the ``[api]``/``[db]`` extras or
``CTFGEN_TEST_DATABASE_URL``. It reuses ``scripts/beta_sim.py`` (single source of
truth) rather than re-implementing the harness.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_beta_sim_integration
"""

from __future__ import annotations

import os
import sys
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS = os.path.join(_REPO_ROOT, "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

try:  # heavy deps optional; guard so import never fails the host suite
    import beta_sim

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - only without the extras
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_SKIP_REASON = (
    f"[api]/[db] not importable ({_IMPORT_ERROR})"
    if _IMPORT_ERROR
    else "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
)
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL)


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class BetaSimIntegrationTests(unittest.TestCase):
    """One shared smoke-scale run; each invariant asserted independently."""

    _result: beta_sim.BetaSimResult

    @classmethod
    def setUpClass(cls) -> None:
        cls._result = beta_sim.run_beta_sim(
            database_url=_TEST_URL,
            teams=3,
            challenges=2,
            concurrency=6,
        )

    def test_at_most_one_solve_under_concurrency(self) -> None:
        s = self._result.single_solve
        self.assertEqual(s.http_errors, [], "every concurrent submission must be accepted")
        # All N correct submissions accepted...
        self.assertEqual(s.accepted, s.concurrency)
        self.assertEqual(s.submissions_in_db, s.concurrency)
        # ...but EXACTLY ONE solve, one 'solve' event, one first_solve winner.
        self.assertEqual(s.first_solves, 1, "exactly one first_solve under the race")
        self.assertEqual(s.solves_in_db, 1, "exactly one persisted solve (no double-count)")
        self.assertEqual(s.solve_events_in_db, 1, "exactly one 'solve' score event")
        self.assertTrue(s.ok)

    def test_scoreboard_reconstructed_matches_live_state(self) -> None:
        r = self._result.recon
        self.assertGreaterEqual(r.live_rows, 1, "the seeded scoreboard must be non-empty")
        self.assertEqual(
            r.reconstructed_rows, r.live_rows, "same number of ranked teams"
        )
        self.assertTrue(
            r.parity,
            f"live projection cache must byte-equal the event refold: {r.detail}",
        )
        self.assertTrue(r.ok)

    def test_overall_beta_sim_passes(self) -> None:
        self.assertTrue(self._result.ok)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
