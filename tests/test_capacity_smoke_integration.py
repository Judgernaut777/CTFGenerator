"""PG-gated SMOKE test for the M20 capacity harness (``scripts/loadtest.py``).

This proves the harness WORKS and yields a first real data point: it runs the
harness at a SMALL scale (a handful of concurrent submitters + readers, NOT the
full 25-team / 20-challenge REQ-NFR-001/002 envelope) against real PostgreSQL
and asserts the MEASURED submission + scoreboard latencies are recorded as real,
finite, positive numbers within a GENEROUS smoke bound.

It deliberately does NOT assert the strict REQ-NFR-005 (< 500 ms) target: at a
handful of concurrent submitters on a loaded shared host that target may or may
not be met, and this smoke scale is not the production capacity sign-off (that
is M21/M22 -- see docs/validation/capacity.md). The generous bound here proves
the pipeline is healthy and the harness measures, without pretending to certify
the SLO.

SKIPS cleanly without the ``[api]``/``[db]`` extras or ``CTFGEN_TEST_DATABASE_URL``.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_capacity_smoke_integration
"""

from __future__ import annotations

import math
import os
import sys
import unittest

# The harness lives in scripts/, which is not on PYTHONPATH; add the repo root.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

try:  # heavy deps optional; guard so import never fails the host suite
    from scripts.loadtest import LoadResult, percentile, run_load

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

# GENEROUS smoke bounds -- ~5x the numbers observed at this scale, so a slow
# shared CI host still passes, while a truly broken pipeline (seconds-per-request
# or a hang) still fails. These are NOT the REQ-NFR SLOs.
_SMOKE_SUBMIT_P95_MS = 3000.0
_SMOKE_SCOREBOARD_P95_MS = 3000.0

# Small scale: a handful of concurrent submitters, NOT 25 teams / 20 challenges.
_TEAMS = 3
_CHALLENGES = 2
_SUBS_PER_TEAM = 5
_READERS = 2


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class CapacitySmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result: LoadResult = run_load(
            database_url=_TEST_URL,
            teams=_TEAMS,
            challenges=_CHALLENGES,
            submissions_per_team=_SUBS_PER_TEAM,
            readers=_READERS,
            seed=7,
        )

    def test_percentile_helper_is_correct(self) -> None:
        # The helper the whole report leans on -- a tautology-free unit check.
        self.assertTrue(math.isnan(percentile([], 50)))
        self.assertEqual(percentile([42.0], 95), 42.0)
        self.assertEqual(percentile([0.0, 10.0], 50), 5.0)
        self.assertEqual(percentile([1.0, 2.0, 3.0, 4.0], 100), 4.0)
        self.assertEqual(percentile([1.0, 2.0, 3.0, 4.0], 0), 1.0)

    def test_all_submissions_and_reads_succeeded(self) -> None:
        r = self.result
        # Every submitter completed its fixed count -> exactly this many 201s,
        # no errors. Proves the concurrent write path is healthy under load.
        self.assertEqual(r.submit_ok, _TEAMS * _SUBS_PER_TEAM, r.errors)
        self.assertEqual(r.submit_err, 0, r.errors)
        self.assertEqual(r.read_err, 0, r.errors)
        self.assertGreater(r.read_ok, 0, "readers recorded no scoreboard reads")

    def test_submission_latency_is_real_and_within_smoke_bound(self) -> None:
        r = self.result
        # One measured latency per successful submission -- real numbers, not a
        # placeholder, and all strictly positive (wall-clock of real work).
        self.assertEqual(len(r.submit_latencies_ms), r.submit_ok)
        self.assertTrue(all(x > 0 for x in r.submit_latencies_ms))
        p50, p95, mx = r.submit_p50_ms, r.submit_p95_ms, r.submit_max_ms
        for label, v in (("p50", p50), ("p95", p95), ("max", mx)):
            self.assertFalse(math.isnan(v), f"submission {label} is NaN")
            self.assertGreater(v, 0.0, f"submission {label} not positive")
        self.assertLessEqual(p50, p95)
        self.assertLessEqual(p95, mx)
        # Generous smoke bound (NOT the 500 ms REQ-NFR-005 SLO): catches a hung
        # or seconds-per-request pipeline; passes on a loaded host.
        self.assertLess(
            p95, _SMOKE_SUBMIT_P95_MS,
            f"submission p95={p95:.1f}ms exceeded smoke bound "
            f"{_SMOKE_SUBMIT_P95_MS}ms (NOT the 500ms SLO)",
        )

    def test_scoreboard_latency_is_real_and_within_smoke_bound(self) -> None:
        r = self.result
        self.assertEqual(len(r.scoreboard_latencies_ms), r.read_ok)
        self.assertTrue(all(x > 0 for x in r.scoreboard_latencies_ms))
        p95 = r.scoreboard_p95_ms
        self.assertFalse(math.isnan(p95))
        # This smoke bound IS the REQ-NFR-004 target (< 3 s); at this scale the
        # read comfortably meets it, giving a genuine (if small) data point.
        self.assertLess(
            p95, _SMOKE_SCOREBOARD_P95_MS,
            f"scoreboard p95={p95:.1f}ms exceeded {_SMOKE_SCOREBOARD_P95_MS}ms",
        )

    def test_launch_success_is_reported_unverified_not_faked(self) -> None:
        # Charter §5: the harness must NOT fabricate a launch-success number.
        probe = self.result.launch_probe
        self.assertFalse(probe.get("measured", True))
        self.assertIn("UNVERIFIED", probe.get("reason", ""))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
