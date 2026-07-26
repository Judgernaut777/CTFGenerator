"""Executed PITR-drill validation for M20 (continuous WAL archiving / RPO).

Docker-gated and fully self-contained: ``scripts/pitr_drill.sh`` spins up its own
throwaway ``postgres:16`` clusters (it touches NO control-plane database), so this
test needs only a working docker -- no ``CTFGEN_TEST_DATABASE_URL``. It asserts the
drill is REAL evidence for the RPO posture (REQ-NFR-006) that the logical-dump
recovery drill deliberately leaves UNVERIFIED:

  * the happy path exits 0, recovers to the target time T, and reports the
    before-target row PRESENT and the after-target row ABSENT -- i.e. recovery
    stopped exactly at T -- with an RPO window within target;
  * the assertion has teeth: ``--negative-control`` recovers PAST T so the
    after-target row survives, and the drill MUST then exit nonzero.

Skips cleanly (documented) only when docker is genuinely unavailable.

    PYTHONPATH=src:tests python -m unittest test_pitr_drill_integration
"""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DRILL = os.path.join(_REPO_ROOT, "scripts", "pitr_drill.sh")


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(  # noqa: S603
            ["docker", "version", "--format", "{{.Server.Version}}"],  # noqa: S607
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return True
    except Exception:
        return False


_ENABLED = _docker_ok()
_SKIP_REASON = "" if _ENABLED else "docker unavailable (the PITR drill needs it)"


def _run_drill(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        ["bash", _DRILL, *args],  # noqa: S607
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class PitrDrillTests(unittest.TestCase):
    def test_point_in_time_recovery_stops_at_target(self) -> None:
        result = _run_drill()
        out = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, out)
        self.assertIn("PITR drill PASS", out)
        # Recovery stopped exactly at T: the before-row survived, the after-row did
        # not -- the point-in-time boundary the whole mechanism relies on.
        self.assertIn("before-target rows        : 1", out)
        self.assertIn("after-target rows         : 0", out)
        self.assertIn("archive lag / RPO window", out)

    def test_negative_control_overshoot_breaches(self) -> None:
        # Recovering past T lets the after-row survive; the drill MUST fail, proving
        # the boundary assertion is not vacuous.
        result = _run_drill("--negative-control")
        out = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, out)
        self.assertIn("after-target rows         : 1", out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
