"""Executed recovery-drill validation for M20 (RTO wall-clock vs SLO).

Docker + PostgreSQL gated. Drives ``scripts/recovery_drill.sh`` against the live
control-plane PostgreSQL and asserts the drill is REAL evidence for REQ-NFR-007 /
RELEASE_CRITERIA gate S8 -- not a claim:

  * the happy path exits 0, reports a MEASURED RTO that is a genuine POSITIVE
    wall-clock number under the SLO, and (via ``--keep``) leaves a recovered
    target whose seeded ledger rows we independently re-verify with the real
    ``verify_restore`` harness -- proving the restore actually happened;
  * the drill's success is anchored to observed data, so a NO-OP restore is
    caught: ``--empty-target`` (verify an un-restored empty target) MUST breach
    and exit nonzero;
  * the RTO SLO is a live gate: ``--rto-slo-seconds 0`` MUST breach and exit
    nonzero;
  * the drill does NOT fake the RPO SLO -- its output documents RPO as
    baseline-only and the continuous RPO<=5min posture as UNVERIFIED (charter
    section 5); we lock that honesty in so it cannot silently regress.

Skips cleanly (documented) only when PostgreSQL / the pg-in-docker tooling the
drill needs is genuinely unreachable.

    CTFGEN_TEST_DATABASE_URL=postgresql+psycopg://ctfgen:ctfgen@172.20.0.2:5432/postgres \\
      PYTHONPATH=src:tests python -m unittest test_recovery_drill_integration
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest

try:
    import sqlalchemy as sa
    from sqlalchemy.engine import make_url

    from ctf_generator.application.backup.verify import verify_restore
    from ctf_generator.infrastructure.database.config import DatabaseConfig
    from ctf_generator.infrastructure.database.session import Database

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_TEST_URL = os.environ.get("CTFGEN_TEST_DATABASE_URL")
_CONTAINER = os.environ.get("CTFGEN_PG_DOCKER_CONTAINER", "ctfgen_pg_epic1")
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DRILL = os.path.join(_REPO_ROOT, "scripts", "recovery_drill.sh")


def _docker_pg() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(  # noqa: S603
            ["docker", "exec", _CONTAINER, "pg_dump", "--version"],  # noqa: S607
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        return True
    except Exception:
        return False


_TOOLING = _TEST_URL is not None and _docker_pg()
_ENABLED = _IMPORT_ERROR is None and bool(_TEST_URL) and _TOOLING
if _IMPORT_ERROR is not None:
    _SKIP_REASON = f"db extra not importable ({_IMPORT_ERROR})"
elif not _TEST_URL:
    _SKIP_REASON = "CTFGEN_TEST_DATABASE_URL not set (needs a running PostgreSQL)"
elif not _TOOLING:
    _SKIP_REASON = f"postgres container {_CONTAINER!r} unreachable via docker exec"
else:
    _SKIP_REASON = ""


def _run_drill(*args: str) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "CTFGEN_TEST_DATABASE_URL": _TEST_URL or "",
        "CTFGEN_PG_DOCKER_CONTAINER": _CONTAINER,
        # Use THIS interpreter (the [db]-extra venv) for the drill's python steps.
        "CTFGEN_PYTHON": sys.executable,
    }
    return subprocess.run(  # noqa: S603
        ["bash", _DRILL, *args],  # noqa: S607
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


@unittest.skipUnless(_ENABLED, _SKIP_REASON)
class RecoveryDrillTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dbs: list[str] = []

    def tearDown(self) -> None:
        # Drop any target DB a --keep run left behind.
        if not self._dbs:
            return
        base = make_url(_TEST_URL)
        engine = sa.create_engine(
            base.set(database="postgres"), isolation_level="AUTOCOMMIT", future=True
        )
        try:
            with engine.connect() as conn:
                for name in self._dbs:
                    conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        finally:
            engine.dispose()

    def _parse(self, out: str, key: str) -> str:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
        self.fail(f"drill output missing {key}=... line:\n{out}")

    # -- happy path: a real, timed, verified recovery -------------------------

    def test_drill_measures_positive_rto_under_slo_and_restores_rows(self) -> None:
        proc = _run_drill("--keep")
        self.assertEqual(
            proc.returncode, 0, f"drill failed:\n{proc.stdout}\n{proc.stderr}"
        )
        out = proc.stdout

        # RTO is a genuine positive wall-clock number, under the (default 30min) SLO.
        rto = float(self._parse(out, "MEASURED_RTO_SECONDS"))
        self.assertGreater(rto, 0.0, "measured RTO must be a real positive wall clock")
        self.assertLess(rto, 1800.0, "measured RTO must be under the 30min SLO")
        self.assertIn("RTO (restore -> verified-usable)", out)
        self.assertIn("PASS", out)

        # The restore genuinely happened: independently re-verify the KEPT target
        # with the real harness, and assert the seeded rows are actually present
        # (row parity via verify.py, not merely the drill's own say-so).
        target_db = self._parse(out, "RECOVERED_TARGET_DB")
        self._dbs.append(target_db)
        url = make_url(_TEST_URL).set(database=target_db).render_as_string(
            hide_password=False
        )
        db = Database(DatabaseConfig(url=url))
        try:
            report = verify_restore(db)
            self.assertTrue(report.passed, report.summary())
            with db.session_scope() as s:
                events = int(
                    s.execute(sa.text("SELECT count(*) FROM score_events")).scalar_one()
                )
                comps = [
                    r[0]
                    for r in s.execute(
                        sa.text("SELECT slug FROM competitions ORDER BY slug")
                    ).all()
                ]
        finally:
            db.dispose()
        self.assertEqual(events, 3, "recovered target must hold the seeded ledger rows")
        self.assertIn("cup", comps, "recovered target must hold the seeded competition")

    # -- no-op restore is caught (must fail loudly) ---------------------------

    def test_no_op_restore_into_empty_target_breaches(self) -> None:
        proc = _run_drill("--empty-target")
        self.assertNotEqual(
            proc.returncode,
            0,
            "a no-op restore (empty target) MUST breach -- the drill must exit nonzero",
        )
        self.assertIn("NO-OP RESTORE correctly BREACHED", proc.stdout, proc.stdout)

    # -- the RTO SLO is a live gate, not a tautology --------------------------

    def test_rto_slo_gate_bites_on_zero_budget(self) -> None:
        proc = _run_drill("--rto-slo-seconds", "0")
        self.assertNotEqual(
            proc.returncode, 0, "an impossible 0s RTO SLO MUST breach and exit nonzero"
        )
        self.assertIn("BREACH", proc.stdout, proc.stdout)

    # -- honest RPO story is documented, not faked ----------------------------

    def test_rpo_reported_as_baseline_only_and_pitr_unverified(self) -> None:
        proc = _run_drill()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        out = proc.stdout
        self.assertIn("BASELINE-ONLY, NOT A GATE", out)
        self.assertIn("UNVERIFIED", out)
        self.assertIn("WAL/PITR", out)


if __name__ == "__main__":
    unittest.main()
