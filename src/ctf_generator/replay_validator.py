from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .runtime_validator import CommandRunner, _record, _run, _wait_for_health
from .validator import validate_challenge


@dataclass
class ReplayReport:
    errors: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    solver_dir: Path | None = None
    target_dir: Path | None = None
    success: bool = False


def cross_replay(
    solver_dir: Path,
    target_dir: Path,
    base_url: str = "http://127.0.0.1:8080",
    timeout_seconds: int = 90,
    keep_running: bool = False,
    runner: CommandRunner | None = None,
) -> ReplayReport:
    """Run ``solver_dir``'s solver against a live instance built from ``target_dir``.

    This is the cross-sibling exploit replay: the solver generated for one
    sibling instance is pointed at a *different* sibling's live app. Success
    (the solver exits 0, i.e. it discovered routes/tokens and extracted the
    flag from the sibling) demonstrates that variants of the same family share
    an exploitable structure.

    Docker/subprocess work goes through the injectable ``runner`` so the test
    suite never needs real Docker or network access.
    """
    runner = runner or _run
    report = ReplayReport(solver_dir=solver_dir, target_dir=target_dir)

    for label, path in (("solver", solver_dir), ("target", target_dir)):
        static_report = validate_challenge(path)
        if static_report.errors:
            report.errors.extend(f"{label}: {error}" for error in static_report.errors)
    if report.errors:
        return report

    project_name = f"ctfgen-replay-{target_dir.name}".replace("_", "-").lower()
    solver = solver_dir / "private" / "solver.py"
    started = False
    try:
        _record(report, runner(["docker", "compose", "-p", project_name, "build"], target_dir, timeout_seconds))
        _record(report, runner(["docker", "compose", "-p", project_name, "up", "-d"], target_dir, timeout_seconds))
        started = True
        _wait_for_health(target_dir, base_url, timeout_seconds, runner, report)
        _record(
            report,
            runner(
                [sys.executable, str(solver), "--base-url", base_url],
                solver_dir,
                timeout_seconds,
            ),
        )
        report.success = True
    except subprocess.CalledProcessError as exc:
        report.errors.append(f"command failed: {' '.join(exc.cmd)}")
        if exc.stdout:
            report.logs.append(exc.stdout)
        if exc.stderr:
            report.logs.append(exc.stderr)
    except TimeoutError as exc:
        report.errors.append(str(exc))
    finally:
        if started and not keep_running:
            try:
                _record(
                    report,
                    runner(
                        ["docker", "compose", "-p", project_name, "down", "--volumes", "--remove-orphans"],
                        target_dir,
                        timeout_seconds,
                    ),
                )
            except subprocess.CalledProcessError as exc:
                report.errors.append(f"cleanup failed: {' '.join(exc.cmd)}")

    return report
