from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .validator import validate_challenge


class CommandRunner(Protocol):
    def __call__(
        self,
        command: list[str],
        cwd: Path,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        ...


@dataclass
class RuntimeValidationReport:
    errors: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)


def validate_runtime(
    challenge_path: Path,
    base_url: str = "http://127.0.0.1:8080",
    timeout_seconds: int = 90,
    keep_running: bool = False,
    runner: CommandRunner | None = None,
) -> RuntimeValidationReport:
    runner = runner or _run
    report = RuntimeValidationReport()

    static_report = validate_challenge(challenge_path)
    if static_report.errors:
        report.errors.extend(static_report.errors)
        return report

    project_name = f"ctfgen-{challenge_path.name}".replace("_", "-").lower()
    manifest = _load_runtime_manifest(challenge_path)
    started = False
    try:
        _record(report, runner(["docker", "compose", "-p", project_name, "build"], challenge_path, timeout_seconds))
        _record(report, runner(["docker", "compose", "-p", project_name, "up", "-d"], challenge_path, timeout_seconds))
        started = True
        _wait_for_health(challenge_path, base_url, timeout_seconds, runner, report, manifest)
        _record(
            report,
            runner(
                _solve_command(base_url, manifest),
                challenge_path,
                timeout_seconds,
            ),
        )
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
                        challenge_path,
                        timeout_seconds,
                    ),
                )
            except subprocess.CalledProcessError as exc:
                report.errors.append(f"cleanup failed: {' '.join(exc.cmd)}")

    return report


def _wait_for_health(
    challenge_path: Path,
    base_url: str,
    timeout_seconds: int,
    runner: CommandRunner,
    report: RuntimeValidationReport,
    manifest: dict | None = None,
) -> None:
    command = _health_command(base_url, manifest)
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            _record(report, runner(command, challenge_path, 10))
            return
        except subprocess.CalledProcessError as exc:
            last_error = exc.stderr or exc.stdout or str(exc)
            time.sleep(1)

    raise TimeoutError(f"health check did not pass within {timeout_seconds}s: {last_error}")


def _load_runtime_manifest(challenge_path: Path) -> dict | None:
    """Read private/runtime.json if a family ships one.

    The manifest lets a non-HTTP-on-8080 family (e.g. a raw-TCP binary service or
    a Modbus PLC) declare exactly how its health check and solver are invoked,
    instead of the web-family default of injecting ``--base-url``. Absent or
    malformed, callers fall back to that default so existing families are
    unaffected.
    """
    path = challenge_path / "private" / "runtime.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _health_command(base_url: str, manifest: dict | None) -> list[str]:
    args = _manifest_args(manifest, "health")
    if args is not None:
        return [sys.executable, "tests/healthcheck.py", *args]
    return [sys.executable, "tests/healthcheck.py", "--base-url", base_url]


def _solve_command(base_url: str, manifest: dict | None) -> list[str]:
    args = _manifest_args(manifest, "solve")
    if args is not None:
        return [sys.executable, "private/solver.py", *args]
    return [sys.executable, "private/solver.py", "--base-url", base_url]


def _manifest_args(manifest: dict | None, key: str) -> list[str] | None:
    """Return the argv (possibly empty) a manifest declares for a step, else None.

    ``None`` means "no manifest entry -- use the --base-url default"; an explicit
    empty list means "invoke the script with no extra args" (its own per-instance
    defaults are already correct).
    """
    if not manifest:
        return None
    entry = manifest.get(key)
    if isinstance(entry, dict) and isinstance(entry.get("args"), list):
        return [str(a) for a in entry["args"]]
    return None


def _run(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        timeout=timeout,
        check=True,
        text=True,
        capture_output=True,
    )


def _record(report: RuntimeValidationReport, result: subprocess.CompletedProcess[str]) -> None:
    command = " ".join(result.args) if isinstance(result.args, list) else str(result.args)
    if result.stdout:
        report.logs.append(f"$ {command}\n{result.stdout}")
    if result.stderr:
        report.logs.append(f"$ {command}\n{result.stderr}")

