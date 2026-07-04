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
    sandbox: bool = False,
) -> RuntimeValidationReport:
    """Build/run a challenge's services and run its health check + solver.

    ``sandbox`` controls WHERE the bundle's ``tests/healthcheck.py`` and
    ``private/solver.py`` run. These are ordinary Python scripts shipped inside
    the challenge; by default they run on the host with the operator's
    privileges (fast, fine for challenges you generated yourself). For an
    UNTRUSTED bundle, set ``sandbox=True`` to run them inside an ephemeral
    ``python:3.11-slim`` container joined to the host network (so it still
    reaches the published service port) with the challenge mounted read-only --
    containing arbitrary bundle code that would otherwise get host execution.
    """
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
        _wait_for_health(challenge_path, base_url, timeout_seconds, runner, report, manifest, sandbox)
        _record(
            report,
            runner(
                _solve_command(base_url, manifest, challenge_path, sandbox),
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
    sandbox: bool = False,
) -> None:
    command = _health_command(base_url, manifest, challenge_path, sandbox)
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


def _health_command(
    base_url: str, manifest: dict | None, challenge_path: Path | None = None, sandbox: bool = False
) -> list[str]:
    args = _manifest_args(manifest, "health")
    script_args = args if args is not None else ["--base-url", base_url]
    return _script_command("tests/healthcheck.py", script_args, challenge_path, sandbox)


def _solve_command(
    base_url: str, manifest: dict | None, challenge_path: Path | None = None, sandbox: bool = False
) -> list[str]:
    args = _manifest_args(manifest, "solve")
    script_args = args if args is not None else ["--base-url", base_url]
    return _script_command("private/solver.py", script_args, challenge_path, sandbox)


def _script_command(
    script: str, script_args: list[str], challenge_path: Path | None, sandbox: bool
) -> list[str]:
    """The argv to run a bundle script -- on the host by default, or inside an
    ephemeral read-only container when ``sandbox`` is set (see
    :func:`validate_runtime`)."""
    if sandbox and challenge_path is not None:
        abs_path = str(Path(challenge_path).resolve())
        return [
            "docker", "run", "--rm", "--network", "host",
            "-v", f"{abs_path}:/work:ro", "-w", "/work",
            "python:3.11-slim", "python", script, *script_args,
        ]
    return [sys.executable, script, *script_args]


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

