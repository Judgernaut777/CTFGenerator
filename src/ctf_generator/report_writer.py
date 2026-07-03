from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__

if TYPE_CHECKING:
    from .agent_eval import AdversarialDeltaReport, AgentEvalReport
    from .replay_validator import ReplayReport
    from .runtime_validator import RuntimeValidationReport
    from .scoreboard import ScoreboardSnapshot
    from .sibling_validator import SiblingValidationReport
    from .validator import ValidationReport


SCHEMA_VERSION = "1.0"


def git_commit(cwd: Path | None = None) -> str:
    """Best-effort ``git rev-parse HEAD``.

    Returns the stripped commit sha on success, or an empty string if git is
    missing, hangs, or the directory is not a repository, so a missing or
    hanging git never breaks a validation run.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(cwd) if cwd is not None else None,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def build_report(
    command: str,
    subject: dict,
    result: dict,
    status: str,
    *,
    timestamp: datetime | None = None,
    git_commit_value: str | None = None,
) -> dict:
    """Build the report envelope. Pure: no I/O when both injectables are given."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    if git_commit_value is None:
        git_commit_value = git_commit()
    return {
        "schema_version": SCHEMA_VERSION,
        "generator_version": __version__,
        "command": command,
        "subject": subject,
        "timestamp": timestamp.isoformat(),
        "git_commit": git_commit_value,
        "status": status,
        "result": result,
    }


def write_report(report_dir: Path, report: dict) -> Path:
    """Write ``report`` as JSON into ``report_dir``, never overwriting a file."""
    report_dir.mkdir(parents=True, exist_ok=True)
    base = _report_filename(report)
    stem = base[: -len(".json")]
    candidate = report_dir / base
    attempt = 0
    payload = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    while True:
        try:
            with candidate.open("x", encoding="utf-8") as handle:
                handle.write(payload)
            return candidate
        except FileExistsError:
            attempt += 1
            candidate = report_dir / f"{stem}-{attempt}.json"


def _report_filename(report: dict) -> str:
    ts = _filename_timestamp(report.get("timestamp"))
    command = report.get("command", "report")
    subject = report.get("subject") or {}
    identifier = subject.get("identifier", "") if isinstance(subject, dict) else ""
    subject_slug = _slug(str(identifier))
    disc = _discriminator(report.get("result", {}))
    return f"{ts}-{command}-{subject_slug}-{disc}.json"


def _filename_timestamp(value: object) -> str:
    """Format the envelope timestamp for the filename so the two always agree.

    Falls back to the current time only when the timestamp is missing or
    unparseable, so an injected/deterministic timestamp is honoured.
    """
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            parsed = datetime.now(timezone.utc)
    else:
        parsed = datetime.now(timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _slug(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    text = text.strip("-")
    return text[:40]


def _discriminator(result: dict) -> str:
    encoded = json.dumps(result, sort_keys=True, default=str).encode()
    return hashlib.sha1(encoded).hexdigest()[:8]


def serialize_validation(report: "ValidationReport") -> dict:
    return {"errors": list(report.errors), "warnings": list(report.warnings)}


def serialize_runtime(report: "RuntimeValidationReport") -> dict:
    return {"errors": list(report.errors), "logs": list(report.logs)}


def serialize_siblings(report: "SiblingValidationReport") -> dict:
    return {
        "errors": list(report.errors),
        "warnings": list(report.warnings),
        "logs": list(report.logs),
        "sibling_a": str(report.sibling_a) if report.sibling_a is not None else None,
        "sibling_b": str(report.sibling_b) if report.sibling_b is not None else None,
        "changed_tokens": list(report.changed_tokens),
    }


def serialize_replay(report: "ReplayReport") -> dict:
    return {
        "errors": list(report.errors),
        "logs": list(report.logs),
        "solver_dir": str(report.solver_dir) if report.solver_dir is not None else None,
        "target_dir": str(report.target_dir) if report.target_dir is not None else None,
        "success": report.success,
    }


def serialize_scoreboard(snapshot: "ScoreboardSnapshot") -> dict:
    return {
        "competition_id": snapshot.competition_id,
        "generated_at": snapshot.generated_at.isoformat(),
        "frozen": snapshot.frozen,
        "entries": [
            {
                "team_id": entry.team_id,
                "score": entry.score,
                "solve_count": entry.solve_count,
                "last_solve_at": (
                    entry.last_solve_at.isoformat() if entry.last_solve_at is not None else None
                ),
                "rank": entry.rank,
            }
            for entry in snapshot.entries
        ],
    }


def _serialize_sim_events(events: list) -> list[dict]:
    """JSON-safe mapping for a list of ``scenario.SimEvent`` (each already
    provides its own ``to_mapping()``, reused verbatim -- not reimplemented)."""
    return [event.to_mapping() for event in events]


def _serialize_scenario_run_report(report) -> dict:
    """JSON-safe mapping for a ``scenario.ScenarioRunReport``.

    Standalone (not imported from ``cli.py``'s private ``_serialize_scenario_report``,
    per this project's strict per-file ownership rules), but mirrors its shape
    so a ``run-scenario`` report artifact and an ``eval-agent --adversarial``
    report artifact serialize a ``ScenarioRunReport`` identically.
    """
    final_state = report.final_state
    return {
        "challenge_path": report.challenge_path,
        "ticks_run": report.ticks_run,
        "timeline": _serialize_sim_events(report.timeline),
        "triggers_fired": list(report.triggers_fired),
        "responses_applied": [
            {
                "tick": record.tick,
                "role": record.role,
                "response_id": record.response_id,
                "action": record.action,
                "target": record.target,
            }
            for record in report.responses_applied
        ],
        "attacker_blocked": list(report.attacker_blocked),
        "final_state": (
            {
                "tick": final_state.tick,
                "checkpoints": sorted(final_state.checkpoints),
                "flags": dict(final_state.flags),
                "fired_triggers": sorted(final_state.fired_triggers),
                "noise_count": final_state.noise_count,
            }
            if final_state is not None
            else None
        ),
    }


def serialize_agent_eval(report: "AgentEvalReport") -> dict:
    """JSON-safe mapping for an ``agent_eval.AgentEvalReport``."""
    return {
        "profile": report.profile,
        "solved": report.solved,
        "steps": report.steps,
        "elapsed_ticks": report.elapsed_ticks,
        "notes": list(report.notes),
    }


def serialize_adversarial_delta(report: "AdversarialDeltaReport") -> dict:
    """JSON-safe mapping for an ``agent_eval.AdversarialDeltaReport``.

    Includes the ``success_dropped``/``step_delta`` derived properties
    (computed, not stored, on the dataclass) so a persisted report artifact
    carries the headline signal without a reader having to recompute it from
    ``baseline``/``adversarial``.
    """
    return {
        "challenge_path": report.challenge_path,
        "profile": report.profile,
        "baseline": serialize_agent_eval(report.baseline),
        "adversarial": serialize_agent_eval(report.adversarial),
        "scenario_report": _serialize_scenario_run_report(report.scenario_report),
        "success_dropped": report.success_dropped,
        "step_delta": report.step_delta,
        "notes": list(report.notes),
    }


def status_of(errors: list[str]) -> str:
    return "passed" if not errors else "failed"
