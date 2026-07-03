from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .generator import create_challenge
from .replay_validator import ReplayReport, cross_replay as run_cross_replay
from .runtime_validator import CommandRunner, RuntimeValidationReport, validate_runtime
from .validator import validate_challenge


@dataclass
class SiblingValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    sibling_a: Path | None = None
    sibling_b: Path | None = None
    changed_tokens: list[str] = field(default_factory=list)


def validate_siblings(
    output_dir: Path,
    seed: str,
    title: str = "Invoice Drift",
    difficulty: str = "medium",
    family: str = "web_business_logic_tenant_export",
    force: bool = False,
    runtime: bool = False,
    cross_replay: bool = False,
    timeout_seconds: int = 90,
    runner: CommandRunner | None = None,
) -> SiblingValidationReport:
    report = SiblingValidationReport()
    if output_dir.exists():
        if not force:
            report.errors.append(f"{output_dir} already exists; pass --force to overwrite")
            return report
        shutil.rmtree(output_dir)

    sibling_a = output_dir / "sibling-a"
    sibling_b = output_dir / "sibling-b"
    report.sibling_a = sibling_a
    report.sibling_b = sibling_b

    create_challenge(
        output_dir=sibling_a,
        seed=f"{seed}:a",
        title=title,
        difficulty=difficulty,
        family=family,
    )
    create_challenge(
        output_dir=sibling_b,
        seed=f"{seed}:b",
        title=title,
        difficulty=difficulty,
        family=family,
    )

    for path in (sibling_a, sibling_b):
        static_report = validate_challenge(path)
        report.errors.extend([f"{path.name}: {error}" for error in static_report.errors])
        report.warnings.extend([f"{path.name}: {warning}" for warning in static_report.warnings])

    if report.errors:
        return report

    metadata_a = _read_variant(sibling_a)
    metadata_b = _read_variant(sibling_b)
    report.changed_tokens = _changed_tokens(metadata_a, metadata_b)
    if len(report.changed_tokens) < 4:
        report.errors.append(
            "sibling variants are too similar; expected at least 4 changed route/token fields"
        )

    if not runtime or report.errors:
        return report

    for path in (sibling_a, sibling_b):
        runtime_report = validate_runtime(path, timeout_seconds=timeout_seconds, runner=runner)
        _merge_runtime_report(report, path.name, runtime_report)

    if cross_replay and not report.errors:
        # Cross-sibling exploit replay: each sibling's solver is pointed at the
        # OTHER sibling's freshly launched instance. Sequential, so both runs
        # can reuse the same base URL.
        replay_ab = run_cross_replay(
            sibling_a, sibling_b, timeout_seconds=timeout_seconds, runner=runner
        )
        _merge_replay_report(report, "a-solver-vs-b", replay_ab)
        replay_ba = run_cross_replay(
            sibling_b, sibling_a, timeout_seconds=timeout_seconds, runner=runner
        )
        _merge_replay_report(report, "b-solver-vs-a", replay_ba)

    return report


def _read_variant(challenge_path: Path) -> dict[str, object]:
    return json.loads((challenge_path / "private/variant.json").read_text(encoding="utf-8"))


def _changed_tokens(metadata_a: dict[str, object], metadata_b: dict[str, object]) -> list[str]:
    changed: list[str] = []
    for section_name in ("routes", "tokens"):
        section_a = metadata_a.get(section_name, {})
        section_b = metadata_b.get(section_name, {})
        if not isinstance(section_a, dict) or not isinstance(section_b, dict):
            continue
        for key in sorted(set(section_a) | set(section_b)):
            if section_a.get(key) != section_b.get(key):
                changed.append(f"{section_name}.{key}")
    return changed


def _merge_runtime_report(
    report: SiblingValidationReport,
    sibling_name: str,
    runtime_report: RuntimeValidationReport,
) -> None:
    report.errors.extend([f"{sibling_name}: {error}" for error in runtime_report.errors])
    report.logs.extend([f"[{sibling_name}]\n{log}" for log in runtime_report.logs])


def _merge_replay_report(
    report: SiblingValidationReport,
    replay_name: str,
    replay_report: ReplayReport,
) -> None:
    report.errors.extend([f"{replay_name}: {error}" for error in replay_report.errors])
    report.logs.extend([f"[{replay_name}]\n{log}" for log in replay_report.logs])

