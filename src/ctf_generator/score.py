from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Dimension:
    name: str
    weight: float
    score: float
    notes: list[str] = field(default_factory=list)


@dataclass
class ScoreReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dimensions: list[Dimension] = field(default_factory=list)
    total: float = 0.0
    band: str = ""

    def to_mapping(self) -> dict[str, object]:
        return {
            "total": round(self.total, 1),
            "band": self.band,
            "dimensions": [
                {
                    "name": d.name,
                    "weight": d.weight,
                    "score": round(d.score, 1),
                    "notes": d.notes,
                }
                for d in self.dimensions
            ],
            "warnings": self.warnings,
            "errors": self.errors,
        }


def score_challenge(challenge_path: Path) -> ScoreReport:
    report = ScoreReport()
    if not challenge_path.is_dir():
        report.errors.append(f"{challenge_path} is not a directory")
        return report

    variant = _read_json(challenge_path / "private/variant.json")
    solver = _read_text(challenge_path / "private/solver.py")
    compose = _read_text(challenge_path / "docker-compose.yml")
    spec = _read_text(challenge_path / "challenge.yaml")
    if variant is None:
        report.errors.append("missing or invalid private/variant.json")
    if not solver:
        report.errors.append("missing private/solver.py")
    if report.errors:
        return report

    ai = _read_block(spec, "ai_resistance")
    variation = _read_block(spec, "dynamic_variation")
    checkpoint_count = spec.count("name:") if spec else 0

    report.dimensions = [
        _variant_uniqueness(variant, variation),
        _statefulness(compose, solver),
        _solver_depth(solver, checkpoint_count, ai),
        _live_interaction(solver, ai, report),
        _scanner_resistance(ai),
    ]

    report.total = sum(d.weight * d.score for d in report.dimensions)
    report.band = _band(report.total)
    _spec_consistency_warnings(ai, solver, compose, report)
    return report


def _variant_uniqueness(variant: dict, variation: dict[str, str]) -> Dimension:
    flags = [
        "per_user_schema",
        "per_user_routes",
        "per_user_seed_data",
        "per_user_auth_flow",
        "per_user_flag_path",
    ]
    enabled = sum(1 for flag in flags if variation.get(flag) == "true")
    flag_fraction = enabled / len(flags)

    routes = variant.get("routes", {}) if isinstance(variant, dict) else {}
    tokens = variant.get("tokens", {}) if isinstance(variant, dict) else {}
    token_count = len(routes) + len(tokens)

    score = 60.0 * flag_fraction + 40.0 * min(1.0, token_count / 8.0)
    return Dimension(
        name="variant_uniqueness",
        weight=0.25,
        score=score,
        notes=[
            f"{enabled}/{len(flags)} dynamic-variation dimensions enabled",
            f"{token_count} per-instance route/token values in variant.json",
        ],
    )


def _statefulness(compose: str, solver: str) -> Dimension:
    has_worker = "worker:" in compose
    has_queue = "redis" in compose.lower()
    polls_status = bool(re.search(r"for .*in range", solver)) and "status" in solver

    signals = [has_worker, has_queue, polls_status]
    score = 100.0 * (sum(signals) / len(signals))
    return Dimension(
        name="statefulness",
        weight=0.20,
        score=score,
        notes=[
            f"background worker service: {has_worker}",
            f"queue/state backend: {has_queue}",
            f"solver drives async job state: {polls_status}",
        ],
    )


def _solver_depth(solver: str, checkpoint_count: int, ai: dict[str, str]) -> Dimension:
    interactions = len(re.findall(r"\b(?:get|post_json)\(", solver))
    min_steps = _read_int(ai.get("min_solver_steps"), default=5)

    checkpoint_score = 100.0 * min(1.0, checkpoint_count / max(min_steps, 1))
    interaction_score = 100.0 * min(1.0, interactions / max(min_steps, 1))
    score = 0.5 * checkpoint_score + 0.5 * interaction_score
    return Dimension(
        name="solver_depth",
        weight=0.20,
        score=score,
        notes=[
            f"{checkpoint_count} declared checkpoints (target {min_steps})",
            f"{interactions} distinct HTTP interactions in solver",
        ],
    )


def _live_interaction(solver: str, ai: dict[str, str], report: ScoreReport) -> Dimension:
    requires_live = ai.get("require_live_interaction") == "true"
    discovers = "/api/profile" in solver
    polls = bool(re.search(r"for .*in range", solver))

    signals = [requires_live, discovers, polls]
    score = 100.0 * (sum(signals) / len(signals))
    return Dimension(
        name="live_interaction",
        weight=0.15,
        score=score,
        notes=[
            f"spec requires live interaction: {requires_live}",
            f"solver discovers routes at runtime: {discovers}",
            f"solver polls a live endpoint: {polls}",
        ],
    )


def _scanner_resistance(ai: dict[str, str]) -> Dimension:
    usefulness = ai.get("generic_scanner_usefulness", "medium")
    resistance = {"low": 100.0, "medium": 60.0, "high": 20.0}.get(usefulness, 50.0)

    density = ai.get("decoy_density", "medium")
    decoy_bonus = {"low": 0.0, "medium": 0.0, "high": 10.0}.get(density, 0.0)

    score = min(100.0, resistance + decoy_bonus)
    return Dimension(
        name="scanner_resistance",
        weight=0.20,
        score=score,
        notes=[
            f"generic scanner usefulness: {usefulness}",
            f"decoy density: {density}",
        ],
    )


def _spec_consistency_warnings(
    ai: dict[str, str],
    solver: str,
    compose: str,
    report: ScoreReport,
) -> None:
    if ai.get("require_live_interaction") == "true" and not re.search(r"for .*in range", solver):
        report.warnings.append(
            "spec claims require_live_interaction but solver has no polling loop"
        )
    if ai.get("hidden_sibling_validation") == "true" and "worker:" not in compose:
        report.warnings.append(
            "spec claims hidden_sibling_validation but no worker service is present"
        )


def _band(total: float) -> str:
    if total >= 85:
        return "strong"
    if total >= 70:
        return "good"
    if total >= 50:
        return "moderate"
    return "weak"


def _read_block(text: str, block_name: str) -> dict[str, str]:
    """Parse a flat scalar block (2-space indented key: value) from dump_yaml output."""
    values: dict[str, str] = {}
    if not text:
        return values
    lines = text.splitlines()
    inside = False
    for line in lines:
        if not inside:
            if line.rstrip() == f"{block_name}:":
                inside = True
            continue
        if line and not line.startswith(" "):
            break
        match = re.match(r"^  (\w+): (.+)$", line)
        if match:
            values[match.group(1)] = match.group(2).strip().strip('"')
    return values


def _read_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""
