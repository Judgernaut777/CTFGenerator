from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import families
from .families import ScoringHints


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
    cve_refs = _read_list_block(spec, "cve_refs")
    scenario = _read_block(spec, "scenario")
    scenario_enabled = scenario.get("enabled") == "true"

    hints = _resolve_scoring_hints(spec)

    report.dimensions = [
        _variant_uniqueness(variant, variation, cve_refs),
        _statefulness(compose, solver, hints),
        _solver_depth(solver, checkpoint_count, ai),
        _live_interaction(solver, ai, report, hints),
        _scanner_resistance(ai),
    ]
    if scenario_enabled:
        _rescale_weights(report.dimensions, _SCENARIO_RESISTANCE_WEIGHT)
        report.dimensions.append(_scenario_resistance(spec))

    report.total = sum(d.weight * d.score for d in report.dimensions)
    report.band = _band(report.total)
    _spec_consistency_warnings(ai, solver, compose, report)

    # Integrity gates: the five dimensions above are DECLARED signals (string
    # counts and self-reported flags), so a broken or gamed challenge can score
    # highly on them. These gates catch the two unambiguous "this is not a real
    # challenge" cases and force the band to "weak" regardless of the declared
    # total, so a stub solver or a leaked flag can never read as strong.
    integrity_errors = _integrity_gate(challenge_path, solver, variant, spec)
    if integrity_errors:
        report.errors.extend(integrity_errors)
        report.band = "weak"
    return report


# Concrete, seed-derived flag: ``ctf{...}`` ending in the hex suffix families
# append. Excludes placeholders like ``ctf{...}``/``ctf{FLAG}``.
_CONCRETE_FLAG = re.compile(r"ctf\{[0-9a-z_]*[0-9a-f]{6}[0-9a-z_]*\}")


def _concrete_flag(challenge_path: Path, variant: dict | None) -> str | None:
    """The instance's real flag: variant.json's ``flag`` when present, else the
    first concrete flag token found in private/ or services/ source."""
    if isinstance(variant, dict):
        candidate = variant.get("flag")
        if isinstance(candidate, str) and _CONCRETE_FLAG.fullmatch(candidate):
            return candidate
    for sub in ("private", "services"):
        base = challenge_path / sub
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            try:
                match = _CONCRETE_FLAG.search(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, OSError):
                continue
            if match:
                return match.group(0)
    return None


def _integrity_gate(
    challenge_path: Path, solver: str, variant: dict | None, spec_text: str
) -> list[str]:
    """Return hard integrity errors that mean 'this is not a genuine, solvable
    challenge' -- an embedded flag (fake solver) or a flag leaked into a
    player-facing file (grep-solvable). Empty when the challenge is sound."""
    errors: list[str] = []
    flag = _concrete_flag(challenge_path, variant)
    if not flag:
        return errors

    # A genuine solver DERIVES the flag at runtime; embedding the literal means
    # the "solver" is a stub that just prints the answer.
    if flag in solver:
        errors.append(
            "integrity: private/solver.py embeds the literal flag -- a genuine "
            "solver must recover it, not print it"
        )

    # The flag must never appear in a file the player is handed, except a
    # defensive (blue) mode whose whole task is analysing a provided artifact.
    mode = _read_scalar(spec_text, "mode") or "red"
    if mode != "blue":
        public = challenge_path / "public"
        if public.is_dir():
            for path in sorted(public.rglob("*")):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                if flag in text:
                    rel = path.relative_to(challenge_path)
                    errors.append(f"integrity: flag leaks into public file {rel}")
                    break
    return errors


def _read_scalar(text: str, key: str) -> str | None:
    """Read a top-level ``key: value`` scalar from rendered challenge.yaml."""
    if not text:
        return None
    match = re.search(rf'^{re.escape(key)}:\s*"?([^"\r\n]*?)"?\s*$', text, re.MULTILINE)
    return match.group(1).strip() if match else None


def _resolve_scoring_hints(spec_text: str) -> ScoringHints:
    """Resolve a challenge's ``Family.scoring_hints`` from its rendered spec.

    Falls back to the default ``ScoringHints()`` (which reproduces today's
    hard-coded signals) when the family can't be resolved -- an unregistered
    or unknown family, or a spec with no top-level ``family:`` line.
    """
    family_name = families.family_of(spec_text) if spec_text else None
    if family_name and families.is_registered(family_name):
        return families.get(family_name).scoring_hints
    return ScoringHints()


def _variant_uniqueness(
    variant: dict, variation: dict[str, str], cve_refs: list[str] | None = None
) -> Dimension:
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
    notes = [
        f"{enabled}/{len(flags)} dynamic-variation dimensions enabled",
        f"{token_count} per-instance route/token values in variant.json",
    ]
    # Non-scoring provenance note: does not affect `score` above, purely
    # informational when this instance was grounded in a real-world CVE.
    for cve_id in cve_refs or []:
        notes.append(f"CVE-grounded: {cve_id}")
    return Dimension(
        name="variant_uniqueness",
        weight=0.25,
        score=score,
        notes=notes,
    )


def _statefulness(compose: str, solver: str, hints: ScoringHints) -> Dimension:
    has_worker = "worker:" in compose
    has_queue = "redis" in compose.lower()
    polls_status = bool(re.search(r"for .*in range", solver)) and "status" in solver

    # Only weigh in a signal the resolved family actually expects; a family
    # whose ScoringHints don't call for a worker/queue backend isn't
    # penalized for lacking one. Defaults (has_worker=has_queue=True)
    # reproduce today's fixed 3-signal check unchanged.
    signals: list[bool] = []
    notes: list[str] = []
    if hints.has_worker:
        signals.append(has_worker)
        notes.append(f"background worker service: {has_worker}")
    if hints.has_queue:
        signals.append(has_queue)
        notes.append(f"queue/state backend: {has_queue}")
    signals.append(polls_status)
    notes.append(f"solver drives async job state: {polls_status}")

    score = 100.0 * (sum(signals) / len(signals)) if signals else 100.0
    return Dimension(
        name="statefulness",
        weight=0.20,
        score=score,
        notes=notes,
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


def _live_interaction(
    solver: str, ai: dict[str, str], report: ScoreReport, hints: ScoringHints
) -> Dimension:
    requires_live = ai.get("require_live_interaction") == "true"
    discovers = "/api/profile" in solver
    polls = bool(re.search(r"for .*in range", solver))

    notes = [
        f"spec requires live interaction: {requires_live}",
        f"solver discovers routes at runtime: {discovers}",
        f"solver polls a live endpoint: {polls}",
    ]
    # A family that doesn't hint at live interaction (hints.live_interaction
    # is False) isn't scored against these three signals at all. Default
    # (True) reproduces today's fixed 3-signal check unchanged.
    if hints.live_interaction:
        signals = [requires_live, discovers, polls]
        score = 100.0 * (sum(signals) / len(signals))
    else:
        score = 100.0
    return Dimension(
        name="live_interaction",
        weight=0.15,
        score=score,
        notes=notes,
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


# Weight the conditional scenario_resistance dimension gets when a challenge
# opts into a live scenario timeline (``scenario.enabled: true``). The other
# five dimensions' weights are rescaled down proportionally so all weights
# keep summing to 1.0; see `_rescale_weights`. When scenario is absent (the
# default) this dimension and rescale never run, so today's five fixed
# weights (0.25/0.20/0.20/0.15/0.20) are untouched.
_SCENARIO_RESISTANCE_WEIGHT = 0.15


def _rescale_weights(dimensions: list[Dimension], reserved_weight: float) -> None:
    """Scale existing dimension weights down so they leave room for one more.

    Preserves each dimension's weight *proportion* relative to the others
    while making room for ``reserved_weight`` of total weight, so the full
    dimension set (existing + new) still sums to 1.0.
    """
    factor = 1.0 - reserved_weight
    for dimension in dimensions:
        dimension.weight *= factor


def _scenario_resistance(spec_text: str) -> Dimension:
    """Score how much a live scenario timeline resists a static, one-shot solve.

    Purely a function of the declared ``scenario`` block in challenge.yaml:
    more distinct triggers/responses and a wider variety of trigger
    conditions / response actions mean a player can't just replay a single
    recorded trace and expect it to still work once the timeline reacts.
    """
    scenario_lines = _extract_block_lines(spec_text, "scenario")
    scenario_block = "\n".join(scenario_lines)

    trigger_count = scenario_block.count("trigger_id:")
    response_count = scenario_block.count("response_id:")
    conditions = {
        m.strip() for m in re.findall(r"condition: (.+)", scenario_block) if m.strip('"').strip()
    }
    actions = {
        m.strip() for m in re.findall(r"action: (.+)", scenario_block) if m.strip('"').strip()
    }

    trigger_score = 100.0 * min(1.0, trigger_count / 3.0)
    response_score = 100.0 * min(1.0, response_count / 3.0)
    diversity_score = 100.0 * min(1.0, (len(conditions) + len(actions)) / 4.0)
    score = (trigger_score + response_score + diversity_score) / 3.0

    return Dimension(
        name="scenario_resistance",
        weight=_SCENARIO_RESISTANCE_WEIGHT,
        score=score,
        notes=[
            f"{trigger_count} scenario trigger(s) declared",
            f"{response_count} scripted response(s) declared",
            f"{len(conditions)} distinct trigger condition(s), "
            f"{len(actions)} distinct response action(s)",
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


def _extract_block_lines(text: str, block_name: str) -> list[str]:
    """Return the raw (still-indented) lines nested under a top-level key.

    Unlike ``_read_block`` (which only keeps flat scalar ``key: value``
    lines), this keeps every line of the block verbatim -- including nested
    sub-blocks and list items -- for callers that need to scan deeper
    structure (e.g. ``scenario.triggers``/``scenario.responses``).
    """
    if not text:
        return []
    lines = text.splitlines()
    inside = False
    collected: list[str] = []
    for line in lines:
        if not inside:
            if line.rstrip() == f"{block_name}:":
                inside = True
            continue
        if line and not line.startswith(" "):
            break
        collected.append(line)
    return collected


def _read_list_block(text: str, block_name: str) -> list[str]:
    """Parse a top-level flat string list (2-space ``- "value"`` items)."""
    values: list[str] = []
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
        match = re.match(r"^  - (.+)$", line)
        if match:
            values.append(match.group(1).strip().strip('"'))
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


# --- score_with_agent_eval (Phase 5) -------------------------------------------
#
# Standalone function combining the static score_challenge() result with a
# previously-saved agent_eval report (a JSON report artifact written by the
# `eval-agent` CLI command via report_writer.write_report). Never modifies
# score_challenge()/ScoreReport themselves -- this is purely an additional,
# opt-in view layered on top.


def score_with_agent_eval(
    challenge_path: Path, eval_report_path: Path | None = None
) -> dict[str, object]:
    """Blend the static AI-resistance score with a saved agent-eval report.

    Always runs the unmodified ``score_challenge`` first; ``static`` in the
    returned mapping is exactly ``ScoreReport.to_mapping()``. When
    ``eval_report_path`` is ``None`` (the default), ``agent_eval`` is ``None``
    and ``blended_score`` simply equals the static total -- so a caller that
    never supplies an eval report gets today's static score back, unchanged.

    When given, ``eval_report_path`` is read as a JSON report artifact
    produced by ``report_writer.build_report``/``write_report`` for either
    the ``eval-agent`` command (``report_writer.serialize_agent_eval`` shape,
    detected by a top-level ``"solved"`` key) or ``eval-agent --adversarial``
    (``report_writer.serialize_adversarial_delta`` shape, detected by
    top-level ``"baseline"``/``"adversarial"`` keys). A missing/unreadable
    file or an unrecognized shape is recorded as a warning rather than
    raising, mirroring this module's existing best-effort read helpers
    (``_read_json``/``_read_text``).

    ``blended_score`` is a simple, deterministic weighted mix: 70% the static
    total, 30% an eval component that is 100 when the agent did *not* solve
    the live challenge (the resistant outcome) and 0 when it did -- using the
    adversarial (harder) leg's outcome when an adversarial-delta report was
    supplied.
    """
    static_report = score_challenge(challenge_path)
    static_mapping = static_report.to_mapping()
    blended: dict[str, object] = {
        "static": static_mapping,
        "agent_eval": None,
        "blended_score": static_mapping["total"],
        "warnings": list(static_report.warnings),
    }
    if eval_report_path is None:
        return blended

    eval_report_path = Path(eval_report_path)
    try:
        payload = json.loads(eval_report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        blended["warnings"].append(f"could not read agent-eval report: {exc}")
        return blended

    result = payload.get("result", payload) if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        blended["warnings"].append("agent-eval report has an unrecognized shape")
        return blended

    if "baseline" in result and "adversarial" in result:
        adversarial = result.get("adversarial") or {}
        baseline = result.get("baseline") or {}
        solved = bool(adversarial.get("solved"))
        agent_summary: dict[str, object] = {
            "kind": "adversarial_delta",
            "profile": result.get("profile"),
            "baseline_solved": bool(baseline.get("solved")),
            "adversarial_solved": solved,
            "success_dropped": bool(result.get("success_dropped")),
        }
    elif "solved" in result:
        solved = bool(result.get("solved"))
        agent_summary = {
            "kind": "agent_eval",
            "profile": result.get("profile"),
            "solved": solved,
            "steps": result.get("steps"),
        }
    else:
        blended["warnings"].append("agent-eval report has an unrecognized shape")
        return blended

    eval_component = 0.0 if solved else 100.0
    blended["agent_eval"] = agent_summary
    blended["blended_score"] = round(
        0.7 * float(static_mapping["total"]) + 0.3 * eval_component, 1
    )
    return blended
