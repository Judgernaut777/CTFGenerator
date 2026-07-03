from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .families import Family


# Back-compat alias: this used to be the sole hard-coded list of required
# files for every generated challenge. It now describes only the
# ``web_business_logic_tenant_export`` family (families.py mirrors it back
# into that family's ``required_files`` at registration time). Kept here,
# unchanged, so existing importers keep working.
REQUIRED_FILES = [
    "challenge.yaml",
    "docker-compose.yml",
    "services/api/Dockerfile",
    "services/api/app.py",
    "services/api/requirements.txt",
    "services/worker/Dockerfile",
    "services/worker/worker.py",
    "services/worker/requirements.txt",
    "public/description.md",
    "public/hints.yaml",
    "private/solution.md",
    "private/solver.py",
    "private/variant.json",
    "private/checkpoints.yaml",
    "tests/healthcheck.py",
    "tests/validate_solver.py",
    "tests/validate_variant.py",
]


# A top-level ``scenario:`` block in rendered challenge.yaml text, with its
# ``enabled:`` child line. Mirrors the indentation-sensitive parsing style of
# ``families.family_of``: only a zero-indent ``scenario:`` line opens the
# block, and only indented lines inside it are inspected for ``enabled``.
_SCENARIO_LINE = re.compile(r"^scenario:\s*$")
_ENABLED_LINE = re.compile(r"^\s+enabled:\s*(true|false)\s*$")


def _scenario_enabled(challenge_yaml_text: str) -> bool:
    """Best-effort parse of ``scenario.enabled`` out of challenge.yaml text.

    Returns ``False`` if no top-level ``scenario:`` block is present (the
    default, back-compat case), or if the block doesn't declare ``enabled``.
    """
    in_scenario = False
    for line in challenge_yaml_text.splitlines():
        if not line.startswith(" "):
            in_scenario = bool(_SCENARIO_LINE.match(line))
            continue
        if in_scenario:
            match = _ENABLED_LINE.match(line)
            if match:
                return match.group(1) == "true"
    return False


def _resolve_family(spec_text: str | None) -> "Family | None":
    """Resolve the registered ``Family`` a rendered challenge.yaml declares.

    Returns ``None`` (never raises) whenever resolution isn't possible: no
    spec text, no top-level ``family:`` field, or an unregistered family
    name. Callers fall back to a minimal generic check in that case.
    """
    if not spec_text:
        return None
    try:
        # Imported lazily: families.py imports REQUIRED_FILES from this
        # module at import time, so a module-level import here would be
        # circular.
        from . import families
    except ImportError:
        return None

    try:
        name = families.family_of(spec_text)
        if not name or not families.is_registered(name):
            return None
        return families.get(name)
    except Exception:
        return None


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _validate_against_family(
    challenge_path: Path, family: "Family", report: ValidationReport
) -> None:
    for relative in family.required_files:
        path = challenge_path / relative
        if not path.exists():
            report.errors.append(f"missing required file: {relative}")
        elif path.is_file() and path.stat().st_size == 0:
            report.errors.append(f"required file is empty: {relative}")

    compose = challenge_path / "docker-compose.yml"
    if compose.exists() and family.compose_service_markers:
        text = compose.read_text(encoding="utf-8")
        for marker in family.compose_service_markers:
            if marker not in text:
                report.errors.append(f"docker-compose.yml missing service marker {marker}")

    spec = challenge_path / "challenge.yaml"
    if spec.exists():
        text = spec.read_text(encoding="utf-8")
        for marker in ("meta:", "ai_resistance:", "dynamic_variation:", "checkpoints:"):
            if marker not in text:
                report.errors.append(f"challenge.yaml missing {marker}")

    solver = challenge_path / "private/solver.py"
    if solver.exists() and "argparse" not in solver.read_text(encoding="utf-8"):
        report.warnings.append("private solver does not appear to expose CLI arguments")


def _validate_generic(
    spec_path: Path, spec_text: str | None, report: ValidationReport
) -> None:
    """Minimal fallback check used when the family can't be resolved.

    Only asserts that ``challenge.yaml`` exists, is non-empty, and looks
    roughly like YAML (has at least one ``key:`` style line) -- it does not
    require any of the family-specific scaffolding files.
    """
    if spec_text is None:
        report.errors.append("missing required file: challenge.yaml")
        return
    if spec_path.stat().st_size == 0:
        report.errors.append("required file is empty: challenge.yaml")
        return
    if not any(":" in line for line in spec_text.splitlines()):
        report.errors.append(
            "challenge.yaml does not look like valid YAML (no key: value lines found)"
        )


def validate_challenge(challenge_path: Path) -> ValidationReport:
    report = ValidationReport()
    if not challenge_path.exists():
        report.errors.append(f"{challenge_path} does not exist")
        return report
    if not challenge_path.is_dir():
        report.errors.append(f"{challenge_path} is not a directory")
        return report

    spec_path = challenge_path / "challenge.yaml"
    spec_text = spec_path.read_text(encoding="utf-8") if spec_path.exists() else None

    family = _resolve_family(spec_text)
    if family is not None:
        _validate_against_family(challenge_path, family, report)
    else:
        _validate_generic(spec_path, spec_text, report)

    # Soft check: a scenario-enabled challenge should ship a timeline the
    # scenario engine can replay. Missing/unparseable is a warning, not a
    # hard error, since this is new surface area that shouldn't break
    # existing (non-scenario) challenges or block generation outright.
    if spec_text is not None and _scenario_enabled(spec_text):
        timeline = challenge_path / "private/scenario_timeline.json"
        if not timeline.exists():
            report.warnings.append(
                "scenario.enabled is true but private/scenario_timeline.json is missing"
            )
        else:
            try:
                json.loads(timeline.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                report.warnings.append(
                    f"private/scenario_timeline.json is not valid JSON: {exc}"
                )

    return report
