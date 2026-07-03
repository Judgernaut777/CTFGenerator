from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


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


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_challenge(challenge_path: Path) -> ValidationReport:
    report = ValidationReport()
    if not challenge_path.exists():
        report.errors.append(f"{challenge_path} does not exist")
        return report
    if not challenge_path.is_dir():
        report.errors.append(f"{challenge_path} is not a directory")
        return report

    for relative in REQUIRED_FILES:
        path = challenge_path / relative
        if not path.exists():
            report.errors.append(f"missing required file: {relative}")
        elif path.is_file() and path.stat().st_size == 0:
            report.errors.append(f"required file is empty: {relative}")

    compose = challenge_path / "docker-compose.yml"
    if compose.exists():
        text = compose.read_text(encoding="utf-8")
        for service in ("api:", "worker:"):
            if service not in text:
                report.errors.append(f"docker-compose.yml missing service marker {service}")

    spec = challenge_path / "challenge.yaml"
    if spec.exists():
        text = spec.read_text(encoding="utf-8")
        for marker in ("meta:", "ai_resistance:", "dynamic_variation:", "checkpoints:"):
            if marker not in text:
                report.errors.append(f"challenge.yaml missing {marker}")

    solver = challenge_path / "private/solver.py"
    if solver.exists() and "argparse" not in solver.read_text(encoding="utf-8"):
        report.warnings.append("private solver does not appear to expose CLI arguments")

    return report
