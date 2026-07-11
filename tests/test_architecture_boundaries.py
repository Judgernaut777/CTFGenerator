"""Architectural import-boundary tests (Milestone 5).

Enforces the layering in docs/architecture/dependency-rules.md at CI time so the
domain core cannot silently regain a dependency on framework, I/O, or
infrastructure code as the refactor proceeds. Today the populated layer is
``domain``; the checks are written to extend to ``application``/``interfaces``
as those layers fill in.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src" / "ctf_generator"

# Third-party / stdlib modules that imply framework, network, or process I/O.
# The domain layer must not touch any of these.
_FORBIDDEN_TOP_LEVEL = {
    "http", "socket", "subprocess", "urllib", "asyncio", "selectors",
    "fastapi", "starlette", "uvicorn", "flask", "werkzeug", "requests",
    "sqlalchemy", "alembic", "psycopg", "psycopg2",
    "anthropic", "openai", "mcp", "docker",
}

# Effectful / infrastructure / interface modules inside the package that the
# domain layer must never import (by their ctf_generator.-relative dotted name).
_FORBIDDEN_INTERNAL = {
    "ctf_generator.infrastructure",
    "ctf_generator.interfaces",
    "ctf_generator.workers",
    # Legacy flat modules that carry I/O or framework concerns (pre-refactor).
    "ctf_generator.runtime_validator",
    "ctf_generator.replay_validator",
    "ctf_generator.sibling_validator",
    "ctf_generator.scenario_runtime",
    "ctf_generator.agent_eval",
    "ctf_generator.dashboard_server",
    "ctf_generator.dashboard_ui",
    "ctf_generator.competition_service",
    "ctf_generator.postgres_events",
    "ctf_generator.mcp_server",
    "ctf_generator.cve_source",
    "ctf_generator.report_writer",
    "ctf_generator.report_index",
    "ctf_generator.runtime_validator",
    "ctf_generator.cli",
    "ctf_generator.generator",
    "ctf_generator.validator",
    "ctf_generator.build",
}


def _module_dotted_name(path: Path) -> str:
    rel = path.relative_to(_SRC.parent).with_suffix("")
    return ".".join(rel.parts)


def _imports_of(path: Path) -> set[str]:
    """Return the set of fully-qualified module names imported by ``path``,
    resolving relative imports against the module's own package."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    dotted = _module_dotted_name(path)
    pkg_parts = dotted.split(".")[:-1]  # containing package
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                # Resolve `from ...x import y` relative to the package.
                anchor = pkg_parts[: len(pkg_parts) - (node.level - 1)]
                base = ".".join([*anchor, node.module]) if node.module else ".".join(anchor)
            names.add(base)
            for alias in node.names:
                names.add(f"{base}.{alias.name}" if base else alias.name)
    return {n for n in names if n}


def _domain_modules() -> list[Path]:
    return sorted((_SRC / "domain").rglob("*.py"))


class DomainBoundaryTests(unittest.TestCase):
    def test_domain_layer_exists(self) -> None:
        self.assertTrue(_domain_modules(), "no domain modules found")

    def test_domain_has_no_forbidden_imports(self) -> None:
        for path in _domain_modules():
            imports = _imports_of(path)
            for name in imports:
                top = name.split(".")[0]
                with self.subTest(module=_module_dotted_name(path), imports=name):
                    self.assertNotIn(
                        top, _FORBIDDEN_TOP_LEVEL,
                        f"{path.name} imports framework/IO module {name!r}",
                    )
                    for forbidden in _FORBIDDEN_INTERNAL:
                        self.assertFalse(
                            name == forbidden or name.startswith(forbidden + "."),
                            f"{path.name} imports infrastructure/effectful module {name!r}",
                        )

    def test_domain_models_importable_via_domain_and_shim(self) -> None:
        from ctf_generator.domain.challenges.models import ChallengeSpec as DomainSpec
        from ctf_generator.models import ChallengeSpec as ShimSpec

        # The shim must re-export the *same* class object (identity preserved,
        # so isinstance and dataclass equality still work across call sites).
        self.assertIs(DomainSpec, ShimSpec)


if __name__ == "__main__":
    unittest.main()
