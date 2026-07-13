"""Host guard over the S1-S9 security-gate -> executed-test mapping (M20).

Not a security test itself: a machine-checkable guard that keeps
``docs/validation/security-checklist.md`` honest. For every standing gate it
proves the cited test MODULE(S) exist on disk and are importable/collectable, so
the mapping cannot silently rot (a renamed/deleted security module fails here).
It does NOT run the PG-/Docker-gated tests -- it only imports + collects them,
which needs no PostgreSQL, Docker, or network. Pure host test.

Run:
    PYTHONPATH=src:tests python -m unittest test_security_validation_meta
"""

from __future__ import annotations

import importlib
import re
import unittest
from pathlib import Path

# Canonical mapping: S-gate -> the test modules cited for it in the checklist.
# Keep this in lock-step with docs/validation/security-checklist.md; the tests
# below prove the doc names every module listed here and covers every gate.
GATE_MODULES: dict[str, tuple[str, ...]] = {
    "S1": ("test_api_authz_scoping_integration", "test_api_instances_integration"),
    "S2": ("test_team_isolation_integration", "test_docker_backend_integration"),
    "S3": ("test_api_authz_scoping_integration", "test_team_isolation_integration"),
    "S4": ("test_public_flag_leak", "test_score"),
    "S5": ("test_logging_redaction",),
    "S6": ("test_build_hardening", "test_mcp_server"),
    "S7": (
        "test_api_auth_integration",
        "test_api_instances_integration",
        "test_web_security",
    ),
    "S8": (
        "test_ledger_repository_integration",
        "test_restore_verify_integration",
        "test_migration_drift_integration",
    ),
    "S9": ("test_mcp_server", "test_architecture_boundaries"),
}

_TESTS_DIR = Path(__file__).resolve().parent
_CHECKLIST = (
    _TESTS_DIR.parent / "docs" / "validation" / "security-checklist.md"
)


class GateModulesExistAndCollect(unittest.TestCase):
    def test_gate_keys_are_exactly_s1_through_s9(self) -> None:
        self.assertEqual(
            sorted(GATE_MODULES), [f"S{i}" for i in range(1, 10)]
        )

    def test_every_cited_module_file_exists(self) -> None:
        for gate, mods in GATE_MODULES.items():
            for mod in mods:
                path = _TESTS_DIR / f"{mod}.py"
                with self.subTest(gate=gate, module=mod):
                    self.assertTrue(
                        path.is_file(),
                        f"{gate}: cited security test {path} is missing",
                    )

    def test_every_cited_module_imports_and_collects(self) -> None:
        # Import + collect proves the module is real and its TestCases load
        # (skipped-by-env tests still collect). Does NOT execute PG/Docker tests.
        loader = unittest.TestLoader()
        seen: dict[str, int] = {}
        for gate, mods in GATE_MODULES.items():
            for mod in mods:
                if mod in seen:
                    continue
                with self.subTest(gate=gate, module=mod):
                    module = importlib.import_module(mod)
                    suite = loader.loadTestsFromModule(module)
                    count = suite.countTestCases()
                    self.assertGreater(
                        count, 0, f"{gate}: {mod} collected no test cases"
                    )
                    seen[mod] = count


class ChecklistDocGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(
            _CHECKLIST.is_file(), f"checklist doc missing: {_CHECKLIST}"
        )
        self.text = _CHECKLIST.read_text(encoding="utf-8")

    def test_doc_lists_every_gate_s1_through_s9(self) -> None:
        for i in range(1, 10):
            with self.subTest(gate=f"S{i}"):
                self.assertRegex(
                    self.text,
                    rf"\bS{i}\b",
                    f"S{i} not mentioned in {_CHECKLIST.name}",
                )

    def test_doc_names_every_cited_module(self) -> None:
        # The doc must reference each module by its real path so a reader can
        # open it; ties the mapping to the prose.
        cited = {m for mods in GATE_MODULES.values() for m in mods}
        for mod in sorted(cited):
            with self.subTest(module=mod):
                self.assertIn(
                    f"tests/{mod}.py",
                    self.text,
                    f"checklist doc does not cite tests/{mod}.py",
                )

    def test_doc_declares_a_status_column(self) -> None:
        # Guards against the table being gutted to a bare list of names.
        self.assertRegex(self.text, r"PG-gated")
        self.assertRegex(self.text, r"Docker-gated")
        # Every gate row must carry an honest run-location word.
        for i in range(1, 10):
            row = re.search(rf"\|\s*\*\*S{i}\*\*\s*\|.*", self.text)
            with self.subTest(gate=f"S{i}"):
                self.assertIsNotNone(row, f"no table row for S{i}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
