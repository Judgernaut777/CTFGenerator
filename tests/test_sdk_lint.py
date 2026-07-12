"""Structural linter: clean on every built-in family, correct on crafted bad ones."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from ctf_generator import families, sdk
from ctf_generator.sdk import lint


def _render_ok(spec, rng, cve_record=None):
    return {
        "public/description.md": "A benign public description.\n",
        "private/solution.md": "The private answer.\n",
    }


def _family(**overrides):
    base = dict(
        name="probe_family",
        category="web",
        modes=("red",),
        render=_render_ok,
        required_files=("challenge.yaml", "public/description.md", "private/solution.md"),
    )
    base.update(overrides)
    return sdk.Family(**base)


class BuiltinFamiliesLintCleanTests(unittest.TestCase):
    def test_all_eight_builtins_lint_clean(self) -> None:
        names = families.family_names()
        self.assertGreaterEqual(len(names), 8)
        for name in names:
            with self.subTest(family=name):
                issues = lint.lint_family(families.get(name))
                errors = [i for i in issues if i.severity == "error"]
                self.assertEqual(
                    errors, [], f"{name} produced lint errors: {[str(e) for e in errors]}"
                )

    def test_assert_family_ok_passes_for_builtins(self) -> None:
        for name in families.family_names():
            with self.subTest(family=name):
                lint.assert_family_ok(families.get(name))  # must not raise


class MissingRequiredFileTests(unittest.TestCase):
    def test_required_file_not_rendered_is_flagged(self) -> None:
        fam = _family(
            required_files=("challenge.yaml", "tests/never_rendered.py"),
        )
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("MISSING_REQUIRED_FILE", codes)
        with self.assertRaises(lint.FamilyLintError):
            lint.assert_family_ok(fam)


class UnsafePathTests(unittest.TestCase):
    def test_absolute_path_is_flagged(self) -> None:
        def render(spec, rng, cve_record=None):
            return {"/etc/passwd": "pwned", "public/description.md": "ok"}

        fam = _family(render=render, required_files=("challenge.yaml",))
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("UNSAFE_PATH", codes)
        with self.assertRaises(lint.FamilyLintError):
            lint.assert_family_ok(fam)

    def test_traversal_path_is_flagged(self) -> None:
        def render(spec, rng, cve_record=None):
            return {"public/../../evil.sh": "x", "public/description.md": "ok"}

        fam = _family(render=render, required_files=("challenge.yaml",))
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("UNSAFE_PATH", codes)

    def test_path_outside_allowed_root_is_flagged(self) -> None:
        def render(spec, rng, cve_record=None):
            return {"weird_root/thing.txt": "x", "public/description.md": "ok"}

        fam = _family(render=render, required_files=("challenge.yaml",))
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("PATH_OUTSIDE_ROOT", codes)


class PrivateLeakTests(unittest.TestCase):
    def test_flag_leaked_into_public_is_flagged(self) -> None:
        def render(spec, rng, cve_record=None):
            return {
                "private/variant.json": '{"flag": "ctf{secret_leak_9f}"}',
                "public/description.md": "hint: the flag is ctf{secret_leak_9f}\n",
            }

        fam = _family(render=render, required_files=("challenge.yaml",))
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("PRIVATE_CONTENT_IN_PUBLIC", codes)
        with self.assertRaises(lint.FamilyLintError):
            lint.assert_family_ok(fam)

    def test_byte_identical_private_public_file_is_flagged(self) -> None:
        def render(spec, rng, cve_record=None):
            body = "leaky shared content\n"
            return {"private/answer.md": body, "public/answer.md": body}

        fam = _family(render=render, required_files=("challenge.yaml",))
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("PRIVATE_CONTENT_IN_PUBLIC", codes)


class MetadataTests(unittest.TestCase):
    def test_bad_semver_and_isolation_flagged(self) -> None:
        fam = _family(
            required_files=("challenge.yaml",),
            version="not-a-semver",
            isolation_level="rootful-vm",
        )
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("BAD_VERSION", codes)
        self.assertIn("BAD_ISOLATION_LEVEL", codes)
        with self.assertRaises(lint.FamilyLintError):
            lint.assert_family_ok(fam)

    def test_bad_maintenance_status_flagged(self) -> None:
        fam = _family(required_files=("challenge.yaml",), maintenance_status="gold")
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("BAD_MAINTENANCE_STATUS", codes)

    def test_empty_modes_and_bad_mode_flagged(self) -> None:
        fam_empty = _family(required_files=("challenge.yaml",), modes=())
        codes_empty = {i.code for i in lint.lint_family(fam_empty) if i.severity == "error"}
        self.assertIn("BAD_MODES", codes_empty)

        fam_bad = _family(required_files=("challenge.yaml",), modes=("chartreuse",))
        codes_bad = {i.code for i in lint.lint_family(fam_bad) if i.severity == "error"}
        self.assertIn("BAD_MODES", codes_bad)

    def test_empty_category_flagged(self) -> None:
        fam = _family(required_files=("challenge.yaml",), category="")
        codes = {i.code for i in lint.lint_family(fam) if i.severity == "error"}
        self.assertIn("EMPTY_CATEGORY", codes)

    def test_render_that_crashes_is_a_finding_not_an_exception(self) -> None:
        def render(spec, rng, cve_record=None):
            raise RuntimeError("boom")

        fam = _family(render=render, required_files=("challenge.yaml",))
        issues = lint.lint_family(fam)  # must not raise
        self.assertIn("RENDER_FAILED", {i.code for i in issues})


_EVIL_MODULE_SRC = '''\
"""A renderer module that violates the circular-import contract."""

FAMILY_NAME = "evil_import_module_family"
CATEGORY = "web"
MODES = ("red",)
DIFFICULTIES = ("easy", "medium", "hard")
CVE_DRIVEN = False
LLM_BRIEF = "x"
COMPOSE_MARKERS = ()
SCORING_HINTS = {}
REQUIRED_FILES = ("challenge.yaml", "public/description.md")

from ctf_generator import families  # FORBIDDEN: circular-import contract violation


def render(spec, rng, cve_record=None):
    _ = families  # pretend to use it
    return {"public/description.md": "ok"}
'''


class RendererModuleLintTests(unittest.TestCase):
    def test_module_importing_families_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mod_path = Path(tmp) / "evil_family_module.py"
            mod_path.write_text(_EVIL_MODULE_SRC, encoding="utf-8")
            spec = importlib.util.spec_from_file_location("evil_family_module", mod_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            issues = lint.lint_renderer_module(module)
            codes = {i.code for i in issues if i.severity == "error"}
            self.assertIn("MODULE_IMPORTS_FAMILIES", codes)

    def test_module_missing_interface_attr_is_flagged(self) -> None:
        # A module that does not expose the full renderer interface (here: no
        # `render`) cannot be adapted -> MODULE_INTERFACE (a finding, not a raise).
        import types

        mod = types.ModuleType("incomplete_family_module")
        mod.FAMILY_NAME = "incomplete_family"
        mod.CATEGORY = "web"
        mod.MODES = ("red",)
        mod.REQUIRED_FILES = ("challenge.yaml",)
        # deliberately NO `render` (and other constants missing)
        issues = lint.lint_renderer_module(mod)
        self.assertIn("MODULE_INTERFACE", {i.code for i in issues})

    def test_source_scan_detects_all_import_forms(self) -> None:
        for src in (
            "import ctf_generator.families",
            "from ctf_generator.families import Family",
            "from ctf_generator import families",
            "from . import families",
            "from .families import Family",
        ):
            with self.subTest(src=src):
                self.assertTrue(lint._families_imported_by_source(src))
        self.assertFalse(lint._families_imported_by_source("import ctf_generator.models"))


if __name__ == "__main__":
    unittest.main()
