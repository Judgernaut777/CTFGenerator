"""External family registration via entry points: discovery, lint, fail-safe."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from ctf_generator import families, sdk
from ctf_generator.sdk import plugins


class _FakeEntryPoint:
    """Mimics importlib.metadata.EntryPoint: name/value/group + load()."""

    def __init__(self, name: str, loader, value: str | None = None) -> None:
        self.name = name
        self.value = value or f"fake.module:{name}"
        self.group = plugins.ENTRY_POINT_GROUP
        self._loader = loader

    def load(self):
        return self._loader()


def _good_render(spec, rng, cve_record=None):
    return {
        "public/description.md": "public brief\n",
        "private/solution.md": "the answer\n",
    }


def _good_family(name: str) -> sdk.Family:
    return sdk.Family(
        name=name,
        category="web",
        modes=("red",),
        render=_good_render,
        required_files=("challenge.yaml", "public/description.md"),
    )


def _lint_failing_family(name: str) -> sdk.Family:
    # Declares a required file it never renders -> MISSING_REQUIRED_FILE.
    return sdk.Family(
        name=name,
        category="web",
        modes=("red",),
        render=_good_render,
        required_files=("challenge.yaml", "tests/never_rendered.py"),
    )


_PLUGIN_NAMES = (
    "sdk_plugin_direct_family",
    "sdk_plugin_factory_family",
    "sdk_plugin_bad_lint_family",
)


class LoadEntryPointFamiliesTests(unittest.TestCase):
    def setUp(self) -> None:
        plugins._reset_for_tests()
        self._cleanup_registry()

    def tearDown(self) -> None:
        plugins._reset_for_tests()
        self._cleanup_registry()

    def _cleanup_registry(self) -> None:
        for name in _PLUGIN_NAMES:
            families._REGISTRY.pop(name, None)

    def _patch(self, eps):
        return mock.patch("importlib.metadata.entry_points", return_value=eps)

    def test_valid_plugins_register_bad_ones_skipped(self) -> None:
        def raiser():
            raise RuntimeError("import blew up")

        eps = [
            _FakeEntryPoint("direct", lambda: _good_family("sdk_plugin_direct_family")),
            # a zero-arg callable/factory returning a Family
            _FakeEntryPoint(
                "factory", lambda: (lambda: _good_family("sdk_plugin_factory_family"))
            ),
            _FakeEntryPoint("raises", raiser),
            _FakeEntryPoint("nonfamily", lambda: {"not": "a family"}),
            _FakeEntryPoint(
                "badlint", lambda: _lint_failing_family("sdk_plugin_bad_lint_family")
            ),
        ]
        with self._patch(eps):
            with self.assertLogs(plugins.logger, level="WARNING") as logctx:
                registered = plugins.load_entry_point_families()

        # Both valid plugins registered; the three broken ones skipped.
        self.assertIn("sdk_plugin_direct_family", registered)
        self.assertIn("sdk_plugin_factory_family", registered)
        self.assertTrue(families.is_registered("sdk_plugin_direct_family"))
        self.assertTrue(families.is_registered("sdk_plugin_factory_family"))
        self.assertIs(families.get("sdk_plugin_direct_family").render, _good_render)

        self.assertFalse(families.is_registered("sdk_plugin_bad_lint_family"))
        # A skip was logged for each of the three broken plugins.
        warnings = "\n".join(logctx.output)
        self.assertIn("raises", warnings)
        self.assertIn("nonfamily", warnings)
        self.assertIn("badlint", warnings)

    def test_one_bad_plugin_does_not_block_a_sibling(self) -> None:
        def raiser():
            raise ValueError("boom")

        eps = [
            _FakeEntryPoint("raises", raiser),
            _FakeEntryPoint("direct", lambda: _good_family("sdk_plugin_direct_family")),
        ]
        with self._patch(eps):
            with self.assertLogs(plugins.logger, level="WARNING"):
                plugins.load_entry_point_families()
        self.assertTrue(families.is_registered("sdk_plugin_direct_family"))

    def test_loading_is_idempotent(self) -> None:
        eps = [_FakeEntryPoint("direct", lambda: _good_family("sdk_plugin_direct_family"))]
        with self._patch(eps):
            first = plugins.load_entry_point_families()
            second = plugins.load_entry_point_families()  # must not error/double
        self.assertEqual(first, ["sdk_plugin_direct_family"])
        self.assertEqual(second, [])  # already loaded -> nothing new
        self.assertTrue(families.is_registered("sdk_plugin_direct_family"))

    def test_on_error_raise_propagates(self) -> None:
        def raiser():
            raise RuntimeError("strict mode")

        eps = [_FakeEntryPoint("raises", raiser)]
        with self._patch(eps):
            with self.assertLogs(plugins.logger, level="WARNING"):
                with self.assertRaises(RuntimeError):
                    plugins.load_entry_point_families(on_error="raise")

    def test_no_entry_points_is_a_noop(self) -> None:
        with self._patch([]):
            self.assertEqual(plugins.load_entry_point_families(), [])

    def test_plugin_colliding_with_builtin_is_refused_not_clobbered(self) -> None:
        # SECURITY: a plugin whose family.name equals a BUILT-IN must NOT replace
        # it -- otherwise third-party render code hijacks a deterministic-core
        # family under a known name. The incumbent survives; a warning is logged.
        builtin = "crypto_token_forgery"
        self.assertTrue(families.is_registered(builtin))
        incumbent = families.get(builtin)
        self.assertIsNot(incumbent.render, _good_render)

        eps = [_FakeEntryPoint("evil", lambda: _good_family(builtin))]
        with self._patch(eps):
            with self.assertLogs(plugins.logger, level="WARNING") as logctx:
                registered = plugins.load_entry_point_families()

        self.assertEqual(registered, [])  # nothing new registered
        # The built-in is UNCHANGED -- same object, not the plugin's render.
        self.assertIs(families.get(builtin), incumbent)
        self.assertIsNot(families.get(builtin).render, _good_render)
        self.assertIn("already registered", "\n".join(logctx.output))

    def test_renderer_module_plugin_is_adapted_and_registered(self) -> None:
        # The loader's renderer-MODULE path: an entry point resolving to a module
        # exposing the interface constants + render is adapted to a Family and
        # registered (module coercion + on-success register).
        import types

        mod = types.ModuleType("fake_sdk_plugin_mod")
        mod.FAMILY_NAME = "sdk_plugin_direct_family"
        mod.CATEGORY = "web"
        mod.MODES = ("red",)
        mod.DIFFICULTIES = ("easy", "medium", "hard")
        mod.CVE_DRIVEN = False
        mod.LLM_BRIEF = "brief"
        mod.COMPOSE_MARKERS = ()
        mod.SCORING_HINTS = {}
        mod.REQUIRED_FILES = ("challenge.yaml", "public/description.md")
        mod.render = _good_render

        eps = [_FakeEntryPoint("mod", lambda: mod)]
        with self._patch(eps):
            # A dynamically-built module has no retrievable source -> a benign
            # MODULE_SOURCE_UNAVAILABLE *warning* (not an error), so it registers.
            registered = plugins.load_entry_point_families()
        self.assertEqual(registered, ["sdk_plugin_direct_family"])
        self.assertTrue(families.is_registered("sdk_plugin_direct_family"))

    def test_renderer_module_importing_families_is_skipped_by_loader(self) -> None:
        # The loader's extra module-import-contract enforcement: a renderer MODULE
        # whose SOURCE imports ctf_generator.families is skipped (MODULE_IMPORTS_
        # FAMILIES), even though it adapts to a shape-valid Family.
        import importlib.util
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad_renderer_plugin.py"
            path.write_text(
                "import ctf_generator.families  # forbidden circular-contract import\n"
                "FAMILY_NAME = 'sdk_plugin_bad_lint_family'\n"
                "CATEGORY = 'web'\n"
                "MODES = ('red',)\n"
                "DIFFICULTIES = ('easy', 'medium', 'hard')\n"
                "CVE_DRIVEN = False\n"
                "LLM_BRIEF = 'b'\n"
                "COMPOSE_MARKERS = ()\n"
                "SCORING_HINTS = {}\n"
                "REQUIRED_FILES = ('challenge.yaml', 'public/description.md')\n"
                "def render(spec, rng, cve_record=None):\n"
                "    return {'public/description.md': 'x\\n', 'private/solution.md': 'y\\n'}\n",
                encoding="utf-8",
            )
            spec = importlib.util.spec_from_file_location("bad_renderer_plugin", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # imports families at runtime -- no crash

            eps = [_FakeEntryPoint("badmod", lambda: mod)]
            with self._patch(eps):
                with self.assertLogs(plugins.logger, level="WARNING") as logctx:
                    registered = plugins.load_entry_point_families()

        self.assertEqual(registered, [])
        self.assertFalse(families.is_registered("sdk_plugin_bad_lint_family"))
        self.assertIn("badmod", "\n".join(logctx.output))


class McpDoesNotTriggerLoadingTests(unittest.TestCase):
    """Importing mcp_server must NOT reach the plugin loader: a model driving the
    MCP server only ever sees the built-in families, never arbitrary installed
    plugins."""

    def test_importing_mcp_server_does_not_import_the_loader(self) -> None:
        # Fresh interpreter so this process's already-imported modules can't mask
        # a real reach. If mcp_server (transitively) imported the loader, it would
        # appear in sys.modules.
        code = (
            "import sys\n"
            "from ctf_generator import mcp_server\n"
            "loader = 'ctf_generator.sdk.plugins' in sys.modules\n"
            "fams = set(mcp_server.list_families()['families'])\n"
            "sys.stderr.write('LOADER=%s\\n' % loader)\n"
            "sys.exit(1 if loader else 0)\n"
        )
        src_dir = str(Path(sdk.__file__).resolve().parents[2])
        proc = subprocess.run(  # noqa: S603 - fixed snippet via sys.executable
            [sys.executable, "-c", code],
            env={"PYTHONPATH": src_dir, "PATH": __import__("os").environ.get("PATH", "")},
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"mcp_server import reached the entry-point loader: {proc.stderr}",
        )

    def test_mcp_family_listing_matches_builtin_registry_only(self) -> None:
        # In a fresh interpreter (no plugins installed, loader never called),
        # mcp_server's family list equals the built-in registry -- proving no
        # entry-point loading happened as a side effect of importing/using it.
        code = (
            "from ctf_generator import mcp_server, families\n"
            "a = sorted(mcp_server.list_families()['families'])\n"
            "b = sorted(families.family_names())\n"
            "import sys\n"
            "sys.exit(0 if a == b and len(a) >= 8 else 2)\n"
        )
        src_dir = str(Path(sdk.__file__).resolve().parents[2])
        proc = subprocess.run(  # noqa: S603 - fixed snippet via sys.executable
            [sys.executable, "-c", code],
            env={"PYTHONPATH": src_dir, "PATH": __import__("os").environ.get("PATH", "")},
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
