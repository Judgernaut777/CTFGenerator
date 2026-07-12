from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ctf_generator import mcp_server

FAMILY = "web_business_logic_tenant_export"

_ORIGINAL_WORKSPACE = mcp_server.get_workspace_root()


def setUpModule() -> None:
    # These tests write challenges under ``tempfile.TemporaryDirectory()``
    # dirs, all of which live under the system temp root. Point the MCP
    # workspace sandbox there so those absolute paths resolve inside it.
    mcp_server.set_workspace_root(tempfile.gettempdir())


def tearDownModule() -> None:
    mcp_server.set_workspace_root(_ORIGINAL_WORKSPACE)


class WorkspaceSandboxTests(unittest.TestCase):
    """The write tools must reject paths that escape the workspace root, so a
    model host cannot use output_dir traversal (+ force=True rmtree) as an
    arbitrary host write/delete primitive."""

    def test_create_challenge_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            mcp_server.set_workspace_root(root)
            try:
                result = mcp_server.create_challenge(
                    output_dir="../../../../tmp/mcp_escape_poc", seed="poc"
                )
                self.assertFalse(result["ok"])
                self.assertTrue(any("escapes the MCP workspace" in e for e in result["errors"]))
                self.assertFalse(Path("/tmp/mcp_escape_poc").exists())
            finally:
                mcp_server.set_workspace_root(tempfile.gettempdir())

    def test_create_challenge_rejects_absolute_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            mcp_server.set_workspace_root(root)
            try:
                result = mcp_server.create_challenge(
                    output_dir="/tmp/mcp_abs_escape_poc", seed="poc"
                )
                self.assertFalse(result["ok"])
                self.assertFalse(Path("/tmp/mcp_abs_escape_poc").exists())
            finally:
                mcp_server.set_workspace_root(tempfile.gettempdir())

    def test_create_challenge_allows_path_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            mcp_server.set_workspace_root(root)
            try:
                result = mcp_server.create_challenge(output_dir="chal", seed="poc")
                self.assertTrue(result["ok"], result)
                self.assertTrue((Path(root) / "chal" / "challenge.yaml").exists())
            finally:
                mcp_server.set_workspace_root(tempfile.gettempdir())

    def test_create_from_spec_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            mcp_server.set_workspace_root(root)
            try:
                built = mcp_server.build_spec(family=FAMILY, difficulty="easy", seed="s")
                result = mcp_server.create_from_spec(
                    built["spec"], "../../../../tmp/mcp_spec_escape_poc"
                )
                self.assertFalse(result["ok"])
                self.assertFalse(Path("/tmp/mcp_spec_escape_poc").exists())
            finally:
                mcp_server.set_workspace_root(tempfile.gettempdir())


class ListingTests(unittest.TestCase):
    def test_list_families(self) -> None:
        result = mcp_server.list_families()
        self.assertIn(FAMILY, result["families"])
        self.assertIn("hard", result["difficulties"])

    def test_spec_schema_exposes_metadata_only(self) -> None:
        schema = mcp_server.spec_schema()
        props = schema["metadata_schema"]["properties"]
        self.assertEqual(set(props), {"title", "learning_objectives", "checkpoints"})
        self.assertNotIn("ai_resistance", props)


class BuildSpecTests(unittest.TestCase):
    def test_host_metadata_merges_with_fixed_knobs(self) -> None:
        result = mcp_server.build_spec(
            family=FAMILY,
            difficulty="hard",
            seed="s1",
            title="Ledger Leak",
            learning_objectives=["trace trust"],
            checkpoints=["1", "2", "3", "4", "5"],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["spec"]["title"], "Ledger Leak")
        # Security knobs come from the server defaults, not the caller.
        self.assertEqual(result["spec"]["ai_resistance"]["min_solver_steps"], 5)

    def test_no_metadata_falls_back_to_deterministic(self) -> None:
        result = mcp_server.build_spec(family=FAMILY, difficulty="medium", seed="s2")
        self.assertTrue(result["ok"], result)
        self.assertGreaterEqual(len(result["spec"]["checkpoints"]), 5)

    def test_unknown_family_rejected(self) -> None:
        result = mcp_server.build_spec(family="bogus", difficulty="hard", seed="s")
        self.assertFalse(result["ok"])

    def test_too_few_checkpoints_flagged(self) -> None:
        result = mcp_server.build_spec(
            family=FAMILY,
            difficulty="hard",
            seed="s",
            title="T",
            learning_objectives=["a"],
            checkpoints=["1", "2"],
        )
        self.assertFalse(result["ok"])
        self.assertTrue(any("min_solver_steps" in e for e in result["errors"]))


class RenderTests(unittest.TestCase):
    def test_build_then_create_from_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            built = mcp_server.build_spec(family=FAMILY, difficulty="hard", seed="mcp-seed")
            out = Path(temp_dir) / "chal"
            result = mcp_server.create_from_spec(built["spec"], str(out))
            self.assertTrue(result["ok"], result)
            self.assertTrue((out / "private/variant.json").exists())

    def test_create_challenge_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            a = Path(temp_dir) / "a"
            b = Path(temp_dir) / "b"
            mcp_server.create_challenge(str(a), seed="match")
            mcp_server.create_challenge(str(b), seed="match")
            self.assertEqual(
                (a / "private/variant.json").read_text(encoding="utf-8"),
                (b / "private/variant.json").read_text(encoding="utf-8"),
            )

    def test_create_from_invalid_spec_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = mcp_server.create_from_spec(
                {"title": "", "family": "bogus"}, str(Path(temp_dir) / "chal")
            )
            self.assertFalse(result["ok"])

    def test_validate_and_score_generated_challenge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "chal"
            mcp_server.create_challenge(str(out), seed="score-seed")
            self.assertTrue(mcp_server.validate_challenge(str(out))["ok"])
            score = mcp_server.score_challenge(str(out))
            self.assertIn("total", score)
            self.assertIn("band", score)


class ToolSurfaceTests(unittest.TestCase):
    def test_no_docker_tool_exposed(self) -> None:
        # Docker-driving commands must stay CLI-only; the MCP surface is pure.
        names = {tool.__name__ for tool in mcp_server.TOOLS}
        for forbidden in ("validate_runtime", "cross_replay", "replay", "validate_siblings"):
            self.assertNotIn(forbidden, names)


# The MCP security boundary (M13c): a model driving the MCP server must NEVER be
# able to reach an EFFECTFUL surface (Docker/subprocess/challenge-execution) or the
# platform DATA PLANE (the application services / DB / API). The tool-name check
# above guards the exposed surface; these guard the IMPORT surface -- so a future
# edit that pulls an effectful/platform module into mcp_server (even transitively)
# fails the gate, not just one that adds a tool by name.

# Effectful challenge-execution + standalone-engine modules, the platform data
# plane, and heavy effectful deps. `subprocess` is the shell-exec primitive the
# pure generator never needs.
_FORBIDDEN_PREFIXES = (
    "subprocess",
    "sqlalchemy",
    "fastapi",
    "httpx",
    "docker",
    "psycopg",
    "alembic",
    "ctf_generator.scenario_runtime",
    "ctf_generator.agent_eval",
    "ctf_generator.dashboard_server",
    "ctf_generator.competition_service",
    # The Docker-driving validators + effectful writers/UI, named INDEPENDENTLY
    # (not merely caught via their module-level ``import subprocess``).
    "ctf_generator.runtime_validator",
    "ctf_generator.replay_validator",
    "ctf_generator.sibling_validator",
    "ctf_generator.report_writer",
    "ctf_generator.dashboard_ui",
    "ctf_generator.application",
    "ctf_generator.infrastructure",
    "ctf_generator.interfaces.api",
    "ctf_generator.interfaces.web",
    "ctf_generator.interfaces.cli",
    "ctf_generator.workers",
)

# Shell/exec primitives reachable WITHOUT importing subprocess/docker: os.system,
# os.popen, os.exec*/spawn*/posix_spawn*. The import firewall cannot see these
# (os is legitimately imported for os.environ), so a dedicated source guard forbids
# them in mcp_server.py.
_EXEC_OS_ATTRS = frozenset(
    {"system", "popen"}
    | {f"exec{s}" for s in ("l", "le", "lp", "v", "ve", "vp", "vpe")}
    | {f"spawn{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")}
    | {"posix_spawn", "posix_spawnp"}
)


def _forbidden(module: str) -> bool:
    return any(module == p or module.startswith(p + ".") for p in _FORBIDDEN_PREFIXES)


class MCPImportFirewallTests(unittest.TestCase):
    def test_source_imports_no_effectful_or_platform_module(self) -> None:
        # Static AST scan of mcp_server.py: no DIRECT import (absolute or the
        # ``from . import <submodule>`` form) may name a forbidden module. Fast,
        # exact, and points at the offending line if it ever regresses.
        import ast
        from pathlib import Path

        src = Path(mcp_server.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level and (node.module is None or node.level == 1):
                    # ``from . import families, foo`` -> ctf_generator.<name>
                    base = "ctf_generator"
                    mod = f"{base}.{node.module}" if node.module else base
                    imported.append(mod)
                    imported.extend(f"{mod}.{a.name}" for a in node.names)
                elif node.module:
                    imported.append(node.module)
                    # ``from ctf_generator import application`` -> record the
                    # subpackage too, so the AST test itself names the offender
                    # (not only the sys.modules backstop below).
                    imported.extend(f"{node.module}.{a.name}" for a in node.names)
        offenders = sorted(m for m in imported if _forbidden(m))
        self.assertEqual(offenders, [], f"mcp_server imports forbidden modules: {offenders}")

    def test_source_calls_no_shell_exec_primitive(self) -> None:
        # os.system / os.popen / os.exec*/spawn*/posix_spawn* reach a shell WITHOUT
        # importing subprocess or docker, so the import firewall alone cannot catch
        # them. Forbid the call form in mcp_server.py's source (AST walks into tool
        # bodies too, so a lazy shell-out inside a tool is caught).
        import ast
        from pathlib import Path

        tree = ast.parse(Path(mcp_server.__file__).read_text(encoding="utf-8"))
        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
                and func.attr in _EXEC_OS_ATTRS
            ):
                offenders.append(f"os.{func.attr} at line {node.lineno}")
            elif isinstance(func, ast.Name) and func.id in {"system", "popen"}:
                offenders.append(f"{func.id}() at line {node.lineno}")
        self.assertEqual(offenders, [], f"mcp_server calls a shell-exec primitive: {offenders}")

    def test_fresh_import_pulls_no_forbidden_module(self) -> None:
        # The strong guarantee: importing mcp_server in a FRESH interpreter must
        # pull NONE of the forbidden modules into sys.modules -- catching a
        # TRANSITIVE reach (a pure module that itself imports an effectful/platform
        # one), which the static scan cannot see. Run in a subprocess so an
        # already-imported module in THIS test process cannot mask a real leak.
        import subprocess
        import sys
        from pathlib import Path

        forbidden = ",".join(repr(p) for p in _FORBIDDEN_PREFIXES)
        code = (
            "import sys\n"
            "from ctf_generator import mcp_server\n"
            f"F = ({forbidden},)\n"
            "hits = sorted(m for m in sys.modules "
            "if any(m == p or m.startswith(p + '.') for p in F))\n"
            "sys.stderr.write('HITS=' + ','.join(hits) + '\\n')\n"
            "sys.exit(1 if hits else 0)\n"
        )
        # mcp_server.__file__ = <repo>/src/ctf_generator/mcp_server.py -> parents[1] is src/.
        src_dir = str(Path(mcp_server.__file__).resolve().parents[1])
        proc = subprocess.run(
            [sys.executable, "-c", code],
            env={**os.environ, "PYTHONPATH": src_dir},
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"mcp_server transitively imports a forbidden module: {proc.stderr}",
        )

    def test_calling_tools_pulls_no_forbidden_module(self) -> None:
        # The import checks are load-time; a tool body could LAZILY import an
        # effectful/data-plane module (or one reached via importlib) that only
        # fires when the tool is CALLED. Drive every pure tool in a FRESH
        # interpreter, then re-check sys.modules -- closing the call-time gap.
        import subprocess
        import sys
        from pathlib import Path

        forbidden = ",".join(repr(p) for p in _FORBIDDEN_PREFIXES)
        code = (
            "import os, sys, tempfile\n"
            "with tempfile.TemporaryDirectory() as ws:\n"
            "    os.environ['CTFGEN_MCP_WORKSPACE'] = ws\n"
            "    from ctf_generator import mcp_server\n"
            "    mcp_server.set_workspace_root(ws)\n"
            "    fams = mcp_server.list_families()['families']\n"
            "    fam = fams[0] if fams else 'web_business_logic_tenant_export'\n"
            "    mcp_server.spec_schema()\n"
            "    mcp_server.family_info(fam)\n"
            "    mcp_server.list_cves()\n"
            "    r = mcp_server.build_spec(family=fam, difficulty='medium', seed='probe-seed')\n"
            "    if isinstance(r, dict) and r.get('ok'):\n"
            "        mcp_server.validate_spec(r['spec'])\n"
            "        c = mcp_server.create_from_spec(r['spec'], 'chal')\n"
            "        d = c.get('output_dir') if isinstance(c, dict) else None\n"
            "        if d:\n"
            "            mcp_server.validate_challenge(d)\n"
            "            mcp_server.score_challenge(d)\n"
            f"    F = ({forbidden},)\n"
            "    hits = sorted(m for m in sys.modules if any(m == p or m.startswith(p + '.') for p in F))\n"
            "    sys.stderr.write('HITS=' + ','.join(hits) + '\\n')\n"
            "    sys.exit(1 if hits else 0)\n"
        )
        src_dir = str(Path(mcp_server.__file__).resolve().parents[1])
        proc = subprocess.run(
            [sys.executable, "-c", code],
            env={**os.environ, "PYTHONPATH": src_dir},
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"calling MCP tools pulled a forbidden module (or errored): {proc.stderr}",
        )


class ModeAndCveRefsTests(unittest.TestCase):
    def test_build_spec_defaults_unchanged(self) -> None:
        # Omitting mode/cve_refs must still produce today's plain spec.
        result = mcp_server.build_spec(family=FAMILY, difficulty="medium", seed="s3")
        self.assertTrue(result["ok"], result)
        self.assertNotIn("mode", result["spec"])
        self.assertNotIn("cve_refs", result["spec"])

    def test_build_spec_valid_mode_accepted(self) -> None:
        result = mcp_server.build_spec(
            family=FAMILY, difficulty="medium", seed="s4", mode="red"
        )
        self.assertTrue(result["ok"], result)

    def test_build_spec_invalid_mode_rejected(self) -> None:
        result = mcp_server.build_spec(
            family=FAMILY, difficulty="medium", seed="s5", mode="bogus-mode"
        )
        self.assertFalse(result["ok"])
        self.assertTrue(any("mode" in e for e in result["errors"]))

    def test_build_spec_invalid_cve_ref_rejected(self) -> None:
        result = mcp_server.build_spec(
            family=FAMILY,
            difficulty="medium",
            seed="s6",
            cve_refs=["not-a-cve"],
        )
        self.assertFalse(result["ok"])
        self.assertTrue(any("cve_ref" in e for e in result["errors"]))

    def test_build_spec_valid_cve_ref_accepted(self) -> None:
        result = mcp_server.build_spec(
            family=FAMILY,
            difficulty="medium",
            seed="s7",
            cve_refs=["CVE-2021-44228"],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["spec"]["cve_refs"], ["CVE-2021-44228"])

    def test_create_challenge_deterministic_with_default_mode(self) -> None:
        # Explicitly passing the default mode/cve_refs must not change output.
        with tempfile.TemporaryDirectory() as temp_dir:
            a = Path(temp_dir) / "a"
            b = Path(temp_dir) / "b"
            mcp_server.create_challenge(str(a), seed="match2")
            mcp_server.create_challenge(str(b), seed="match2", mode="red", cve_refs=[])
            self.assertEqual(
                (a / "private/variant.json").read_text(encoding="utf-8"),
                (b / "private/variant.json").read_text(encoding="utf-8"),
            )

    def test_create_challenge_invalid_mode_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = mcp_server.create_challenge(
                str(Path(temp_dir) / "chal"), seed="s8", mode="bogus-mode"
            )
            self.assertFalse(result["ok"])

    def test_create_challenge_invalid_cve_ref_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = mcp_server.create_challenge(
                str(Path(temp_dir) / "chal"), seed="s9", cve_refs=["nope"]
            )
            self.assertFalse(result["ok"])

    def test_create_from_spec_mode_override_rejected_when_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            built = mcp_server.build_spec(family=FAMILY, difficulty="hard", seed="ov1")
            result = mcp_server.create_from_spec(
                built["spec"], str(Path(temp_dir) / "chal"), mode="bogus-mode"
            )
            self.assertFalse(result["ok"])

    def test_create_from_spec_default_unchanged(self) -> None:
        # Omitting the override params must behave exactly as before.
        with tempfile.TemporaryDirectory() as temp_dir:
            built = mcp_server.build_spec(family=FAMILY, difficulty="hard", seed="ov2")
            out = Path(temp_dir) / "chal"
            result = mcp_server.create_from_spec(built["spec"], str(out))
            self.assertTrue(result["ok"], result)


class FamilyInfoTests(unittest.TestCase):
    def test_family_info_known(self) -> None:
        info = mcp_server.family_info(FAMILY)
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["category"], "web")
        self.assertIn("red", info["modes"])
        self.assertIsInstance(info["required_files"], list)
        self.assertIn("llm_brief", info)

    def test_family_info_unknown(self) -> None:
        info = mcp_server.family_info("bogus-family")
        self.assertFalse(info["ok"])


class ListCvesTests(unittest.TestCase):
    def test_list_cves_defaults(self) -> None:
        result = mcp_server.list_cves()
        self.assertLessEqual(len(result["cves"]), 10)
        self.assertGreater(len(result["cves"]), 0)
        for record in result["cves"]:
            self.assertIn("cve_id", record)
            self.assertIn("category", record)

    def test_list_cves_keyword_filters(self) -> None:
        result = mcp_server.list_cves(keyword="log4j", limit=5)
        self.assertTrue(result["cves"])
        for record in result["cves"]:
            self.assertIn("log4j", record["description"].lower())

    def test_list_cves_category_filters(self) -> None:
        result = mcp_server.list_cves(category="web", limit=50)
        self.assertTrue(result["cves"])
        for record in result["cves"]:
            self.assertEqual(record["category"], "web")

    def test_list_cves_never_exposes_source_param(self) -> None:
        # There must be no way to steer this tool at an nvd/network source.
        import inspect

        params = inspect.signature(mcp_server.list_cves).parameters
        self.assertNotIn("source", params)


class ScenarioTimelineSummaryTests(unittest.TestCase):
    def test_absent_file_reports_not_present(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = mcp_server.scenario_timeline_summary(temp_dir)
            self.assertTrue(result["ok"])
            self.assertFalse(result["present"])

    def test_present_file_summarized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            timeline_dir = Path(temp_dir) / "private"
            timeline_dir.mkdir()
            (timeline_dir / "scenario_timeline.json").write_text(
                '{"enabled": true, "triggers": [{"trigger_id": "t1"}], '
                '"responses": [{"response_id": "r1"}, {"response_id": "r2"}]}',
                encoding="utf-8",
            )
            result = mcp_server.scenario_timeline_summary(temp_dir)
            self.assertTrue(result["ok"])
            self.assertTrue(result["present"])
            self.assertTrue(result["enabled"])
            self.assertEqual(result["trigger_count"], 1)
            self.assertEqual(result["response_count"], 2)

    def test_malformed_file_reports_error_not_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            timeline_dir = Path(temp_dir) / "private"
            timeline_dir.mkdir()
            (timeline_dir / "scenario_timeline.json").write_text(
                "not json", encoding="utf-8"
            )
            result = mcp_server.scenario_timeline_summary(temp_dir)
            self.assertFalse(result["ok"])


class SecurityRegressionTests(unittest.TestCase):
    """Guards the no-Docker / metadata-only MCP boundary against regressions.

    mcp_server.py must never gain a dependency (direct or transitive) on
    anything that shells out (subprocess) or that drives Docker-backed
    runtime validation/scenario execution. Those stay CLI-only.
    """

    _FORBIDDEN_MODULES = (
        "ctf_generator.runtime_validator",
        "ctf_generator.replay_validator",
        "ctf_generator.sibling_validator",
        "ctf_generator.report_writer",
        # Phase 5 modules -- must not exist as an mcp_server dependency even
        # once added to the codebase.
        "ctf_generator.scenario_runtime",
        "ctf_generator.agent_eval",
        "ctf_generator.dashboard_server",
    )

    def test_mcp_server_does_not_import_subprocess_directly(self) -> None:
        import ast
        import inspect

        source = inspect.getsource(mcp_server)
        tree = ast.parse(source)
        imported_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_names.add(node.module)
        self.assertNotIn("subprocess", imported_names)

    def test_transitive_import_graph_excludes_docker_driving_modules(self) -> None:
        # Reimport ctf_generator.mcp_server in a fresh subprocess so the
        # transitive import graph reflects only what mcp_server itself (and
        # what it imports) pulls in -- not whatever earlier tests happened
        # to already import into this process's sys.modules.
        import subprocess
        import sys

        code = (
            "import sys, json\n"
            "import ctf_generator.mcp_server\n"
            "mods = sorted(m for m in sys.modules if m.startswith('ctf_generator'))\n"
            "print(json.dumps({'mods': mods, 'subprocess_loaded': 'subprocess' in sys.modules}))\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(Path(__file__).resolve().parent.parent),
            env={"PYTHONPATH": "src", "PATH": __import__("os").environ.get("PATH", "")},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = __import__("json").loads(proc.stdout)
        self.assertFalse(
            payload["subprocess_loaded"],
            "importing ctf_generator.mcp_server must not pull in subprocess",
        )
        for forbidden in self._FORBIDDEN_MODULES:
            self.assertNotIn(
                forbidden,
                payload["mods"],
                f"mcp_server must not transitively import {forbidden}",
            )


if __name__ == "__main__":
    unittest.main()
