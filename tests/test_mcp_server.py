from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_generator import mcp_server

FAMILY = "web_business_logic_tenant_export"


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


if __name__ == "__main__":
    unittest.main()
