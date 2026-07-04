"""Front B: families with a live-adversarial scenario actually fire it.

The critical-review AI-resistance lens found the scenario engine was inert --
enabled=False in 8/8 families, run-scenario firing 0 triggers. These tests
prove that families shipping a default scenario now (1) write a timeline, (2)
fire their triggers deterministically offline, and (3) genuinely disrupt the
family's REAL attack surface mid-solve (not a hand-matched test literal): a
request to the instance's own route is refused once the blue team reacts.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ctf_generator import families, scenario as sc
from ctf_generator.agent_eval import HTTPResponse, _ScenarioDefendedHTTPClient
from ctf_generator.cli import _scenario_spec_from_mapping
from ctf_generator.generator import create_challenge

# Family -> a substring identifying the instance's real attack-surface route in
# variant.json (the one the scenario target should block).
_REAL_ROUTE_MARKER = {
    "crypto_token_forgery": "/api/admin/",
    "cloud_metadata_ssrf": "/internal/objects/",
}


class _FakeInner:
    def request(self, method, url, *, json_body=None, headers=None, timeout=10.0):
        return HTTPResponse(status=200, body="{}", headers={})


def _families_with_scenarios() -> list[str]:
    return [n for n in families.family_names() if families.get(n).default_scenario is not None]


class FamilyScenarioTests(unittest.TestCase):
    def test_at_least_one_family_ships_a_scenario(self) -> None:
        self.assertTrue(_families_with_scenarios())

    def test_scenarios_write_timeline_fire_triggers_and_block_real_route(self) -> None:
        for name in _families_with_scenarios():
            with self.subTest(family=name):
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / "chal"
                    create_challenge(
                        output_dir=out,
                        seed="scenario-seed",
                        title="Scenario",
                        difficulty="medium",
                        family=name,
                    )

                    # (1) the generator wrote the timeline
                    timeline = out / "private" / "scenario_timeline.json"
                    self.assertTrue(timeline.exists(), f"{name}: no scenario_timeline.json")

                    spec = _scenario_spec_from_mapping(
                        json.loads(timeline.read_text(encoding="utf-8"))
                    )
                    self.assertTrue(spec.enabled)

                    # (2) triggers fire deterministically offline
                    report = sc.run_scenario(
                        challenge_path=out,
                        environment=sc.NullEnvironmentController(),
                        events=sc.ReplayEventSource({}),
                        spec=spec,
                        max_ticks=10,
                    )
                    self.assertEqual(len(report.triggers_fired), len(spec.triggers))
                    patched = [
                        r for r in report.responses_applied if r.action == "patch_route"
                    ]
                    self.assertTrue(patched, f"{name}: no patch_route response fired")

                    # (3) the defense blocks the instance's REAL route mid-solve
                    variant = json.loads(
                        (out / "private" / "variant.json").read_text(encoding="utf-8")
                    )
                    marker = _REAL_ROUTE_MARKER[name]
                    real_route = next(
                        v
                        for v in variant.get("routes", {}).values()
                        if marker in str(v)
                    )
                    defended = _ScenarioDefendedHTTPClient(_FakeInner(), report)
                    # A few benign early calls, then repeated hits on the real route.
                    statuses = [
                        defended.request("GET", "http://svc" + u).status
                        for u in ["/api/a", "/api/b", real_route, real_route, real_route]
                    ]
                    self.assertEqual(statuses[0], 200)
                    self.assertIn(403, statuses, f"{name}: real route never blocked")


if __name__ == "__main__":
    unittest.main()
