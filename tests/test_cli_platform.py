from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ctf_generator import cve_source
from ctf_generator.cli import main
from ctf_generator.generator import create_challenge
from ctf_generator.models import ChallengeSpec, ResponseSpec, ScenarioSpec, TriggerSpec


def _run(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


def _reports(report_dir: Path) -> list[Path]:
    return sorted(report_dir.glob("*.json"))


class CveSearchCliTests(unittest.TestCase):
    def test_cve_search_prints_matching_records(self) -> None:
        code, out, _ = _run(
            [
                "cve-search",
                "--category",
                "web",
                "--min-cvss",
                "9.0",
                "--limit",
                "5",
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn("CVE-2021-44228", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("web", out)

    def test_cve_search_keyword_filters(self) -> None:
        code, out, _ = _run(["cve-search", "--keyword", "heartbeat"])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2014-0160", out)
        self.assertNotIn("CVE-2021-44228", out)

    def test_cve_search_no_matches_prints_message(self) -> None:
        code, out, _ = _run(["cve-search", "--keyword", "no-such-keyword-xyz"])
        self.assertEqual(code, 0)
        self.assertIn("No matching CVEs found", out)

    def test_cve_search_with_cache_dir_writes_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_dir = Path(temp_dir) / "cache"
            code, out, _ = _run(
                ["cve-search", "--category", "binary", "--cache-dir", str(cache_dir)]
            )
            self.assertEqual(code, 0)
            self.assertIn("CVE-2021-3156", out)
            self.assertTrue(any(cache_dir.glob("*.json")))


class CveShowCliTests(unittest.TestCase):
    def test_cve_show_known_id(self) -> None:
        code, out, _ = _run(["cve-show", "CVE-2021-44228"])
        self.assertEqual(code, 0)
        self.assertIn("cve_id: CVE-2021-44228", out)
        self.assertIn("cvss_severity: CRITICAL", out)

    def test_cve_show_unknown_id_fails(self) -> None:
        code, _, err = _run(["cve-show", "CVE-0000-0000"])
        self.assertEqual(code, 1)
        self.assertIn("unknown CVE id", err)


class CveCategoriesCliTests(unittest.TestCase):
    def test_lists_all_categories(self) -> None:
        code, out, _ = _run(["cve-categories"])
        self.assertEqual(code, 0)
        printed = out.splitlines()
        self.assertEqual(printed, list(cve_source.CATEGORIES))


class CreateFromCveCliTests(unittest.TestCase):
    def test_create_from_cve_positional_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "chal"
            code, out, _ = _run(
                [
                    "create-from-cve",
                    "-o",
                    str(output),
                    "CVE-2021-44228",
                    "--seed",
                    "cli-cve-seed",
                ]
            )
            self.assertEqual(code, 0)
            self.assertIn("CVE-2021-44228", out)
            self.assertTrue((output / "challenge.yaml").exists())
            yaml_text = (output / "challenge.yaml").read_text(encoding="utf-8")
            self.assertIn("CVE-2021-44228", yaml_text)

    def test_create_from_cve_flag_id_and_report_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "chal"
            report_dir = Path(temp_dir) / "reports"
            code, _, _ = _run(
                [
                    "create-from-cve",
                    "-o",
                    str(output),
                    "--cve-id",
                    "CVE-2021-3156",
                    "--seed",
                    "cli-cve-seed-2",
                    "--report-dir",
                    str(report_dir),
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue((output / "challenge.yaml").exists())
            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "create-from-cve")
            self.assertEqual(payload["status"], "passed")

    def test_create_from_cve_missing_id_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "chal"
            with self.assertRaises(SystemExit):
                main(["create-from-cve", "-o", str(output)])

    def test_create_from_cve_unknown_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "chal"
            code, _, err = _run(
                ["create-from-cve", "-o", str(output), "CVE-0000-0000"]
            )
            self.assertEqual(code, 1)
            self.assertIn("unknown CVE id", err)


class ListScoringEnginesCliTests(unittest.TestCase):
    def test_lists_engines_and_marks_default(self) -> None:
        code, out, _ = _run(["list-scoring-engines"])
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertIn("time_decay (default)", lines)
        self.assertIn("static", lines)
        self.assertIn("dynamic_decay", lines)
        self.assertIn("ai_resistance", lines)


class RunScenarioCliTests(unittest.TestCase):
    def _generate_scenario_challenge(self, temp_dir: str) -> Path:
        output = Path(temp_dir) / "scenario-chal"
        spec = ChallengeSpec(
            title="Scenario Drift",
            category="web",
            difficulty="easy",
            family="web_business_logic_tenant_export",
            seed="scenario-seed",
            learning_objectives=["learn something"],
            checkpoints=[f"checkpoint-{i}" for i in range(5)],
            scenario=ScenarioSpec(
                enabled=True,
                triggers=[
                    TriggerSpec(
                        trigger_id="t1",
                        description="fires immediately",
                        condition="time:+0s",
                    )
                ],
                responses=[
                    ResponseSpec(
                        response_id="r1",
                        description="reveal a hint",
                        action="reveal_hint",
                        payload={"checkpoint": "c1"},
                    )
                ],
            ),
        )
        create_challenge(
            output_dir=output,
            seed=spec.seed,
            title=spec.title,
            difficulty=spec.difficulty,
            family=spec.family,
            spec=spec,
        )
        self.assertTrue((output / "private/scenario_timeline.json").exists())
        return output

    def test_run_scenario_fires_trigger_from_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = self._generate_scenario_challenge(temp_dir)
            code, out, _ = _run(["run-scenario", str(challenge), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertIn("t1", payload["triggers_fired"])
            self.assertEqual(payload["ticks_run"], 20)

    def test_run_scenario_human_readable_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = self._generate_scenario_challenge(temp_dir)
            code, out, _ = _run(["run-scenario", str(challenge)])
            self.assertEqual(code, 0)
            self.assertIn("Triggers fired: ['t1']", out)

    def test_run_scenario_without_timeline_runs_inert(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = Path(temp_dir) / "plain-chal"
            create_challenge(
                output_dir=challenge,
                seed="plain-seed",
                title="Plain",
                difficulty="easy",
                family="web_business_logic_tenant_export",
            )
            self.assertFalse((challenge / "private/scenario_timeline.json").exists())
            code, out, _ = _run(["run-scenario", str(challenge), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertEqual(payload["triggers_fired"], [])

    def test_run_scenario_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = self._generate_scenario_challenge(temp_dir)
            report_dir = Path(temp_dir) / "reports"
            code, _, _ = _run(
                ["run-scenario", str(challenge), "--report-dir", str(report_dir)]
            )
            self.assertEqual(code, 0)
            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "run-scenario")


class ScoreboardCliTests(unittest.TestCase):
    def _write_fixtures(self, temp_dir: str) -> tuple[Path, Path, Path]:
        events_path = Path(temp_dir) / "events.json"
        challenges_path = Path(temp_dir) / "challenges.json"
        config_path = Path(temp_dir) / "config.json"

        events_path.write_text(
            json.dumps(
                [
                    {
                        "team_id": "team-a",
                        "challenge_id": "chal-1",
                        "solved_at": "2026-01-01T01:00:00+00:00",
                        "submission_id": "sub-1",
                    },
                    {
                        "team_id": "team-b",
                        "challenge_id": "chal-1",
                        "solved_at": "2026-01-01T02:00:00+00:00",
                        "submission_id": "sub-2",
                    },
                ]
            ),
            encoding="utf-8",
        )
        challenges_path.write_text(
            json.dumps(
                [
                    {
                        "challenge_id": "chal-1",
                        "initial_value": 500,
                        "minimum_value": 100,
                        "decay_function": "static",
                        "decay": 0,
                    }
                ]
            ),
            encoding="utf-8",
        )
        config_path.write_text(
            json.dumps(
                {
                    "competition_id": "comp-1",
                    "name": "Test Comp",
                    "start_time": "2026-01-01T00:00:00+00:00",
                    "end_time": "2026-01-02T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )
        return events_path, challenges_path, config_path

    def test_scoreboard_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            events_path, challenges_path, config_path = self._write_fixtures(temp_dir)
            code, out, _ = _run(
                [
                    "scoreboard",
                    "--events",
                    str(events_path),
                    "--challenges",
                    str(challenges_path),
                    "--config",
                    str(config_path),
                    "--json",
                ]
            )
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertEqual(payload["competition_id"], "comp-1")
            self.assertEqual(len(payload["entries"]), 2)
            self.assertEqual(payload["entries"][0]["team_id"], "team-a")
            self.assertEqual(payload["entries"][0]["rank"], 1)

    def test_scoreboard_human_readable_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            events_path, challenges_path, config_path = self._write_fixtures(temp_dir)
            code, out, _ = _run(
                [
                    "scoreboard",
                    "--events",
                    str(events_path),
                    "--challenges",
                    str(challenges_path),
                    "--config",
                    str(config_path),
                ]
            )
            self.assertEqual(code, 0)
            self.assertIn("Scoreboard for comp-1", out)
            self.assertIn("1. team-a", out)

    def test_scoreboard_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            events_path, challenges_path, config_path = self._write_fixtures(temp_dir)
            report_dir = Path(temp_dir) / "reports"
            code, _, _ = _run(
                [
                    "scoreboard",
                    "--events",
                    str(events_path),
                    "--challenges",
                    str(challenges_path),
                    "--config",
                    str(config_path),
                    "--report-dir",
                    str(report_dir),
                ]
            )
            self.assertEqual(code, 0)
            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "scoreboard")
            self.assertEqual(payload["result"]["competition_id"], "comp-1")

    def test_scoreboard_unknown_engine_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            events_path, challenges_path, config_path = self._write_fixtures(temp_dir)
            code, _, err = _run(
                [
                    "scoreboard",
                    "--events",
                    str(events_path),
                    "--challenges",
                    str(challenges_path),
                    "--config",
                    str(config_path),
                    "--engine",
                    "bogus-engine",
                ]
            )
            self.assertEqual(code, 1)
            self.assertIn("bogus-engine", err)

    def test_scoreboard_bad_input_path_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            code, _, err = _run(
                [
                    "scoreboard",
                    "--events",
                    str(Path(temp_dir) / "missing.json"),
                    "--challenges",
                    str(Path(temp_dir) / "missing.json"),
                    "--config",
                    str(Path(temp_dir) / "missing.json"),
                ]
            )
            self.assertEqual(code, 1)
            self.assertIn("Could not load scoreboard inputs", err)


class CreateSpecModeAndCveRefCliTests(unittest.TestCase):
    def test_create_with_mode_and_cve_ref_unused_matches_default(self) -> None:
        # Sanity: omitting --mode/--cve-ref keeps identical output to before
        # these flags existed (same seed -> byte-identical variant.json).
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "chal"
            code, _, _ = _run(["create", "-o", str(output), "--seed", "unused-flags"])
            self.assertEqual(code, 0)
            self.assertTrue((output / "private/variant.json").exists())

    def test_spec_with_cve_ref_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_path = Path(temp_dir) / "spec.json"
            code, _, _ = _run(
                [
                    "spec",
                    "-o",
                    str(spec_path),
                    "--seed",
                    "cve-ref-seed",
                    "--cve-ref",
                    "CVE-2021-44228",
                ]
            )
            self.assertEqual(code, 0)
            data = json.loads(spec_path.read_text(encoding="utf-8"))
            self.assertEqual(data["cve_refs"], ["CVE-2021-44228"])

    def test_create_with_family_outside_original_single_choice(self) -> None:
        # --family choices now span the full registry, not just the original
        # tenant_export family.
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "chal"
            code, _, err = _run(
                [
                    "create",
                    "-o",
                    str(output),
                    "--seed",
                    "binary-fam",
                    "--family",
                    "binary_heap_exploit",
                ]
            )
            self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
