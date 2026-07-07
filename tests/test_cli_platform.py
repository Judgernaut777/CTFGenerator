from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_generator import cve_source
from ctf_generator.cli import main
from ctf_generator.generator import create_challenge
from ctf_generator.models import ChallengeSpec, ResponseSpec, ScenarioSpec, TriggerSpec
from ctf_generator.spec_generator import default_spec


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
            # tenant_export ships an enabled default scenario; disable it so this
            # challenge has no timeline and run-scenario is genuinely inert.
            base = default_spec(
                seed="plain-seed",
                title="Plain",
                difficulty="easy",
                family="web_business_logic_tenant_export",
            )
            create_challenge(
                output_dir=challenge,
                seed="plain-seed",
                title="Plain",
                difficulty="easy",
                family="web_business_logic_tenant_export",
                spec=replace(base, scenario=ScenarioSpec()),
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


class EvalAgentCliTests(unittest.TestCase):
    """Offline: agent_eval.run_agent_eval/run_adversarial_delta are patched
    (via mock.patch on the lazily-imported module attribute cli.py calls
    through) so no real Docker/HTTP is ever touched."""

    def _fake_agent_report(self, *, solved: bool = True, steps: int = 3):
        from ctf_generator.agent_eval import AgentEvalReport

        return AgentEvalReport(
            profile="writeup_replay",
            solved=solved,
            steps=steps,
            elapsed_ticks=steps,
            notes=["GET /api/flag -> 200", "flag found: ctf{fake}"],
        )

    def _fake_delta_report(self, challenge_dir: Path):
        from ctf_generator.agent_eval import AdversarialDeltaReport
        from ctf_generator.scenario import ScenarioRunReport

        return AdversarialDeltaReport(
            challenge_path=str(challenge_dir),
            profile="writeup_replay",
            baseline=self._fake_agent_report(solved=True, steps=2),
            adversarial=self._fake_agent_report(solved=False, steps=5),
            scenario_report=ScenarioRunReport(challenge_path=str(challenge_dir), ticks_run=20),
            notes=["scenario ticks_run=20"],
        )

    def test_eval_agent_basic_prints_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge_dir = Path(temp_dir) / "chal"
            report_dir = Path(temp_dir) / "reports"
            fake_report = self._fake_agent_report()
            with mock.patch(
                "ctf_generator.agent_eval.run_agent_eval", return_value=fake_report
            ) as run_mock:
                code, out, _ = _run(
                    [
                        "eval-agent",
                        str(challenge_dir),
                        "--profile",
                        "writeup_replay",
                        "--report-dir",
                        str(report_dir),
                    ]
                )
            self.assertEqual(code, 0)
            run_mock.assert_called_once()
            self.assertIn("solved=True steps=3", out)
            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "eval-agent")
            self.assertEqual(payload["result"]["profile"], "writeup_replay")
            self.assertTrue(payload["result"]["solved"])

    def test_eval_agent_adversarial_prints_delta_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge_dir = Path(temp_dir) / "chal"
            report_dir = Path(temp_dir) / "reports"
            fake_delta = self._fake_delta_report(challenge_dir)
            with mock.patch(
                "ctf_generator.agent_eval.run_adversarial_delta", return_value=fake_delta
            ) as run_mock:
                code, out, _ = _run(
                    [
                        "eval-agent",
                        str(challenge_dir),
                        "--profile",
                        "writeup_replay",
                        "--adversarial",
                        "--report-dir",
                        str(report_dir),
                    ]
                )
            self.assertEqual(code, 0)
            run_mock.assert_called_once()
            self.assertIn("success_dropped=True", out)
            files = _reports(report_dir)
            self.assertEqual(len(files), 1)
            payload = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "eval-agent")
            self.assertTrue(payload["result"]["success_dropped"])
            self.assertIn("scenario_report", payload["result"])


class RunScenarioRuntimeFlagCliTests(unittest.TestCase):
    """Offline: scenario_runtime.run_live_scenario is patched so --runtime
    never touches real Docker/HTTP. Confirms the sibling branch dispatches
    correctly and the existing (non---runtime) run-scenario branch is
    untouched by exercising both in the same test module."""

    def test_run_scenario_with_runtime_flag_uses_scenario_runtime(self) -> None:
        from ctf_generator.scenario import ScenarioRunReport

        with tempfile.TemporaryDirectory() as temp_dir:
            challenge_dir = Path(temp_dir) / "chal"
            fake_report = ScenarioRunReport(
                challenge_path=str(challenge_dir), ticks_run=7, triggers_fired=["t1"]
            )
            with mock.patch(
                "ctf_generator.scenario_runtime.run_live_scenario", return_value=fake_report
            ) as run_mock:
                code, out, _ = _run(
                    [
                        "run-scenario",
                        str(challenge_dir),
                        "--runtime",
                        "--base-url",
                        "http://127.0.0.1:9999",
                        "--json",
                    ]
                )
            self.assertEqual(code, 0)
            run_mock.assert_called_once()
            _, kwargs = run_mock.call_args
            self.assertEqual(kwargs["base_url"], "http://127.0.0.1:9999")
            payload = json.loads(out)
            self.assertEqual(payload["ticks_run"], 7)
            self.assertEqual(payload["triggers_fired"], ["t1"])

    def test_run_scenario_runtime_loads_timeline_as_spec(self) -> None:
        # Regression: the --runtime branch must read private/scenario_timeline.json
        # and pass it as `spec`, or the live defender has no triggers to fire.
        from ctf_generator.scenario import ScenarioRunReport

        with tempfile.TemporaryDirectory() as temp_dir:
            challenge_dir = Path(temp_dir) / "chal"
            (challenge_dir / "private").mkdir(parents=True)
            (challenge_dir / "private" / "scenario_timeline.json").write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "triggers": [
                            {"trigger_id": "t9", "description": "d", "condition": "time:>=1"}
                        ],
                        "responses": [
                            {
                                "response_id": "r9",
                                "description": "d",
                                "action": "patch_route",
                                "payload": {"target": "api"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            fake_report = ScenarioRunReport(challenge_path=str(challenge_dir), ticks_run=3)
            with mock.patch(
                "ctf_generator.scenario_runtime.run_live_scenario", return_value=fake_report
            ) as run_mock:
                code, _, _ = _run(["run-scenario", str(challenge_dir), "--runtime", "--json"])
            self.assertEqual(code, 0)
            _, kwargs = run_mock.call_args
            spec = kwargs.get("spec")
            self.assertIsNotNone(spec, "--runtime must pass the loaded scenario spec")
            self.assertTrue(spec.enabled)
            self.assertEqual([t.trigger_id for t in spec.triggers], ["t9"])
            self.assertEqual([r.response_id for r in spec.responses], ["r9"])


class ServeHelperTests(unittest.TestCase):
    """Offline: only the pure service/auth builder helpers are exercised --
    never dashboard_server.serve()/serve_forever(), which would open a real
    socket."""

    def test_build_serve_service_defaults_to_in_memory_and_empty_catalog(self) -> None:
        from ctf_generator.cli import _build_serve_service
        from ctf_generator.competition_service import CompetitionService
        from ctf_generator.events import InMemoryEventStore

        args = argparse_namespace(events_file=None, challenges=None, config=None)
        service = _build_serve_service(args)
        self.assertIsInstance(service, CompetitionService)
        self.assertIsInstance(service.store, InMemoryEventStore)
        self.assertEqual(service.catalog.ids(), [])
        self.assertEqual(service.config.competition_id, "ctfgen-live")

    def test_build_serve_service_reads_events_file_and_challenges(self) -> None:
        from ctf_generator.cli import _build_serve_service
        from ctf_generator.events import JsonlEventStore

        with tempfile.TemporaryDirectory() as temp_dir:
            events_path = Path(temp_dir) / "events.jsonl"
            challenges_path = Path(temp_dir) / "challenges.json"
            challenges_path.write_text(
                json.dumps([{"challenge_id": "chal-1", "initial_value": 500}]),
                encoding="utf-8",
            )
            args = argparse_namespace(
                events_file=events_path, challenges=challenges_path, config=None
            )
            service = _build_serve_service(args)
            self.assertIsInstance(service.store, JsonlEventStore)
            self.assertEqual(service.catalog.ids(), ["chal-1"])

    def test_build_serve_auth_uses_given_public_token(self) -> None:
        from ctf_generator.cli import _build_serve_auth

        args = argparse_namespace(admin_user="admin", admin_password="hunter2", public_token="fixed-token")
        auth = _build_serve_auth(args)
        self.assertEqual(auth.admin_username, "admin")
        self.assertEqual(auth.public_token, "fixed-token")
        self.assertTrue(auth.verify_password("admin", "hunter2"))
        self.assertFalse(auth.verify_password("admin", "wrong"))


class CatalogCommandTests(unittest.TestCase):
    """Offline: only filesystem scanning of real, locally-generated challenge
    folders -- no network/Docker/sockets."""

    def test_catalog_scans_two_generated_challenges(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenges_dir = Path(temp_dir) / "challenges"
            create_challenge(
                output_dir=challenges_dir / "chal-a",
                seed="cat-a",
                title="Catalog Sample A",
                difficulty="easy",
                family="web_business_logic_tenant_export",
            )
            create_challenge(
                output_dir=challenges_dir / "chal-b",
                seed="cat-b",
                title="Catalog Sample B",
                difficulty="easy",
                family="crypto_token_forgery",
            )
            out_path = Path(temp_dir) / "catalog.json"
            code, out, _ = _run(
                ["catalog", "--challenges-dir", str(challenges_dir), "-o", str(out_path)]
            )
            self.assertEqual(code, 0)
            self.assertIn("2 challenge(s)", out)

            entries = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(len(entries), 2)
            ids = {entry["challenge_id"] for entry in entries}
            self.assertEqual(ids, {"chal-a", "chal-b"})
            titles = {entry["challenge_id"]: entry["title"] for entry in entries}
            self.assertEqual(titles["chal-a"], "Catalog Sample A")
            self.assertEqual(titles["chal-b"], "Catalog Sample B")

            # Compatible with `serve --challenges` / `scoreboard --challenges`:
            # scoreboard.load_challenges must parse it without error and key
            # it by challenge_id, ignoring the extra title/category fields.
            from ctf_generator.scoreboard import load_challenges

            loaded = load_challenges(out_path)
            self.assertEqual(set(loaded), {"chal-a", "chal-b"})
            self.assertEqual(loaded["chal-a"].challenge_id, "chal-a")

    def test_catalog_without_output_prints_json_to_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenges_dir = Path(temp_dir) / "challenges"
            create_challenge(
                output_dir=challenges_dir / "chal-only",
                seed="cat-only",
                title="Catalog Sample Only",
                difficulty="easy",
                family="web_business_logic_tenant_export",
            )
            code, out, _ = _run(["catalog", "--challenges-dir", str(challenges_dir)])
            self.assertEqual(code, 0)
            entries = json.loads(out)
            self.assertEqual([entry["challenge_id"] for entry in entries], ["chal-only"])

    def test_catalog_empty_dir_yields_empty_array(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            empty_dir = Path(temp_dir) / "empty"
            empty_dir.mkdir()
            code, out, _ = _run(["catalog", "--challenges-dir", str(empty_dir)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out), [])


class QuickstartCommandTests(unittest.TestCase):
    """Offline, no Docker: generates real (small) challenge folders on disk
    via create_challenge/create_challenge_from_cve, same as create/
    create-from-cve use."""

    def test_quickstart_creates_sample_challenges_and_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "quickstart-out"
            code, out, _ = _run(
                ["quickstart", "--output", str(output_dir), "--seed", "qs-test"]
            )
            self.assertEqual(code, 0)

            for name in ("web-sample", "crypto-sample", "cve-log4shell-sample"):
                self.assertTrue(
                    (output_dir / name / "challenge.yaml").is_file(),
                    f"expected {name}/challenge.yaml to exist",
                )

            # Prints the exact next commands, referencing both the catalog
            # step and the browser UI (/ and /public).
            self.assertIn("ctfgen catalog --challenges-dir", out)
            self.assertIn("ctfgen serve", out)
            self.assertIn("--challenges-dir", out)
            self.assertIn("/public", out)
            self.assertNotIn("docker", out.lower())

    def test_quickstart_is_idempotent_with_same_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "quickstart-out"
            code1, _, _ = _run(["quickstart", "--output", str(output_dir), "--seed", "qs-again"])
            code2, _, _ = _run(["quickstart", "--output", str(output_dir), "--seed", "qs-again"])
            self.assertEqual(code1, 0)
            self.assertEqual(code2, 0)


class ServeChallengesDirTests(unittest.TestCase):
    """Offline: exercises _build_serve_service directly with --challenges-dir,
    never dashboard_server.serve()/serve_forever() (no real socket)."""

    def test_build_serve_service_builds_nonempty_catalog_from_dir(self) -> None:
        from ctf_generator.cli import _build_serve_service

        with tempfile.TemporaryDirectory() as temp_dir:
            challenges_dir = Path(temp_dir) / "challenges"
            create_challenge(
                output_dir=challenges_dir / "chal-x",
                seed="dir-x",
                title="Dir Sample X",
                difficulty="easy",
                family="web_business_logic_tenant_export",
            )
            args = argparse_namespace(
                events_file=None,
                challenges=None,
                challenges_dir=challenges_dir,
                config=None,
            )
            service = _build_serve_service(args)
            self.assertEqual(service.catalog.ids(), ["chal-x"])
            meta = service.catalog.get("chal-x")
            self.assertEqual(meta.title, "Dir Sample X")

    def test_challenges_dir_takes_precedence_over_challenges_file(self) -> None:
        from ctf_generator.cli import _build_serve_service

        with tempfile.TemporaryDirectory() as temp_dir:
            challenges_dir = Path(temp_dir) / "challenges"
            create_challenge(
                output_dir=challenges_dir / "chal-y",
                seed="dir-y",
                title="Dir Sample Y",
                difficulty="easy",
                family="web_business_logic_tenant_export",
            )
            challenges_file = Path(temp_dir) / "other.json"
            challenges_file.write_text(
                json.dumps([{"challenge_id": "from-file"}]), encoding="utf-8"
            )
            args = argparse_namespace(
                events_file=None,
                challenges=challenges_file,
                challenges_dir=challenges_dir,
                config=None,
            )
            service = _build_serve_service(args)
            self.assertEqual(service.catalog.ids(), ["chal-y"])


def argparse_namespace(**kwargs):
    import argparse

    return argparse.Namespace(**kwargs)


if __name__ == "__main__":
    unittest.main()
