from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from ctf_generator.models import ResponseSpec, ScenarioSpec, TriggerSpec
from ctf_generator.scenario import ScriptedDefender
from ctf_generator.scenario_runtime import (
    DockerEnvironmentController,
    HttpEventSource,
    run_live_scenario,
)


def _fake_runner(calls: list[list[str]], stdout: str = "ok\n", returncode: int = 0):
    def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")

    return runner


class DockerEnvironmentControllerTests(unittest.TestCase):
    def test_rotate_credential_runs_compose_exec_and_emits_event(self) -> None:
        calls: list[list[str]] = []
        controller = DockerEnvironmentController(
            challenge_path=Path("/challenges/demo"),
            project_name="ctfgen-demo",
            runner=_fake_runner(calls, stdout="rotated\n"),
        )

        event = controller.rotate_credential("api", {"target": "api"})

        self.assertEqual(calls[0][:4], ["docker", "compose", "-p", "ctfgen-demo"])
        self.assertIn("exec", calls[0])
        self.assertIn("api", calls[0])
        self.assertEqual(event.source, "environment")
        self.assertEqual(event.kind, "rotate_credential")
        self.assertEqual(event.target, "api")
        self.assertEqual(event.payload["returncode"], "0")
        self.assertEqual(event.payload["stdout"], "rotated\n")
        self.assertEqual(controller.recorded, [("rotate_credential", "api", {"target": "api"})])

    def test_rotate_credential_honors_command_override(self) -> None:
        calls: list[list[str]] = []
        controller = DockerEnvironmentController(
            challenge_path=Path("/challenges/demo"),
            project_name="ctfgen-demo",
            runner=_fake_runner(calls),
        )

        controller.rotate_credential("api", {"target": "api", "command": "rotate-secret.sh"})

        self.assertIn("rotate-secret.sh", calls[0])

    def test_patch_route_runs_compose_exec(self) -> None:
        calls: list[list[str]] = []
        controller = DockerEnvironmentController(
            challenge_path=Path("/challenges/demo"),
            project_name="ctfgen-demo",
            runner=_fake_runner(calls),
        )

        event = controller.patch_route("gateway", {"target": "gateway"})

        self.assertIn("exec", calls[0])
        self.assertIn("gateway", calls[0])
        self.assertEqual(event.kind, "patch_route")
        self.assertEqual(event.target, "gateway")

    def test_quarantine_host_runs_compose_stop(self) -> None:
        calls: list[list[str]] = []
        controller = DockerEnvironmentController(
            challenge_path=Path("/challenges/demo"),
            project_name="ctfgen-demo",
            runner=_fake_runner(calls),
        )

        event = controller.quarantine_host("attacker-box", {"target": "attacker-box"})

        self.assertEqual(calls[0], ["docker", "compose", "-p", "ctfgen-demo", "stop", "attacker-box"])
        self.assertEqual(event.kind, "quarantine_host")
        self.assertEqual(event.target, "attacker-box")

    def test_inject_noise_runs_compose_exec(self) -> None:
        calls: list[list[str]] = []
        controller = DockerEnvironmentController(
            challenge_path=Path("/challenges/demo"),
            project_name="ctfgen-demo",
            runner=_fake_runner(calls),
        )

        event = controller.inject_noise("api", {"target": "api"})

        self.assertIn("exec", calls[0])
        self.assertEqual(event.kind, "inject_noise")

    def test_default_project_name_matches_runtime_validator_convention(self) -> None:
        calls: list[list[str]] = []
        controller = DockerEnvironmentController(
            challenge_path=Path("/challenges/Invoice_Drift"),
            runner=_fake_runner(calls),
        )

        self.assertEqual(controller.project_name, "ctfgen-invoice-drift")

    def test_failing_command_propagates_called_process_error(self) -> None:
        def failing_runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            raise subprocess.CalledProcessError(1, command, output="boom", stderr="bad")

        controller = DockerEnvironmentController(
            challenge_path=Path("/challenges/demo"),
            project_name="ctfgen-demo",
            runner=failing_runner,
        )

        with self.assertRaises(subprocess.CalledProcessError):
            controller.rotate_credential("api", {"target": "api"})

    def test_tick_is_zero_placeholder_like_null_environment_controller(self) -> None:
        controller = DockerEnvironmentController(
            challenge_path=Path("/challenges/demo"),
            project_name="ctfgen-demo",
            runner=_fake_runner([]),
        )
        event = controller.rotate_credential("api", {"target": "api"})
        self.assertEqual(event.tick, 0)


class HttpEventSourceTests(unittest.TestCase):
    def test_poll_emits_checkpoint_once(self) -> None:
        responses = ['{"checkpoint": "recon_done"}', '{"checkpoint": "recon_done"}']
        calls: list[str] = []

        def fetcher(url: str, timeout: int) -> str:
            calls.append(url)
            return responses.pop(0)

        source = HttpEventSource(base_url="http://127.0.0.1:8080/", fetcher=fetcher)

        first = source.poll(0)
        second = source.poll(1)

        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].kind, "checkpoint_reached")
        self.assertEqual(first[0].target, "recon_done")
        self.assertEqual(first[0].tick, 0)
        self.assertEqual(second, [])
        self.assertEqual(calls, [
            "http://127.0.0.1:8080/scenario/state",
            "http://127.0.0.1:8080/scenario/state",
        ])

    def test_poll_emits_events_list(self) -> None:
        body = (
            '{"events": [{"source": "sensor", "kind": "attacker_request", '
            '"target": "/admin", "payload": {"ip": "10.0.0.5"}}]}'
        )

        def fetcher(url: str, timeout: int) -> str:
            return body

        source = HttpEventSource(base_url="http://host", fetcher=fetcher)
        events = source.poll(3)

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.tick, 3)
        self.assertEqual(event.source, "sensor")
        self.assertEqual(event.kind, "attacker_request")
        self.assertEqual(event.target, "/admin")
        self.assertEqual(event.payload, {"ip": "10.0.0.5"})

    def test_poll_uses_custom_path(self) -> None:
        seen_urls: list[str] = []

        def fetcher(url: str, timeout: int) -> str:
            seen_urls.append(url)
            return "{}"

        source = HttpEventSource(base_url="http://host", path="custom/state", fetcher=fetcher)
        source.poll(0)

        self.assertEqual(seen_urls, ["http://host/custom/state"])

    def test_poll_error_is_reported_as_event_not_raised(self) -> None:
        def fetcher(url: str, timeout: int) -> str:
            raise OSError("connection refused")

        source = HttpEventSource(base_url="http://host", fetcher=fetcher)
        events = source.poll(2)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "poll_error")
        self.assertEqual(events[0].tick, 2)
        self.assertIn("connection refused", events[0].payload["error"])

    def test_poll_invalid_json_is_reported_as_event(self) -> None:
        def fetcher(url: str, timeout: int) -> str:
            return "not json"

        source = HttpEventSource(base_url="http://host", fetcher=fetcher)
        events = source.poll(0)

        self.assertEqual(events[0].kind, "poll_error")

    def test_poll_empty_object_emits_nothing(self) -> None:
        def fetcher(url: str, timeout: int) -> str:
            return "{}"

        source = HttpEventSource(base_url="http://host", fetcher=fetcher)
        self.assertEqual(source.poll(0), [])


class RunLiveScenarioTests(unittest.TestCase):
    def test_run_live_scenario_wires_docker_and_http_deterministically(self) -> None:
        docker_calls: list[list[str]] = []

        def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            docker_calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        http_responses = [
            "{}",
            '{"checkpoint": "breach"}',
            "{}",
        ]

        def fetcher(url: str, timeout: int) -> str:
            return http_responses.pop(0) if http_responses else "{}"

        spec = ScenarioSpec(
            enabled=True,
            triggers=[TriggerSpec(trigger_id="t1", condition="event:checkpoint_reached")],
            responses=[
                ResponseSpec(
                    response_id="r1",
                    action="rotate_credential",
                    payload={"target": "api"},
                )
            ],
        )

        report = run_live_scenario(
            challenge_path=Path("/challenges/demo"),
            base_url="http://127.0.0.1:9000",
            spec=spec,
            runner=runner,
            fetcher=fetcher,
            max_ticks=3,
        )

        self.assertEqual(report.challenge_path, str(Path("/challenges/demo")))
        self.assertEqual(report.ticks_run, 3)
        # Checkpoint observed at tick 1 fires the trigger at tick 1, which
        # invokes rotate_credential against the real (fake) docker runner.
        self.assertIn("t1", report.triggers_fired)
        self.assertTrue(
            any(call[:4] == ["docker", "compose", "-p", "ctfgen-demo"] for call in docker_calls)
        )
        self.assertTrue(any("exec" in call for call in docker_calls))

    def test_run_live_scenario_is_deterministic_across_runs(self) -> None:
        def make_runner(calls: list[list[str]]):
            def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

            return runner

        def make_fetcher():
            responses = ['{"checkpoint": "breach"}', "{}", "{}"]

            def fetcher(url: str, timeout: int) -> str:
                return responses.pop(0) if responses else "{}"

            return fetcher

        spec = ScenarioSpec(
            enabled=True,
            triggers=[TriggerSpec(trigger_id="t1", condition="event:checkpoint_reached")],
            responses=[
                ResponseSpec(response_id="r1", action="quarantine_host", payload={"target": "attacker"})
            ],
        )

        calls_a: list[list[str]] = []
        report_a = run_live_scenario(
            challenge_path=Path("/challenges/demo"),
            base_url="http://host",
            spec=spec,
            runner=make_runner(calls_a),
            fetcher=make_fetcher(),
            max_ticks=3,
        )

        calls_b: list[list[str]] = []
        report_b = run_live_scenario(
            challenge_path=Path("/challenges/demo"),
            base_url="http://host",
            spec=spec,
            runner=make_runner(calls_b),
            fetcher=make_fetcher(),
            max_ticks=3,
        )

        self.assertEqual(report_a.triggers_fired, report_b.triggers_fired)
        self.assertEqual(
            [e.to_mapping() for e in report_a.timeline],
            [e.to_mapping() for e in report_b.timeline],
        )
        self.assertEqual(calls_a, calls_b)

    def test_run_live_scenario_accepts_explicit_defender(self) -> None:
        defender = ScriptedDefender(
            triggers=[TriggerSpec(trigger_id="t1", condition="time:+1s")],
            trigger_responses={
                "t1": [
                    ResponseSpec(
                        response_id="r1",
                        action="inject_noise",
                        payload={"target": "api"},
                    )
                ]
            },
        )
        calls: list[list[str]] = []

        def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        def fetcher(url: str, timeout: int) -> str:
            return "{}"

        report = run_live_scenario(
            challenge_path=Path("/challenges/demo"),
            base_url="http://host",
            defender=defender,
            runner=runner,
            fetcher=fetcher,
            max_ticks=2,
        )

        self.assertIn("t1", report.triggers_fired)
        self.assertTrue(any("exec" in call for call in calls))

    def test_run_live_scenario_custom_project_name(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        defender = ScriptedDefender(
            triggers=[TriggerSpec(trigger_id="t1", condition="time:+0s")],
            trigger_responses={
                "t1": [ResponseSpec(response_id="r1", action="patch_route", payload={"target": "gw"})]
            },
        )

        run_live_scenario(
            challenge_path=Path("/challenges/demo"),
            base_url="http://host",
            defender=defender,
            runner=runner,
            fetcher=lambda url, timeout: "{}",
            project_name="custom-project",
            max_ticks=1,
        )

        self.assertTrue(any(call[:4] == ["docker", "compose", "-p", "custom-project"] for call in calls))


if __name__ == "__main__":
    unittest.main()
