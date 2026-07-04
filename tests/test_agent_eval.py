from __future__ import annotations

import json
import random
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ctf_generator.agent_eval import (
    ADVERSARIAL_COMPOSE_PROFILE,
    EVAL_PROFILES,
    LLM_ANTHROPIC_DEFAULT_MODEL,
    LLM_OPENAI_DEFAULT_MODEL,
    AgentEvalReport,
    AgentTranscript,
    HTTPResponse,
    LlmSolverAgent,
    ScriptedSolverAgent,
    _extract_plan,
    list_eval_profiles,
    run_adversarial_delta,
    run_agent_eval,
)
from ctf_generator.models import ResponseSpec, TriggerSpec
from ctf_generator.scenario import ScriptedDefender


DESCRIPTION_MD = """# Widget Vault

Start at:

- `GET /api/flag`

Use the `X-Session: letmein` request header. The flag format is `ctf{...}`.
"""

HINTS_YAML = 'hints:\n  - "Sessions are just a shared secret."\n'


def _write_challenge(root: Path, *, description: str = DESCRIPTION_MD, hints: str = HINTS_YAML) -> Path:
    challenge = root / "widget-vault"
    (challenge / "public").mkdir(parents=True)
    (challenge / "private").mkdir(parents=True)
    (challenge / "challenge.yaml").write_text("title: Widget Vault\nfamily: none\n", encoding="utf-8")
    (challenge / "public" / "description.md").write_text(description, encoding="utf-8")
    (challenge / "public" / "hints.yaml").write_text(hints, encoding="utf-8")
    return challenge


class FakeHTTPClient:
    """Deterministic fake: one endpoint, one secret header, no network."""

    def __init__(self, secret: str = "letmein", flag: str = "ctf{fake_flag_123456}") -> None:
        self.secret = secret
        self.flag = flag
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, *, json_body=None, headers=None, timeout=10.0) -> HTTPResponse:
        headers = headers or {}
        self.calls.append((method, url, dict(headers)))
        if url.endswith("/api/flag") and headers.get("X-Session") == self.secret:
            return HTTPResponse(status=200, body=f"here you go: {self.flag}", headers={})
        return HTTPResponse(status=403, body="forbidden", headers={})


def _tool_use_block(call_id: str, name: str, tool_input: dict) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=call_id, name=name, input=tool_input)


def _text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


class FakeAnthropicClient:
    """Deterministic fake ``anthropic.Anthropic()``: scripted, cycling turns.

    ``turns`` is a list of "content" lists (each a list of blocks as
    ``client.messages.create(...).content`` would return); calls beyond the
    list length wrap around via modulo, so the same client can be reused
    across two ``solve()`` runs (e.g. the baseline and adversarial legs of
    :func:`run_adversarial_delta`, which share one injected agent/client).
    """

    def __init__(self, turns: list[list[SimpleNamespace]]) -> None:
        self._turns = list(turns)
        self.calls = 0
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs) -> SimpleNamespace:
        content = self._turns[self.calls % len(self._turns)]
        self.calls += 1
        return SimpleNamespace(content=content)


def _openai_tool_call(call_id: str, name: str, arguments: dict) -> SimpleNamespace:
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))


def _openai_message(text: str | None = None, tool_calls: list[SimpleNamespace] | None = None) -> SimpleNamespace:
    return SimpleNamespace(content=text, tool_calls=tool_calls or [])


class FakeOpenAIClient:
    """Deterministic fake ``openai.OpenAI()``: scripted, cycling messages."""

    def __init__(self, messages: list[SimpleNamespace]) -> None:
        self._messages = list(messages)
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs) -> SimpleNamespace:
        message = self._messages[self.calls % len(self._messages)]
        self.calls += 1
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class ExtractPlanTests(unittest.TestCase):
    def test_extracts_method_path_and_header(self) -> None:
        candidates, headers = _extract_plan(DESCRIPTION_MD)
        self.assertEqual(candidates, [("GET", "/api/flag")])
        self.assertEqual(headers, {"X-Session": "letmein"})

    def test_falls_back_to_default_candidates_when_nothing_found(self) -> None:
        candidates, headers = _extract_plan("no hints here")
        self.assertEqual(headers, {})
        self.assertIn(("GET", "/"), candidates)
        self.assertTrue(all(method == "GET" for method, _ in candidates))


class ScriptedSolverAgentTests(unittest.TestCase):
    def test_solves_when_plan_matches_live_app(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()
            agent = ScriptedSolverAgent()

            transcript = agent.solve(
                base_url="http://fake-app",
                public_dir=challenge / "public",
                http=http,
                rng=random.Random(0),
                max_steps=8,
                deadline=float("inf"),
            )

        self.assertIsInstance(transcript, AgentTranscript)
        self.assertTrue(transcript.solved)
        self.assertEqual(transcript.steps, 1)
        self.assertEqual(transcript.flag, "ctf{fake_flag_123456}")
        self.assertEqual(len(http.calls), 1)
        self.assertEqual(http.calls[0][2].get("X-Session"), "letmein")

    def test_fails_when_secret_does_not_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient(secret="different-secret")
            agent = ScriptedSolverAgent()

            transcript = agent.solve(
                base_url="http://fake-app",
                public_dir=challenge / "public",
                http=http,
                rng=random.Random(0),
                max_steps=8,
                deadline=float("inf"),
            )

        self.assertFalse(transcript.solved)
        self.assertIsNone(transcript.flag)

    def test_respects_max_steps_budget(self) -> None:
        description = "\n".join(f"- `GET /path{i}`" for i in range(5))
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir), description=description, hints="hints: []\n")
            http = FakeHTTPClient()
            agent = ScriptedSolverAgent()

            transcript = agent.solve(
                base_url="http://fake-app",
                public_dir=challenge / "public",
                http=http,
                rng=random.Random(0),
                max_steps=2,
                deadline=float("inf"),
            )

        self.assertFalse(transcript.solved)
        self.assertEqual(transcript.steps, 2)
        self.assertEqual(len(http.calls), 2)


class EvalProfilesTests(unittest.TestCase):
    def test_expected_profiles_registered(self) -> None:
        self.assertEqual(
            list_eval_profiles(),
            ["llm_agent", "one_shot_prompt", "tool_using_agent", "writeup_replay"],
        )

    def test_one_shot_prompt_has_smallest_budget(self) -> None:
        self.assertEqual(EVAL_PROFILES["one_shot_prompt"].max_steps, 1)
        self.assertLess(
            EVAL_PROFILES["one_shot_prompt"].max_steps, EVAL_PROFILES["writeup_replay"].max_steps
        )
        self.assertLess(
            EVAL_PROFILES["writeup_replay"].max_steps, EVAL_PROFILES["tool_using_agent"].max_steps
        )

    def test_adversarial_compose_profile_constant(self) -> None:
        self.assertEqual(ADVERSARIAL_COMPOSE_PROFILE, "adversarial")


class RunAgentEvalTests(unittest.TestCase):
    def test_already_running_skips_docker_and_solves(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()

            def runner(command, cwd, timeout):
                raise AssertionError("runner must not be called when already_running=True")

            report = run_agent_eval(
                challenge,
                "writeup_replay",
                base_url="http://fake-app",
                http=http,
                already_running=True,
                runner=runner,
            )

        self.assertIsInstance(report, AgentEvalReport)
        self.assertTrue(report.solved)
        self.assertEqual(report.steps, 1)
        self.assertEqual(report.elapsed_ticks, 1)

    def test_unknown_profile_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            with self.assertRaises(ValueError):
                run_agent_eval(challenge, "not-a-real-profile", already_running=True, http=FakeHTTPClient())

    def test_static_validation_failure_short_circuits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = Path(temp_dir) / "missing"
            report = run_agent_eval(challenge, "writeup_replay", already_running=True, http=FakeHTTPClient())

        self.assertFalse(report.solved)
        self.assertTrue(any("does not exist" in note for note in report.notes))

    def test_drives_docker_lifecycle_when_not_already_running(self) -> None:
        calls: list[list[str]] = []

        def runner(command, cwd, timeout):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()

            report = run_agent_eval(
                challenge,
                "writeup_replay",
                base_url="http://fake-app",
                http=http,
                runner=runner,
                timeout_seconds=1,
            )

        self.assertTrue(report.solved)
        self.assertIn("build", calls[0])
        self.assertIn("up", calls[1])
        self.assertIn("tests/healthcheck.py", calls[2])
        self.assertIn("down", calls[3])

    def test_keep_running_skips_teardown(self) -> None:
        calls: list[list[str]] = []

        def runner(command, cwd, timeout):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()

            run_agent_eval(
                challenge,
                "writeup_replay",
                base_url="http://fake-app",
                http=http,
                runner=runner,
                timeout_seconds=1,
                keep_running=True,
            )

        self.assertEqual(len(calls), 3)
        self.assertFalse(any("down" in call for call in calls))


class RunAdversarialDeltaTests(unittest.TestCase):
    def _defender(self) -> ScriptedDefender:
        trigger = TriggerSpec(trigger_id="rotate", condition="time:>=0")
        response = ResponseSpec(
            response_id="rotate-session",
            description="rotate the leaked session secret",
            action="rotate_credential",
            payload={"target": "letmein"},
        )
        return ScriptedDefender([trigger], {"rotate": [response]})

    def test_defense_off_solves_defense_on_breaks_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()

            report = run_adversarial_delta(
                challenge,
                "writeup_replay",
                base_url="http://fake-app",
                http=http,
                already_running=True,
                defender=self._defender(),
                max_ticks=3,
            )

        self.assertTrue(report.baseline.solved)
        self.assertFalse(report.adversarial.solved)
        self.assertTrue(report.success_dropped)
        self.assertIn("rotate", report.scenario_report.triggers_fired)

    def test_no_defender_leaves_success_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()

            report = run_adversarial_delta(
                challenge,
                "writeup_replay",
                base_url="http://fake-app",
                http=http,
                already_running=True,
                max_ticks=3,
            )

        self.assertTrue(report.baseline.solved)
        self.assertTrue(report.adversarial.solved)
        self.assertFalse(report.success_dropped)

    def test_deterministic_across_repeated_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))

            reports = []
            for _ in range(2):
                http = FakeHTTPClient()
                reports.append(
                    run_adversarial_delta(
                        challenge,
                        "writeup_replay",
                        base_url="http://fake-app",
                        http=http,
                        already_running=True,
                        defender=self._defender(),
                        max_ticks=3,
                    )
                )

        self.assertEqual(reports[0].baseline.solved, reports[1].baseline.solved)
        self.assertEqual(reports[0].adversarial.solved, reports[1].adversarial.solved)
        self.assertEqual(reports[0].adversarial.steps, reports[1].adversarial.steps)


class LlmSolverAgentTests(unittest.TestCase):
    def test_construction_does_not_require_sdk(self) -> None:
        agent = LlmSolverAgent(provider="anthropic")
        self.assertEqual(agent.name, "llm")

    def test_unsupported_provider_rejected(self) -> None:
        with self.assertRaises(ValueError):
            LlmSolverAgent(provider="not-a-real-provider")

    def test_default_models_selected_per_provider(self) -> None:
        self.assertEqual(LlmSolverAgent(provider="anthropic").model, LLM_ANTHROPIC_DEFAULT_MODEL)
        self.assertEqual(LlmSolverAgent(provider="openai").model, LLM_OPENAI_DEFAULT_MODEL)

    def test_solve_without_sdk_raises_clear_error(self) -> None:
        agent = LlmSolverAgent(provider="anthropic")
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            with self.assertRaises((ImportError, NotImplementedError)):
                agent.solve(
                    base_url="http://fake-app",
                    public_dir=challenge / "public",
                    http=FakeHTTPClient(),
                    rng=random.Random(0),
                    max_steps=1,
                    deadline=float("inf"),
                )

    def test_solve_drives_tool_loop_to_flag_offline(self) -> None:
        """Fake Anthropic client + fake HTTPClient, no network, no SDK."""
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()
            decision = [
                _tool_use_block(
                    "call-1",
                    "http_request",
                    {"method": "GET", "path": "/api/flag", "headers": {"X-Session": "letmein"}},
                )
            ]
            client = FakeAnthropicClient([decision])
            agent = LlmSolverAgent(provider="anthropic", client=client)

            transcript = agent.solve(
                base_url="http://fake-app",
                public_dir=challenge / "public",
                http=http,
                rng=random.Random(0),
                max_steps=5,
                deadline=float("inf"),
            )

        self.assertIsInstance(transcript, AgentTranscript)
        self.assertTrue(transcript.solved)
        self.assertEqual(transcript.steps, 1)
        self.assertEqual(transcript.flag, "ctf{fake_flag_123456}")
        self.assertEqual(client.calls, 1)
        self.assertEqual(http.calls[0][2].get("X-Session"), "letmein")

    def test_solve_stops_when_model_gives_up(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient(secret="different-secret")
            turns = [
                [_tool_use_block("call-1", "http_request", {"method": "GET", "path": "/api/flag", "headers": {}})],
                [_text_block("Nothing else worth trying; giving up.")],
            ]
            client = FakeAnthropicClient(turns)
            agent = LlmSolverAgent(provider="anthropic", client=client)

            transcript = agent.solve(
                base_url="http://fake-app",
                public_dir=challenge / "public",
                http=http,
                rng=random.Random(0),
                max_steps=5,
                deadline=float("inf"),
            )

        self.assertFalse(transcript.solved)
        self.assertIsNone(transcript.flag)
        self.assertEqual(transcript.steps, 1)
        self.assertEqual(client.calls, 2)

    def test_solve_respects_max_steps_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient(secret="different-secret")
            decision = [_tool_use_block("call-1", "http_request", {"method": "GET", "path": "/api/flag", "headers": {}})]
            client = FakeAnthropicClient([decision])
            agent = LlmSolverAgent(provider="anthropic", client=client)

            transcript = agent.solve(
                base_url="http://fake-app",
                public_dir=challenge / "public",
                http=http,
                rng=random.Random(0),
                max_steps=3,
                deadline=float("inf"),
            )

        self.assertFalse(transcript.solved)
        self.assertEqual(transcript.steps, 3)
        self.assertEqual(client.calls, 3)

    def test_solve_openai_provider_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()
            tool_call = _openai_tool_call(
                "call-1", "http_request", {"method": "GET", "path": "/api/flag", "headers": {"X-Session": "letmein"}}
            )
            client = FakeOpenAIClient([_openai_message(tool_calls=[tool_call])])
            agent = LlmSolverAgent(provider="openai", client=client)

            transcript = agent.solve(
                base_url="http://fake-app",
                public_dir=challenge / "public",
                http=http,
                rng=random.Random(0),
                max_steps=5,
                deadline=float("inf"),
            )

        self.assertTrue(transcript.solved)
        self.assertEqual(transcript.flag, "ctf{fake_flag_123456}")
        self.assertEqual(client.calls, 1)

    def test_run_agent_eval_with_llm_agent_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()
            decision = [
                _tool_use_block(
                    "call-1",
                    "http_request",
                    {"method": "GET", "path": "/api/flag", "headers": {"X-Session": "letmein"}},
                )
            ]
            agent = LlmSolverAgent(provider="anthropic", client=FakeAnthropicClient([decision]))

            report = run_agent_eval(
                challenge,
                "llm_agent",
                base_url="http://fake-app",
                http=http,
                already_running=True,
                agent=agent,
            )

        self.assertIsInstance(report, AgentEvalReport)
        self.assertTrue(report.solved)
        self.assertEqual(report.steps, 1)


class RunAdversarialDeltaWithLlmAgentTests(unittest.TestCase):
    def _defender(self) -> ScriptedDefender:
        trigger = TriggerSpec(trigger_id="rotate", condition="time:>=0")
        response = ResponseSpec(
            response_id="rotate-session",
            description="rotate the leaked session secret",
            action="rotate_credential",
            payload={"target": "letmein"},
        )
        return ScriptedDefender([trigger], {"rotate": [response]})

    def test_llm_agent_success_dropped_under_defense(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge = _write_challenge(Path(temp_dir))
            http = FakeHTTPClient()
            # Cycling single-turn client: always asks for the same request, so
            # it can be reused (baseline solves turn 1; the defended leg keeps
            # retrying the now-broken plan until its step budget runs out).
            decision = [
                _tool_use_block(
                    "call-1",
                    "http_request",
                    {"method": "GET", "path": "/api/flag", "headers": {"X-Session": "letmein"}},
                )
            ]
            agent = LlmSolverAgent(provider="anthropic", client=FakeAnthropicClient([decision]))

            report = run_adversarial_delta(
                challenge,
                "llm_agent",
                base_url="http://fake-app",
                http=http,
                already_running=True,
                agent=agent,
                defender=self._defender(),
                max_ticks=3,
            )

        self.assertTrue(report.baseline.solved)
        self.assertFalse(report.adversarial.solved)
        self.assertTrue(report.success_dropped)
        self.assertEqual(report.baseline.steps, 1)
        self.assertEqual(report.adversarial.steps, EVAL_PROFILES["llm_agent"].max_steps)


if __name__ == "__main__":
    unittest.main()
