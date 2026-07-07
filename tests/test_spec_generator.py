from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ctf_generator import families, spec_generator
from ctf_generator.cli import main
from ctf_generator.models import (
    AIResistance,
    ChallengeSpec,
    DynamicVariation,
    ResponseSpec,
    ScenarioSpec,
    TriggerSpec,
)
from ctf_generator.spec_generator import (
    AnthropicSpecBackend,
    DeterministicSpecBackend,
    OpenAISpecBackend,
    build_prompt,
    default_spec,
    default_spec_for_family,
    get_backend,
    spec_from_dict,
    spec_from_llm_output,
    spec_to_dict,
    validate_spec,
)

FAMILY = "web_business_logic_tenant_export"


class _FakeBlock:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.content = [_FakeBlock(text)]


class _FakeMessages:
    def __init__(self, payload: dict, capture: dict) -> None:
        self._payload = payload
        self._capture = capture

    def create(self, **kwargs):
        self._capture.update(kwargs)
        return _FakeResponse(json.dumps(self._payload))


class _FakeClient:
    def __init__(self, payload: dict, capture: dict) -> None:
        self.messages = _FakeMessages(payload, capture)


class _FakeChatMessage:
    def __init__(self, content: str) -> None:
        self.message = type("_Msg", (), {"content": content})()


class _FakeChatResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_FakeChatMessage(content)]


class _FakeCompletions:
    def __init__(self, payload: dict, capture: dict) -> None:
        self._payload = payload
        self._capture = capture

    def create(self, **kwargs):
        self._capture.update(kwargs)
        return _FakeChatResponse(json.dumps(self._payload))


class _FakeOpenAIClient:
    def __init__(self, payload: dict, capture: dict) -> None:
        self.chat = type("_Chat", (), {"completions": _FakeCompletions(payload, capture)})()


class DeterministicBackendTests(unittest.TestCase):
    def test_default_spec_is_valid(self) -> None:
        spec = DeterministicSpecBackend().generate(
            family=FAMILY, difficulty="medium", seed="s", title="T"
        )
        self.assertEqual(validate_spec(spec), [])
        self.assertGreaterEqual(len(spec.checkpoints), spec.ai_resistance.min_solver_steps)


class ValidateSpecTests(unittest.TestCase):
    def _base(self, **over) -> ChallengeSpec:
        data = dict(
            title="T",
            category="web",
            difficulty="medium",
            family=FAMILY,
            seed="s",
            learning_objectives=["a"],
            checkpoints=["1", "2", "3", "4", "5"],
        )
        data.update(over)
        return ChallengeSpec(**data)

    def test_empty_title(self) -> None:
        self.assertIn("title is empty", validate_spec(self._base(title="  ")))

    def test_unknown_family(self) -> None:
        errors = validate_spec(self._base(family="bogus"))
        self.assertTrue(any("unknown family" in e for e in errors))

    def test_too_few_checkpoints(self) -> None:
        errors = validate_spec(self._base(checkpoints=["1", "2"]))
        self.assertTrue(any("min_solver_steps" in e for e in errors))

    def test_family_recognized_via_registry(self) -> None:
        # FAMILY is only known because families.py registered it; this is a
        # proxy for "validate_spec consults the families registry".
        self.assertIn(FAMILY, families.family_names())
        self.assertEqual(validate_spec(self._base(family=FAMILY)), [])

    def test_invalid_cve_ref_rejected(self) -> None:
        errors = validate_spec(self._base(cve_refs=["not-a-cve"]))
        self.assertTrue(any("invalid cve_ref" in e for e in errors))

    def test_valid_cve_ref_accepted(self) -> None:
        errors = validate_spec(self._base(cve_refs=["CVE-2023-12345"]))
        self.assertEqual([e for e in errors if "cve_ref" in e], [])

    def test_mode_not_valid_for_family_rejected(self) -> None:
        errors = validate_spec(self._base(mode="scenario"))
        self.assertTrue(any("mode" in e for e in errors))

    def test_default_mode_valid_for_family(self) -> None:
        errors = validate_spec(self._base(mode="red"))
        self.assertEqual([e for e in errors if "mode" in e], [])

    def test_unknown_family_skips_mode_check_gracefully(self) -> None:
        # An unknown family is already flagged; the mode check must not also
        # blow up (e.g. via a KeyError from families.get()).
        errors = validate_spec(self._base(family="bogus", mode="anything"))
        self.assertTrue(any("unknown family" in e for e in errors))
        self.assertFalse(any("mode" in e for e in errors))


class FamiliesAliasTests(unittest.TestCase):
    def test_module_families_mirrors_registry(self) -> None:
        self.assertEqual(list(spec_generator.FAMILIES), families.family_names())
        self.assertIn(FAMILY, spec_generator.FAMILIES)
        self.assertEqual(spec_generator.FAMILIES[0], families.family_names()[0])


class DefaultSpecForFamilyTests(unittest.TestCase):
    def test_falls_back_to_default_spec_when_no_builder(self) -> None:
        # web_business_logic_tenant_export has no default_spec_builder set.
        spec = default_spec_for_family(seed="s", title="T", difficulty="medium", family=FAMILY)
        self.assertEqual(spec, default_spec(seed="s", title="T", difficulty="medium", family=FAMILY))

    def test_uses_registered_builder_when_present(self) -> None:
        sentinel = ChallengeSpec(
            title="from-builder",
            category="web",
            difficulty="medium",
            family=FAMILY,
            seed="s",
            learning_objectives=["a"],
            checkpoints=["1", "2", "3", "4", "5"],
        )
        captured: dict = {}

        def builder(*, seed, title, difficulty, family):
            captured.update(seed=seed, title=title, difficulty=difficulty, family=family)
            return sentinel

        original = families.get(FAMILY)
        families.register(
            families.Family(
                name=original.name,
                category=original.category,
                modes=original.modes,
                render=original.render,
                required_files=original.required_files,
                compose_service_markers=original.compose_service_markers,
                difficulties=original.difficulties,
                cve_driven=original.cve_driven,
                llm_brief=original.llm_brief,
                default_spec_builder=builder,
                scoring_hints=original.scoring_hints,
            )
        )
        try:
            spec = default_spec_for_family(
                seed="s", title="T", difficulty="medium", family=FAMILY
            )
        finally:
            families.register(original)

        self.assertIs(spec, sentinel)
        self.assertEqual(captured, {"seed": "s", "title": "T", "difficulty": "medium", "family": FAMILY})


class NewSpecFieldsRoundTripTests(unittest.TestCase):
    def test_round_trip_without_new_fields_unchanged(self) -> None:
        # A dict lacking the new keys must load identically to before they
        # existed (defaults: mode="red", scenario disabled, cve_refs=[]).
        # tenant_export now ships an enabled default scenario, so disable it to
        # get a spec with all-default new fields.
        spec = replace(
            default_spec(seed="s", title="T", difficulty="hard", family=FAMILY),
            scenario=ScenarioSpec(),
        )
        base_dict = spec_to_dict(spec)
        self.assertNotIn("cve_refs", base_dict)
        self.assertNotIn("cve_content_hash", base_dict)
        self.assertNotIn("mode", base_dict)
        self.assertNotIn("scenario", base_dict)
        restored = spec_from_dict(base_dict)
        self.assertEqual(restored, spec)
        self.assertEqual(restored.mode, "red")
        self.assertEqual(restored.cve_refs, [])
        self.assertEqual(restored.scenario, ScenarioSpec())

    def test_round_trip_with_new_fields(self) -> None:
        spec = ChallengeSpec(
            title="T",
            category="web",
            difficulty="hard",
            family=FAMILY,
            seed="s",
            learning_objectives=["a"],
            checkpoints=["1", "2", "3", "4", "5"],
            cve_refs=["CVE-2023-12345"],
            cve_content_hash="abc123",
            mode="scenario",
            scenario=ScenarioSpec(
                enabled=True,
                triggers=[TriggerSpec(trigger_id="t1", description="d", condition="c")],
                responses=[
                    ResponseSpec(
                        response_id="r1", description="d", action="a", payload={"k": "v"}
                    )
                ],
            ),
        )
        data = spec_to_dict(spec)
        self.assertEqual(data["cve_refs"], ["CVE-2023-12345"])
        self.assertEqual(data["cve_content_hash"], "abc123")
        self.assertEqual(data["mode"], "scenario")
        self.assertEqual(data["scenario"], spec.scenario.to_mapping())
        restored = spec_from_dict(data)
        self.assertEqual(restored, spec)


class SerializationTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        spec = default_spec(seed="s", title="T", difficulty="hard", family=FAMILY)
        restored = spec_from_dict(spec_to_dict(spec))
        self.assertEqual(restored, spec)

    def test_write_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "nested" / "spec.json"
            spec = default_spec(seed="s", title="T", difficulty="medium", family=FAMILY)
            spec_generator.write_spec(path, spec)
            self.assertEqual(spec_generator.load_spec(path), spec)


class AnthropicBackendTests(unittest.TestCase):
    def test_build_prompt_mentions_family_and_difficulty(self) -> None:
        system, user = build_prompt(FAMILY, "hard")
        self.assertIn("never write", system.lower())
        self.assertIn(FAMILY, user)
        self.assertIn("hard", user)

    def test_llm_output_merges_with_fixed_safety_knobs(self) -> None:
        spec = spec_from_llm_output(
            {"title": "Ledger Leak", "learning_objectives": ["a", "b"], "checkpoints": ["1"]},
            family=FAMILY,
            difficulty="hard",
            seed="s1",
            fallback_title="fallback",
        )
        self.assertEqual(spec.title, "Ledger Leak")
        # Security-relevant knobs are never taken from the model.
        self.assertEqual(spec.ai_resistance, AIResistance())
        self.assertEqual(spec.dynamic_variation, DynamicVariation())

    def test_generate_uses_structured_output_and_default_model(self) -> None:
        payload = {
            "title": "Ledger Leak",
            "learning_objectives": ["trace trust", "chain the job", "extract flag"],
            "checkpoints": ["1", "2", "3", "4", "5"],
        }
        capture: dict = {}
        backend = AnthropicSpecBackend(client=_FakeClient(payload, capture))
        spec = backend.generate(family=FAMILY, difficulty="hard", seed="s1", title="fallback")

        self.assertEqual(spec.title, "Ledger Leak")
        self.assertEqual(spec.checkpoints, ["1", "2", "3", "4", "5"])
        self.assertEqual(spec.seed, "s1")
        self.assertEqual(spec.difficulty, "hard")
        self.assertEqual(validate_spec(spec), [])
        self.assertEqual(capture["model"], "claude-opus-4-8")
        self.assertIn("output_config", capture)
        self.assertEqual(capture["thinking"], {"type": "adaptive"})


class OpenAIBackendTests(unittest.TestCase):
    def test_generate_uses_strict_json_schema_and_default_model(self) -> None:
        payload = {
            "title": "Ledger Leak",
            "learning_objectives": ["trace trust", "chain the job", "extract flag"],
            "checkpoints": ["1", "2", "3", "4", "5"],
        }
        capture: dict = {}
        backend = OpenAISpecBackend(client=_FakeOpenAIClient(payload, capture))
        spec = backend.generate(family=FAMILY, difficulty="hard", seed="s1", title="fallback")

        self.assertEqual(spec.title, "Ledger Leak")
        self.assertEqual(spec.checkpoints, ["1", "2", "3", "4", "5"])
        self.assertEqual(spec.seed, "s1")
        self.assertEqual(validate_spec(spec), [])
        # Security-relevant knobs are never taken from the model.
        self.assertEqual(spec.ai_resistance, AIResistance())
        self.assertEqual(capture["model"], "gpt-5.1")
        self.assertEqual(capture["response_format"]["type"], "json_schema")
        self.assertTrue(capture["response_format"]["json_schema"]["strict"])


class GetBackendTests(unittest.TestCase):
    def test_resolves_each_provider(self) -> None:
        self.assertIsInstance(get_backend("deterministic"), DeterministicSpecBackend)
        self.assertIsInstance(get_backend("anthropic"), AnthropicSpecBackend)
        self.assertIsInstance(get_backend("openai"), OpenAISpecBackend)

    def test_unknown_backend_raises(self) -> None:
        with self.assertRaises(ValueError):
            get_backend("bogus")


class SpecCliTests(unittest.TestCase):
    def test_spec_then_create_from_spec(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_path = Path(temp_dir) / "spec.json"
            challenge = Path(temp_dir) / "chal"

            self.assertEqual(
                main(["spec", "-o", str(spec_path), "--seed", "cli-seed"]), 0
            )
            self.assertTrue(spec_path.exists())

            self.assertEqual(
                main(["create", "-o", str(challenge), "--from-spec", str(spec_path)]), 0
            )
            variant = json.loads((challenge / "private/variant.json").read_text(encoding="utf-8"))
            self.assertEqual(variant["meta"]["seed"], "cli-seed")

    def test_create_from_spec_matches_direct_seed(self) -> None:
        # A deterministic spec renders identically to a direct create with the
        # same seed -- proving the spec fully determines the instance.
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_path = Path(temp_dir) / "spec.json"
            from_spec = Path(temp_dir) / "a"
            direct = Path(temp_dir) / "b"

            main(["spec", "-o", str(spec_path), "--seed", "match-seed"])
            main(["create", "-o", str(from_spec), "--from-spec", str(spec_path)])
            main(["create", "-o", str(direct), "--seed", "match-seed"])

            a = (from_spec / "private/variant.json").read_text(encoding="utf-8")
            b = (direct / "private/variant.json").read_text(encoding="utf-8")
            self.assertEqual(a, b)

    def test_create_from_invalid_spec_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spec_path = Path(temp_dir) / "bad.json"
            spec_path.write_text(json.dumps({"title": "", "family": "bogus"}), encoding="utf-8")
            code = main(["create", "-o", str(Path(temp_dir) / "chal"), "--from-spec", str(spec_path)])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
