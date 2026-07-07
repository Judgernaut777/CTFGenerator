from __future__ import annotations

import random
import unittest

from ctf_generator import families
from ctf_generator.families import (
    Family,
    ScoringHints,
    family_names,
    family_of,
    families_for_category,
    families_for_mode,
    get,
    is_registered,
    register,
)
from ctf_generator.models import ChallengeSpec
from ctf_generator.templates.tenant_export import render_tenant_export


def _spec(**overrides: object) -> ChallengeSpec:
    defaults = dict(
        title="Invoice Drift",
        category="web",
        difficulty="medium",
        family="web_business_logic_tenant_export",
        seed="abc123",
        learning_objectives=["obj-1"],
        checkpoints=["step-1", "step-2", "step-3", "step-4", "step-5"],
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


class BootstrapRegistrationTests(unittest.TestCase):
    def test_tenant_export_family_registered(self) -> None:
        self.assertTrue(is_registered("web_business_logic_tenant_export"))
        fam = get("web_business_logic_tenant_export")
        self.assertEqual(fam.name, "web_business_logic_tenant_export")
        self.assertEqual(fam.category, "web")
        self.assertEqual(fam.modes, ("red",))
        self.assertFalse(fam.cve_driven)
        self.assertIn("worker:", fam.compose_service_markers)
        self.assertIn("redis", fam.compose_service_markers)
        self.assertEqual(fam.difficulties, ("easy", "medium", "hard"))
        self.assertTrue(fam.llm_brief)
        self.assertIsInstance(fam.scoring_hints, ScoringHints)
        self.assertTrue(fam.scoring_hints.has_worker)
        self.assertTrue(fam.scoring_hints.has_queue)
        self.assertTrue(fam.scoring_hints.live_interaction)

    def test_required_files_match_validator(self) -> None:
        from ctf_generator.validator import REQUIRED_FILES

        fam = get("web_business_logic_tenant_export")
        self.assertEqual(fam.required_files, tuple(REQUIRED_FILES))

    def test_llm_brief_matches_spec_generator(self) -> None:
        from ctf_generator.spec_generator import _FAMILY_BRIEF

        fam = get("web_business_logic_tenant_export")
        self.assertEqual(
            fam.llm_brief, _FAMILY_BRIEF["web_business_logic_tenant_export"]
        )


class SnapshotWrapperTests(unittest.TestCase):
    """Assert the registered adapter is byte-identical to the raw renderer."""

    def test_wrapped_render_matches_direct_call(self) -> None:
        spec = _spec()
        fam = get("web_business_logic_tenant_export")

        direct = render_tenant_export(spec, random.Random("shared-seed"))
        wrapped = fam.render(spec, random.Random("shared-seed"))

        self.assertEqual(direct, wrapped)

    def test_wrapped_render_ignores_cve_record(self) -> None:
        spec = _spec()
        fam = get("web_business_logic_tenant_export")

        direct = render_tenant_export(spec, random.Random("shared-seed"))
        wrapped_with_cve = fam.render(spec, random.Random("shared-seed"), cve_record=object())

        self.assertEqual(direct, wrapped_with_cve)

    def test_wrapped_render_varies_with_rng_like_direct(self) -> None:
        spec = _spec()
        fam = get("web_business_logic_tenant_export")

        direct_a = render_tenant_export(spec, random.Random("seed-a"))
        direct_b = render_tenant_export(spec, random.Random("seed-b"))
        wrapped_a = fam.render(spec, random.Random("seed-a"))
        wrapped_b = fam.render(spec, random.Random("seed-b"))

        self.assertEqual(direct_a, wrapped_a)
        self.assertEqual(direct_b, wrapped_b)
        self.assertNotEqual(direct_a, direct_b)


class RegistryOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        # Snapshot and restore the module-global registry so tests that
        # register scratch families never leak into other tests.
        self._saved = dict(families._REGISTRY)
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._saved)

    def _dummy_render(self, spec, rng, cve_record=None) -> dict[str, str]:
        return {"flag.txt": f"FLAG{{{spec.seed}}}"}

    def test_register_and_get(self) -> None:
        fam = Family(
            name="scratch_family",
            category="crypto",
            modes=("red",),
            render=self._dummy_render,
            required_files=("challenge.yaml",),
        )
        register(fam)
        self.assertIs(get("scratch_family"), fam)
        self.assertTrue(is_registered("scratch_family"))

    def test_get_unknown_raises_keyerror(self) -> None:
        with self.assertRaises(KeyError):
            get("does_not_exist")

    def test_is_registered_false_for_unknown(self) -> None:
        self.assertFalse(is_registered("does_not_exist"))

    def test_family_names_sorted_and_includes_bootstrap(self) -> None:
        register(
            Family(
                name="aaa_scratch",
                category="crypto",
                modes=("red",),
                render=self._dummy_render,
                required_files=("challenge.yaml",),
            )
        )
        names = family_names()
        self.assertEqual(names, sorted(names))
        self.assertIn("web_business_logic_tenant_export", names)
        self.assertIn("aaa_scratch", names)

    def test_families_for_mode(self) -> None:
        register(
            Family(
                name="scenario_only",
                category="web",
                modes=("scenario",),
                render=self._dummy_render,
                required_files=("challenge.yaml",),
            )
        )
        red_families = families_for_mode("red")
        self.assertTrue(any(f.name == "web_business_logic_tenant_export" for f in red_families))
        self.assertFalse(any(f.name == "scenario_only" for f in red_families))

        scenario_families = families_for_mode("scenario")
        self.assertTrue(any(f.name == "scenario_only" for f in scenario_families))

    def test_families_for_category(self) -> None:
        register(
            Family(
                name="crypto_scratch",
                category="crypto",
                modes=("red",),
                render=self._dummy_render,
                required_files=("challenge.yaml",),
            )
        )
        web_families = families_for_category("web")
        self.assertTrue(any(f.name == "web_business_logic_tenant_export" for f in web_families))
        self.assertFalse(any(f.name == "crypto_scratch" for f in web_families))

        crypto_families = families_for_category("crypto")
        self.assertTrue(any(f.name == "crypto_scratch" for f in crypto_families))


class FamilyOfParsingTests(unittest.TestCase):
    def test_parses_top_level_family_field(self) -> None:
        text = (
            "meta:\n"
            '  generator_version: "0.1.0"\n'
            '  spec_version: "1.0"\n'
            '  family: "not_this_one"\n'
            '  seed: "abc123"\n'
            'title: "Invoice Drift"\n'
            'category: "web"\n'
            'family: "web_business_logic_tenant_export"\n'
            'seed: "abc123"\n'
        )
        self.assertEqual(family_of(text), "web_business_logic_tenant_export")

    def test_returns_none_when_absent(self) -> None:
        text = 'title: "No family here"\ncategory: "web"\n'
        self.assertIsNone(family_of(text))

    def test_returns_none_for_empty_text(self) -> None:
        self.assertIsNone(family_of(""))

    def test_matches_meta_mapping_family_via_dump_yaml(self) -> None:
        from ctf_generator.yaml_writer import dump_yaml

        spec = _spec()
        yaml_text = dump_yaml(spec.to_mapping())
        self.assertEqual(family_of(yaml_text), spec.family)


class WebFamilyDefaultScenarioTests(unittest.TestCase):
    """Front B: tenant_export ships an enabled default live-adversarial scenario
    whose blue-team block targets '/download/' -- a stable segment of the
    randomized export route that BOTH vulnerability classes must hit."""

    def test_default_scenario_is_enabled_and_targets_download(self) -> None:
        fam = get("web_business_logic_tenant_export")
        scenario = fam.default_scenario
        self.assertIsNotNone(scenario)
        self.assertTrue(scenario.enabled)
        targets = {r.payload.get("target") for r in scenario.responses}
        self.assertEqual(targets, {"/download/"})

    def test_default_spec_attaches_the_enabled_scenario(self) -> None:
        from ctf_generator.spec_generator import default_spec

        spec = default_spec(
            seed="s",
            title="T",
            difficulty="medium",
            family="web_business_logic_tenant_export",
        )
        self.assertTrue(spec.scenario.enabled)


if __name__ == "__main__":
    unittest.main()
