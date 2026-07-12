"""The sdk facade re-exports the real authoring types (identity, not shims)."""

from __future__ import annotations

import unittest

from ctf_generator import build as _build
from ctf_generator import cve_source as _cve_source
from ctf_generator import families as _families
from ctf_generator import models as _models
from ctf_generator import schema as _schema
from ctf_generator import sdk
from ctf_generator import spec_generator as _spec_generator


class FacadeExportsTests(unittest.TestCase):
    def test_documented_names_present(self) -> None:
        expected = {
            "Family",
            "FamilyRenderer",
            "ScoringHints",
            "DefaultSpecBuilder",
            "register",
            "get",
            "is_registered",
            "family_names",
            "families_for_mode",
            "families_for_category",
            "ChallengeSpec",
            "ScenarioSpec",
            "TriggerSpec",
            "ResponseSpec",
            "AIResistance",
            "DynamicVariation",
            "CveRecord",
            "default_spec",
            "validate_spec",
            "spec_to_dict",
            "spec_from_dict",
            "DIFFICULTIES",
            "validate_relative_path",
            "parse_semver",
            "SchemaError",
            "family_from_module",
            "is_renderer_module",
            "ModuleInterfaceError",
            "lint_family",
            "lint_renderer_module",
            "assert_family_ok",
            "LintIssue",
            "FamilyLintError",
            "load_entry_point_families",
            "bootstrap_family_plugins",
            "ENTRY_POINT_GROUP",
        }
        self.assertEqual(expected, set(sdk.__all__))
        for name in expected:
            self.assertTrue(hasattr(sdk, name), f"sdk facade missing {name}")


class FacadeIdentityTests(unittest.TestCase):
    """Every re-export IS the object at its canonical internal home, so authoring
    against the facade is authoring against the real types."""

    def test_registry_and_family_record_identity(self) -> None:
        self.assertIs(sdk.Family, _families.Family)
        self.assertIs(sdk.FamilyRenderer, _families.FamilyRenderer)
        self.assertIs(sdk.ScoringHints, _families.ScoringHints)
        self.assertIs(sdk.register, _families.register)
        self.assertIs(sdk.get, _families.get)
        self.assertIs(sdk.is_registered, _families.is_registered)
        self.assertIs(sdk.family_names, _families.family_names)
        self.assertIs(sdk.families_for_mode, _families.families_for_mode)
        self.assertIs(sdk.families_for_category, _families.families_for_category)

    def test_spec_value_type_identity(self) -> None:
        self.assertIs(sdk.ChallengeSpec, _models.ChallengeSpec)
        self.assertIs(sdk.ScenarioSpec, _models.ScenarioSpec)
        self.assertIs(sdk.TriggerSpec, _models.TriggerSpec)
        self.assertIs(sdk.ResponseSpec, _models.ResponseSpec)
        self.assertIs(sdk.AIResistance, _models.AIResistance)
        self.assertIs(sdk.DynamicVariation, _models.DynamicVariation)
        # A cve_driven family's render() receives a CveRecord -> it must be typeable
        # against the stable surface (7 of 8 built-ins are CVE-driven).
        self.assertIs(sdk.CveRecord, _cve_source.CveRecord)

    def test_spec_construction_identity(self) -> None:
        self.assertIs(sdk.default_spec, _spec_generator.default_spec)
        self.assertIs(sdk.validate_spec, _spec_generator.validate_spec)
        self.assertIs(sdk.spec_to_dict, _spec_generator.spec_to_dict)
        self.assertIs(sdk.spec_from_dict, _spec_generator.spec_from_dict)

    def test_build_and_schema_helper_identity(self) -> None:
        self.assertIs(sdk.validate_relative_path, _build.validate_relative_path)
        self.assertIs(sdk.parse_semver, _schema.parse_semver)
        self.assertIs(sdk.SchemaError, _schema.SchemaError)

    def test_registering_via_facade_hits_the_real_registry(self) -> None:
        # A Family registered through the facade is get()-able through the real
        # module -- proving the facade shares the one process-wide registry.
        fam = sdk.Family(
            name="facade_identity_probe_family",
            category="web",
            modes=("red",),
            render=lambda spec, rng, cve_record=None: {"public/x.md": "x"},
            required_files=("challenge.yaml",),
        )
        try:
            sdk.register(fam)
            self.assertTrue(_families.is_registered("facade_identity_probe_family"))
            self.assertIs(_families.get("facade_identity_probe_family"), fam)
        finally:
            _families._REGISTRY.pop("facade_identity_probe_family", None)


if __name__ == "__main__":
    unittest.main()
