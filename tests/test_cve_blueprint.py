from __future__ import annotations

import unittest

from ctf_generator import families
from ctf_generator.cve_blueprint import (
    CATEGORY_FAMILY_MAP,
    CveBlueprint,
    blueprint_from_cve,
    content_hash,
    difficulty_from_cvss,
    fold_seed,
    spec_from_cve,
)
from ctf_generator.cve_source import CveRecord, SnapshotCveSource
from ctf_generator.spec_generator import validate_spec

_SOURCE = SnapshotCveSource()


def _record(cve_id: str) -> CveRecord:
    record = _SOURCE.get(cve_id)
    assert record is not None, f"fixture missing from SnapshotCveSource: {cve_id}"
    return record


class FoldSeedTests(unittest.TestCase):
    def test_deterministic_same_inputs(self) -> None:
        self.assertEqual(
            fold_seed("base-1", "CVE-2021-44228"),
            fold_seed("base-1", "CVE-2021-44228"),
        )

    def test_varies_with_base_seed(self) -> None:
        self.assertNotEqual(
            fold_seed("base-1", "CVE-2021-44228"),
            fold_seed("base-2", "CVE-2021-44228"),
        )

    def test_varies_with_cve_id(self) -> None:
        self.assertNotEqual(
            fold_seed("base-1", "CVE-2021-44228"),
            fold_seed("base-1", "CVE-2017-5638"),
        )


class DifficultyFromCvssTests(unittest.TestCase):
    def test_hard_at_and_above_nine(self) -> None:
        self.assertEqual(difficulty_from_cvss(9.0), "hard")
        self.assertEqual(difficulty_from_cvss(10.0), "hard")
        self.assertEqual(difficulty_from_cvss(9.8), "hard")

    def test_medium_between_seven_and_nine(self) -> None:
        self.assertEqual(difficulty_from_cvss(7.0), "medium")
        self.assertEqual(difficulty_from_cvss(8.8), "medium")
        self.assertEqual(difficulty_from_cvss(8.999), "medium")

    def test_easy_below_seven(self) -> None:
        self.assertEqual(difficulty_from_cvss(6.999), "easy")
        self.assertEqual(difficulty_from_cvss(4.3), "easy")
        self.assertEqual(difficulty_from_cvss(0.0), "easy")


class ContentHashTests(unittest.TestCase):
    def test_stable_for_same_record(self) -> None:
        record = _record("CVE-2021-44228")
        self.assertEqual(content_hash(record), content_hash(record))

    def test_stable_across_equal_but_distinct_records(self) -> None:
        record = _record("CVE-2021-44228")
        clone = CveRecord(**record.to_mapping())
        self.assertEqual(content_hash(record), content_hash(clone))

    def test_differs_for_different_records(self) -> None:
        self.assertNotEqual(
            content_hash(_record("CVE-2021-44228")),
            content_hash(_record("CVE-2017-5638")),
        )

    def test_changes_when_content_changes(self) -> None:
        record = _record("CVE-2021-44228")
        mutated = CveRecord(**{**record.to_mapping(), "cvss_score": 1.0})
        self.assertNotEqual(content_hash(record), content_hash(mutated))

    def test_is_hex_sha256_digest(self) -> None:
        digest = content_hash(_record("CVE-2021-44228"))
        self.assertEqual(len(digest), 64)
        int(digest, 16)  # raises ValueError if not valid hex


class CategoryFamilyMapTests(unittest.TestCase):
    def test_exact_canonical_map(self) -> None:
        self.assertEqual(
            CATEGORY_FAMILY_MAP,
            {
                "web": "web_business_logic_tenant_export",
                "scada_ics": "scada_ics_modbus_takeover",
                "network": "network_lateral_pivot",
                "crypto": "crypto_token_forgery",
                "cloud": "cloud_metadata_ssrf",
                "forensics": "forensics_incident_triage",
                "binary": "binary_heap_exploit",
                "mobile": "mobile_insecure_storage",
            },
        )


class BlueprintFromCveTests(unittest.TestCase):
    def test_defaults_derived_from_record(self) -> None:
        record = _record("CVE-2021-44228")  # web, CVSS 10.0
        blueprint = blueprint_from_cve(record, base_seed="base")
        self.assertIsInstance(blueprint, CveBlueprint)
        self.assertEqual(blueprint.family, "web_business_logic_tenant_export")
        self.assertEqual(blueprint.difficulty, "hard")
        self.assertEqual(blueprint.mode, "red")
        self.assertEqual(blueprint.cve_id, "CVE-2021-44228")
        self.assertIn("CVE-2021-44228", blueprint.themed_title)
        self.assertGreaterEqual(len(blueprint.themed_objectives), 3)
        self.assertGreaterEqual(len(blueprint.themed_checkpoints), 5)

    def test_forensics_defaults_to_blue_mode(self) -> None:
        record = _record("CVE-2020-13379")  # forensics category fixture
        blueprint = blueprint_from_cve(record, base_seed="base")
        self.assertEqual(blueprint.mode, "blue")
        self.assertEqual(blueprint.family, "forensics_incident_triage")

    def test_overrides_are_honored(self) -> None:
        record = _record("CVE-2021-44228")
        blueprint = blueprint_from_cve(
            record,
            base_seed="base",
            family="custom_family",
            difficulty="easy",
            mode="blue",
            title="My Title",
        )
        self.assertEqual(blueprint.family, "custom_family")
        self.assertEqual(blueprint.difficulty, "easy")
        self.assertEqual(blueprint.mode, "blue")
        self.assertEqual(blueprint.themed_title, "My Title")

    def test_deterministic_across_calls(self) -> None:
        record = _record("CVE-2021-3156")
        first = blueprint_from_cve(record, base_seed="base")
        second = blueprint_from_cve(record, base_seed="base")
        self.assertEqual(first, second)

    def test_themed_text_is_on_theme(self) -> None:
        record = _record("CVE-2021-3156")  # sudo heap overflow, CWE-193/CWE-787
        blueprint = blueprint_from_cve(record, base_seed="base")
        self.assertIn("CWE-193", blueprint.themed_title)
        joined_checkpoints = " ".join(blueprint.themed_checkpoints)
        self.assertIn("sudo", joined_checkpoints.lower())


class SpecFromCveTests(unittest.TestCase):
    def test_web_category_validates_cleanly(self) -> None:
        record = _record("CVE-2021-44228")
        spec = spec_from_cve(record, base_seed="base-seed")
        self.assertEqual(validate_spec(spec), [])
        self.assertEqual(spec.family, "web_business_logic_tenant_export")
        self.assertEqual(spec.category, "web")
        self.assertEqual(spec.difficulty, "hard")
        self.assertEqual(spec.mode, "red")
        self.assertEqual(spec.cve_refs, ["CVE-2021-44228"])
        self.assertEqual(spec.cve_content_hash, content_hash(record))
        self.assertEqual(spec.seed, fold_seed("base-seed", "CVE-2021-44228"))
        self.assertGreaterEqual(len(spec.checkpoints), 5)

    def test_binary_category_uses_its_now_registered_family(self) -> None:
        # binary_heap_exploit was wired up in Phase 3.5, so a "binary" CVE
        # resolves to its intended family instead of falling back.
        record = _record("CVE-2021-3156")  # category "binary"
        self.assertTrue(families.is_registered(CATEGORY_FAMILY_MAP["binary"]))
        spec = spec_from_cve(record, base_seed="base-seed")
        self.assertEqual(validate_spec(spec), [])
        self.assertEqual(spec.family, "binary_heap_exploit")
        self.assertEqual(spec.mode, "red")
        self.assertEqual(spec.category, "binary")
        self.assertIn("CVE-2021-3156", spec.title)
        self.assertEqual(spec.cve_refs, ["CVE-2021-3156"])
        self.assertEqual(spec.cve_content_hash, content_hash(record))

    def test_forensics_category_uses_its_now_registered_family_in_blue_mode(self) -> None:
        # forensics_incident_triage ("blue"-only) was wired up in Phase 3.5,
        # so a "forensics" CVE resolves to its intended family and keeps its
        # blue mode instead of falling back and downgrading.
        record = _record("CVE-2020-13379")
        self.assertTrue(families.is_registered(CATEGORY_FAMILY_MAP["forensics"]))
        spec = spec_from_cve(record, base_seed="base-seed")
        self.assertEqual(validate_spec(spec), [])
        self.assertEqual(spec.family, "forensics_incident_triage")
        self.assertEqual(spec.mode, "blue")
        self.assertEqual(spec.category, "forensics")

    def test_unregistered_family_override_falls_back_but_keeps_theme(self) -> None:
        # spec_from_cve's fallback path is still reachable via an explicit
        # override naming a family that isn't registered (now that every
        # CATEGORY_FAMILY_MAP entry is registered, this is the only way to
        # exercise it).
        record = _record("CVE-2021-3156")
        self.assertFalse(families.is_registered("totally_bogus_family"))
        spec = spec_from_cve(record, base_seed="base-seed", family="totally_bogus_family")
        self.assertEqual(validate_spec(spec), [])
        # Falls back to the always-registered family...
        self.assertEqual(spec.family, "web_business_logic_tenant_export")
        # ...but category, title, provenance stay CVE-derived.
        self.assertEqual(spec.category, "binary")
        self.assertIn("CVE-2021-3156", spec.title)
        self.assertEqual(spec.cve_refs, ["CVE-2021-3156"])
        self.assertEqual(spec.cve_content_hash, content_hash(record))

    def test_unregistered_family_override_falls_back_and_downgrades_mode(self) -> None:
        # An explicit blue-mode override paired with an unregistered family
        # must still fall back to a family that supports the resolved mode,
        # downgrading to "red" so validate_spec() accepts the result.
        record = _record("CVE-2020-13379")
        self.assertFalse(families.is_registered("totally_bogus_family"))
        spec = spec_from_cve(
            record, base_seed="base-seed", family="totally_bogus_family", mode="blue"
        )
        self.assertEqual(validate_spec(spec), [])
        self.assertEqual(spec.family, "web_business_logic_tenant_export")
        self.assertEqual(spec.mode, "red")
        self.assertEqual(spec.category, "forensics")

    def test_all_bundled_categories_produce_valid_specs(self) -> None:
        for record in SnapshotCveSource().fetch(limit=100):
            with self.subTest(cve_id=record.cve_id, category=record.category):
                spec = spec_from_cve(record, base_seed="fixed-base")
                self.assertEqual(validate_spec(spec), [])

    def test_deterministic_across_calls(self) -> None:
        record = _record("CVE-2014-0160")
        first = spec_from_cve(record, base_seed="base-seed")
        second = spec_from_cve(record, base_seed="base-seed")
        self.assertEqual(first, second)

    def test_explicit_overrides_flow_through(self) -> None:
        record = _record("CVE-2021-44228")
        spec = spec_from_cve(
            record,
            base_seed="base-seed",
            difficulty="easy",
            title="Custom Title",
        )
        self.assertEqual(validate_spec(spec), [])
        self.assertEqual(spec.difficulty, "easy")
        self.assertEqual(spec.title, "Custom Title")

    def test_mode_override_unsupported_by_family_is_downgraded(self) -> None:
        # "web_business_logic_tenant_export" (the resolved family for a web
        # CVE) only supports "red" -- an explicit "blue" override must not
        # produce an invalid spec.
        record = _record("CVE-2021-44228")
        spec = spec_from_cve(record, base_seed="base-seed", mode="blue")
        self.assertEqual(validate_spec(spec), [])
        self.assertEqual(spec.mode, "red")


if __name__ == "__main__":
    unittest.main()
