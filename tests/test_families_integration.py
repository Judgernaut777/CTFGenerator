"""End-to-end integration test for every registered challenge family.

For each family in the live registry, build a minimal valid ``ChallengeSpec``
(family + a mode the family actually supports + >=5 checkpoints), render it
into a fresh temp directory via ``generator.create_challenge``, and assert
``validator.validate_challenge`` reports zero errors.

Also asserts the registry-level bookkeeping (``family_names``,
``families_for_category``) reflects all 8 families now registered: the
original ``web_business_logic_tenant_export`` bootstrap plus the 7 Phase 3
template-module families (scada_ics, network, crypto, cloud, forensics,
binary, mobile).

STDLIB ONLY. Run with: PYTHONPATH=src python3 -m unittest
tests.test_families_integration -v
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_generator import families, generator, validator
from ctf_generator.models import ChallengeSpec

# --- Expected registry membership --------------------------------------------

_EXPECTED_FAMILY_CATEGORIES: dict[str, str] = {
    "web_business_logic_tenant_export": "web",
    "scada_ics_modbus_takeover": "scada_ics",
    "network_lateral_pivot": "network",
    "crypto_token_forgery": "crypto",
    "cloud_metadata_ssrf": "cloud",
    "forensics_incident_triage": "forensics",
    "binary_heap_exploit": "binary",
    "mobile_insecure_storage": "mobile",
}

_CHECKPOINTS = [
    "checkpoint-1",
    "checkpoint-2",
    "checkpoint-3",
    "checkpoint-4",
    "checkpoint-5",
]


def _spec_for(family_name: str, seed: str, mode: str | None = None) -> ChallengeSpec:
    """A minimal, valid spec for ``family_name`` using a supported mode.

    ``ChallengeSpec`` is frozen, so the mode is fixed at construction time
    rather than mutated afterwards.
    """
    fam = families.get(family_name)
    return ChallengeSpec(
        title=f"Integration Test: {family_name}",
        category=fam.category,
        difficulty="medium",
        family=family_name,
        seed=seed,
        learning_objectives=["obj-1", "obj-2"],
        checkpoints=list(_CHECKPOINTS),
        mode=mode if mode is not None else fam.modes[0],
    )


class RegistryMembershipTests(unittest.TestCase):
    def test_family_names_lists_all_eight(self) -> None:
        self.assertEqual(families.family_names(), sorted(_EXPECTED_FAMILY_CATEGORIES))

    def test_families_for_category_returns_right_family(self) -> None:
        for name, category in _EXPECTED_FAMILY_CATEGORIES.items():
            names_in_category = {f.name for f in families.families_for_category(category)}
            self.assertIn(
                name,
                names_in_category,
                f"expected {name!r} in families_for_category({category!r})",
            )


class GenerateAndValidateEachFamilyTests(unittest.TestCase):
    def test_all_families_generate_and_validate_clean(self) -> None:
        for family_name in _EXPECTED_FAMILY_CATEGORIES:
            with self.subTest(family=family_name):
                spec = _spec_for(family_name, seed=f"seed-{family_name}")
                with tempfile.TemporaryDirectory() as tmp:
                    output_dir = Path(tmp) / "challenge"
                    generator.create_challenge(
                        output_dir=output_dir,
                        seed=spec.seed,
                        title=spec.title,
                        difficulty=spec.difficulty,
                        family=spec.family,
                        spec=spec,
                    )
                    report = validator.validate_challenge(output_dir)
                    self.assertEqual(
                        report.errors,
                        [],
                        f"{family_name} failed validation: {report.errors}",
                    )

    def test_all_families_generate_and_validate_each_supported_mode(self) -> None:
        # Belt-and-braces: exercise every mode each family declares, not just
        # its first, so mode-specific rendering branches (e.g. scada_ics's
        # red/blue/purple split) are all covered end-to-end.
        for family_name in _EXPECTED_FAMILY_CATEGORIES:
            fam = families.get(family_name)
            for mode in fam.modes:
                with self.subTest(family=family_name, mode=mode):
                    spec = _spec_for(family_name, seed=f"seed-{family_name}-{mode}", mode=mode)
                    with tempfile.TemporaryDirectory() as tmp:
                        output_dir = Path(tmp) / "challenge"
                        generator.create_challenge(
                            output_dir=output_dir,
                            seed=spec.seed,
                            title=spec.title,
                            difficulty=spec.difficulty,
                            family=spec.family,
                            spec=spec,
                        )
                        report = validator.validate_challenge(output_dir)
                        self.assertEqual(
                            report.errors,
                            [],
                            f"{family_name} mode={mode} failed validation: {report.errors}",
                        )


if __name__ == "__main__":
    unittest.main()
