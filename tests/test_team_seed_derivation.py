"""PR C: authoritative team seed and trusted family answer derivation."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctf_generator.application.submissions.verifier import SpecFlagVerifier
from ctf_generator.domain.authoring.models import ChallengeVersion
from ctf_generator.families import Family, derive_family_answer, register


class TeamSeedDerivationTests(unittest.TestCase):
    def test_family_derivation_is_seed_deterministic(self) -> None:
        family = Family(
            name="seeded-test",
            category="test",
            modes=("blue",),
            render=lambda spec, rng, cve_record=None: {},
            required_files=(),
            derive_answer=lambda spec, seed: f"answer:{spec['case']}:{seed}",
        )
        self.assertEqual(
            derive_family_answer(family, {"case": "alpha"}, "team-a-seed"),
            derive_family_answer(family, {"case": "alpha"}, "team-a-seed"),
        )
        self.assertNotEqual(
            derive_family_answer(family, {"case": "alpha"}, "team-a-seed"),
            derive_family_answer(family, {"case": "alpha"}, "team-b-seed"),
        )

    def test_verifier_uses_only_the_resolved_seed_for_family_derivation(self) -> None:
        family = Family(
            name="seeded-verifier-test",
            category="test",
            modes=("blue",),
            render=lambda spec, rng, cve_record=None: {},
            required_files=(),
            derive_answer=lambda spec, seed: f"answer:{seed}",
        )
        register(family)
        version = ChallengeVersion(
            definition_slug="case",
            version_no=1,
            state="published",
            family_version="1.0",
            seed="version-seed",
            spec_sha256="a" * 64,
            spec={"answer_derivation": {"family": family.name}},
            spec_version="1.1",
            published_at=datetime(2026, 8, 26, tzinfo=UTC),
        )
        verifier = SpecFlagVerifier()
        self.assertTrue(verifier.verify(version, "issued-team-seed", "answer:issued-team-seed"))
        self.assertFalse(verifier.verify(version, "other-team-seed", "answer:issued-team-seed"))


if __name__ == "__main__":
    unittest.main()
