"""Unit coverage for typed, private answer-verifier specifications (PR B)."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctf_generator.application.submissions.verifier import SpecFlagVerifier
from ctf_generator.domain.answers.models import AnswerSpecError, parse_answer_spec
from ctf_generator.domain.authoring.models import ChallengeVersion

_NOW = datetime(2026, 8, 26, tzinfo=UTC)


def _version(spec: dict[str, object]) -> ChallengeVersion:
    return ChallengeVersion(
        definition_slug="osint-case",
        version_no=1,
        state="published",
        family_version="1.0.0",
        seed="fixed-seed",
        spec_sha256="a" * 64,
        spec=spec,
        spec_version="1.1",
        published_at=_NOW,
    )


class TypedAnswerSpecTests(unittest.TestCase):
    def test_aliases_normalize_case_and_punctuation(self) -> None:
        spec = parse_answer_spec({"kind": "aliases", "answers": ["St. John's", "Saint Johns"]})
        verifier = SpecFlagVerifier()
        version = _version({"answer_verifier": spec.to_mapping()})
        self.assertTrue(verifier.verify(version, None, "  saint-johns! "))
        self.assertFalse(verifier.verify(version, None, "Saint James"))

    def test_coordinate_haversine_accepts_inside_and_rejects_outside_tolerance(self) -> None:
        spec = parse_answer_spec(
            {
                "kind": "coordinate",
                "latitude": 51.5007,
                "longitude": -0.1246,
                "tolerance_meters": 100,
            }
        )
        verifier = SpecFlagVerifier()
        version = _version({"answer_verifier": spec.to_mapping()})
        self.assertTrue(verifier.verify(version, None, "51.5014,-0.1246"))
        self.assertFalse(verifier.verify(version, None, "51.5020,-0.1246"))

    def test_identifier_configured_prefix_and_separator_normalization(self) -> None:
        spec = parse_answer_spec(
            {
                "kind": "identifier",
                "value": "IMO1234567",
                "strip_prefixes": ["IMO"],
                "strip_separators": True,
            }
        )
        verifier = SpecFlagVerifier()
        version = _version({"answer_verifier": spec.to_mapping()})
        self.assertTrue(verifier.verify(version, None, "imo-123 4567"))
        self.assertFalse(verifier.verify(version, None, "IMO1234568"))

    def test_multipart_requires_every_named_field(self) -> None:
        spec = parse_answer_spec(
            {
                "kind": "multipart",
                "fields": {
                    "vessel": {"kind": "aliases", "answers": ["Aurora"]},
                    "imo": {
                        "kind": "identifier",
                        "value": "IMO1234567",
                        "strip_prefixes": ["IMO"],
                        "strip_separators": True,
                    },
                },
            }
        )
        verifier = SpecFlagVerifier()
        version = _version({"answer_verifier": spec.to_mapping()})
        self.assertTrue(verifier.verify(version, None, '{"imo":"imo-1234567","vessel":"aurora"}'))
        self.assertFalse(verifier.verify(version, None, '{"vessel":"aurora"}'))

    def test_malformed_specs_and_candidates_are_rejected(self) -> None:
        with self.assertRaises(AnswerSpecError):
            parse_answer_spec(
                {"kind": "coordinate", "latitude": 91, "longitude": 0, "tolerance_meters": 1}
            )
        version = _version(
            {
                "answer_verifier": {
                    "kind": "multipart",
                    "fields": {"place": {"kind": "aliases", "answers": ["Rome"]}},
                }
            }
        )
        self.assertFalse(SpecFlagVerifier().verify(version, None, "not-json"))

    def test_legacy_flag_remains_exact(self) -> None:
        verifier = SpecFlagVerifier()
        version = _version({"flag": "ctf{legacy}"})
        self.assertTrue(verifier.verify(version, None, "ctf{legacy}"))
        self.assertFalse(verifier.verify(version, None, "CTF{legacy}"))

    def test_author_schema_rejects_malformed_answer_verifier(self) -> None:
        try:
            from ctf_generator.interfaces.api.schemas.challenges import (
                ChallengeVersionCreateRequest,
            )
        except ImportError:
            self.skipTest("API extra is not installed")
        with self.assertRaises(ValueError):
            ChallengeVersionCreateRequest(
                definition_slug="osint-case",
                seed="fixed-seed",
                family_version="1.0.0",
                spec={"answer_verifier": {"kind": "coordinate", "latitude": 999}},
            )

    def test_public_version_response_redacts_private_answer_material(self) -> None:
        try:
            from ctf_generator.interfaces.api.schemas.challenges import version_to_response
        except ImportError:
            self.skipTest("API extra is not installed")
        private = {"kind": "aliases", "answers": ["private-answer"]}
        response = version_to_response(
            _version({"title": "Public", "flag": "ctf{private}", "answer_verifier": private})
        )
        rendered = repr(response)
        self.assertNotIn("ctf{private}", rendered)
        self.assertNotIn("private-answer", rendered)
        self.assertNotIn("answer_verifier", response["spec"])
        self.assertNotIn("flag", response["spec"])


if __name__ == "__main__":
    unittest.main()
