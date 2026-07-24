"""Host tests for the pure build-completion parser (build_challenge slice 2).

Stdlib-only: no DB, no Docker. Proves the mapping/gating of a ``build_challenge``
job's completion result before it drives the (DB-backed) worker-image-cache +
version->image-registry writes in ``WorkerJobService``. Key contract: the parser
extracts only the build OUTPUTS (image_ref/digest/bundle), never the payload's
slug/version (the authoritative target is the job), and NEVER raises (a bad
worker payload must not be able to veto its job's terminalization).
"""

from __future__ import annotations

import unittest

from ctf_generator.application.execution.build_completion import (
    BuildCompletion,
    parse_build_completion,
)

# The exact shape workers/worker.py::_do_build_challenge reports on completion.
_BUILD_RESULT = {
    "definition_slug": "invoice-drift",
    "version_no": 3,
    "bundle_sha256": "a" * 64,
    "image_ref": "ctfgen-build/invoice-drift:v3-abcdef0123456789",
    "digest": "sha256:" + "b" * 64,
}


class ParseBuildCompletionTests(unittest.TestCase):
    def test_maps_a_full_build_result(self) -> None:
        completion = parse_build_completion(_BUILD_RESULT)
        assert completion is not None
        self.assertEqual(completion.image_ref, _BUILD_RESULT["image_ref"])
        self.assertEqual(completion.bundle_sha256, _BUILD_RESULT["bundle_sha256"])
        self.assertEqual(completion.image_digest, _BUILD_RESULT["digest"])
        self.assertTrue(completion.can_record_image)

    def test_does_not_expose_payload_slug_or_version(self) -> None:
        # The target version is the JOB's, never the payload's -- the parsed
        # value must not surface (and cannot be trusted for) slug/version.
        completion = parse_build_completion(_BUILD_RESULT)
        assert completion is not None
        self.assertFalse(hasattr(completion, "definition_slug"))
        self.assertFalse(hasattr(completion, "version_no"))

    def test_none_result_is_not_a_build_completion(self) -> None:
        self.assertIsNone(parse_build_completion(None))

    def test_empty_result_is_not_a_build_completion(self) -> None:
        self.assertIsNone(parse_build_completion({}))

    def test_non_build_result_without_image_ref_is_none(self) -> None:
        self.assertIsNone(
            parse_build_completion({"solved": True, "steps": 4, "blended_score": 12})
        )

    def test_blank_or_missing_image_ref_is_treated_as_absent(self) -> None:
        self.assertIsNone(parse_build_completion({**_BUILD_RESULT, "image_ref": "   "}))
        self.assertIsNone(parse_build_completion({**_BUILD_RESULT, "image_ref": ""}))
        self.assertIsNone(
            parse_build_completion({k: v for k, v in _BUILD_RESULT.items() if k != "image_ref"})
        )

    def test_missing_digest_disables_registry_but_still_parses(self) -> None:
        result = {k: v for k, v in _BUILD_RESULT.items() if k != "digest"}
        completion = parse_build_completion(result)
        assert completion is not None
        self.assertIsNone(completion.image_digest)
        self.assertFalse(completion.can_record_image)

    def test_missing_bundle_disables_registry_but_still_parses(self) -> None:
        result = {k: v for k, v in _BUILD_RESULT.items() if k != "bundle_sha256"}
        completion = parse_build_completion(result)
        assert completion is not None
        self.assertIsNone(completion.bundle_sha256)
        self.assertFalse(completion.can_record_image)

    def test_blank_digest_and_bundle_are_treated_as_absent(self) -> None:
        completion = parse_build_completion(
            {**_BUILD_RESULT, "digest": "  ", "bundle_sha256": ""}
        )
        assert completion is not None
        self.assertIsNone(completion.image_digest)
        self.assertIsNone(completion.bundle_sha256)
        self.assertFalse(completion.can_record_image)

    def test_never_raises_on_malformed_sibling_fields(self) -> None:
        # A hostile/misreporting worker payload must NEVER raise out of the parser
        # (that would let it veto its own job's terminalization). The parser
        # ignores the payload's slug/version entirely, so their type is irrelevant.
        weird = {
            "image_ref": "ctfgen-build/x:v1-deadbeefdeadbeef",
            "definition_slug": 123,          # wrong type -- ignored
            "version_no": "not-an-int",       # wrong type -- ignored
            "bundle_sha256": {"nested": "junk"},  # wrong type -> absent
            "digest": ["list"],               # wrong type -> absent
        }
        completion = parse_build_completion(weird)  # must not raise
        assert completion is not None
        self.assertEqual(completion.image_ref, "ctfgen-build/x:v1-deadbeefdeadbeef")
        self.assertIsNone(completion.bundle_sha256)
        self.assertIsNone(completion.image_digest)
        self.assertFalse(completion.can_record_image)


class BuildCompletionInvariantTests(unittest.TestCase):
    def test_rejects_blank_image_ref_on_direct_construction(self) -> None:
        with self.assertRaises(ValueError):
            BuildCompletion(image_ref="   ")

    def test_none_digest_and_bundle_allowed(self) -> None:
        completion = BuildCompletion(image_ref="img")
        self.assertIsNone(completion.image_digest)
        self.assertIsNone(completion.bundle_sha256)
        self.assertFalse(completion.can_record_image)

    def test_can_record_image_requires_both_digest_and_bundle(self) -> None:
        self.assertFalse(BuildCompletion("img", bundle_sha256="b").can_record_image)
        self.assertFalse(BuildCompletion("img", image_digest="d").can_record_image)
        self.assertTrue(
            BuildCompletion("img", bundle_sha256="b", image_digest="d").can_record_image
        )

    def test_secret_free_surface(self) -> None:
        completion = parse_build_completion(_BUILD_RESULT)
        assert completion is not None
        blob = repr(completion)
        self.assertNotIn("ctf{", blob)
        self.assertNotIn("flag", blob.lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
