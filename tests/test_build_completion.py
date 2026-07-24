"""Host tests for the pure build-completion parser (build_challenge slice 2).

Stdlib-only: no DB, no Docker. Proves the mapping/gating/validation of a
``build_challenge`` job's completion result before it drives the (DB-backed)
worker-image-cache + version->image-registry writes in ``WorkerJobService``.
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
        self.assertEqual(completion.definition_slug, "invoice-drift")
        self.assertEqual(completion.version_no, 3)
        self.assertEqual(completion.image_ref, _BUILD_RESULT["image_ref"])
        self.assertEqual(completion.bundle_sha256, _BUILD_RESULT["bundle_sha256"])
        self.assertEqual(completion.image_digest, _BUILD_RESULT["digest"])
        self.assertTrue(completion.has_image_digest)

    def test_none_result_is_not_a_build_completion(self) -> None:
        self.assertIsNone(parse_build_completion(None))

    def test_empty_result_is_not_a_build_completion(self) -> None:
        self.assertIsNone(parse_build_completion({}))

    def test_non_build_result_without_image_ref_is_none(self) -> None:
        # e.g. a run_agent_evaluation result -- carries no image_ref.
        self.assertIsNone(
            parse_build_completion({"solved": True, "steps": 4, "blended_score": 12})
        )

    def test_blank_image_ref_is_treated_as_absent(self) -> None:
        self.assertIsNone(parse_build_completion({**_BUILD_RESULT, "image_ref": "   "}))
        self.assertIsNone(parse_build_completion({**_BUILD_RESULT, "image_ref": ""}))

    def test_missing_digest_yields_no_registry_write_but_still_parses(self) -> None:
        result = {k: v for k, v in _BUILD_RESULT.items() if k != "digest"}
        completion = parse_build_completion(result)
        assert completion is not None
        self.assertIsNone(completion.image_digest)
        self.assertFalse(completion.has_image_digest)

    def test_blank_digest_is_treated_as_absent(self) -> None:
        completion = parse_build_completion({**_BUILD_RESULT, "digest": "  "})
        assert completion is not None
        self.assertIsNone(completion.image_digest)

    def test_image_ref_present_but_missing_definition_slug_raises(self) -> None:
        result = {k: v for k, v in _BUILD_RESULT.items() if k != "definition_slug"}
        with self.assertRaises(ValueError):
            parse_build_completion(result)

    def test_image_ref_present_but_non_int_version_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_build_completion({**_BUILD_RESULT, "version_no": "3"})

    def test_image_ref_present_but_missing_bundle_sha_raises(self) -> None:
        result = {k: v for k, v in _BUILD_RESULT.items() if k != "bundle_sha256"}
        with self.assertRaises(ValueError):
            parse_build_completion(result)


class BuildCompletionInvariantTests(unittest.TestCase):
    def test_rejects_empty_definition_slug(self) -> None:
        with self.assertRaises(ValueError):
            BuildCompletion(
                definition_slug="",
                version_no=1,
                image_ref="img",
                bundle_sha256="x",
            )

    def test_rejects_version_below_one(self) -> None:
        with self.assertRaises(ValueError):
            BuildCompletion(
                definition_slug="d",
                version_no=0,
                image_ref="img",
                bundle_sha256="x",
            )

    def test_rejects_blank_image_ref(self) -> None:
        with self.assertRaises(ValueError):
            BuildCompletion(
                definition_slug="d",
                version_no=1,
                image_ref="   ",
                bundle_sha256="x",
            )

    def test_rejects_blank_image_digest_when_present(self) -> None:
        with self.assertRaises(ValueError):
            BuildCompletion(
                definition_slug="d",
                version_no=1,
                image_ref="img",
                bundle_sha256="x",
                image_digest="  ",
            )

    def test_none_digest_is_allowed(self) -> None:
        completion = BuildCompletion(
            definition_slug="d",
            version_no=1,
            image_ref="img",
            bundle_sha256="x",
            image_digest=None,
        )
        self.assertFalse(completion.has_image_digest)

    def test_secret_free_surface(self) -> None:
        # Only references/hashes appear on the parsed value -- never a flag/token.
        completion = parse_build_completion(_BUILD_RESULT)
        assert completion is not None
        blob = repr(completion)
        self.assertNotIn("ctf{", blob)
        self.assertNotIn("flag", blob.lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
