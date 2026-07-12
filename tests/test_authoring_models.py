"""Pure unit tests for the authoring domain value types (host-runnable, stdlib)."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctf_generator.domain.authoring.models import (
    ChallengeBuild,
    ChallengeDefinition,
    ChallengePublication,
    ChallengeVersion,
)

_TS = datetime(2026, 6, 1, tzinfo=UTC)


def _version(**kw):
    base = dict(
        definition_slug="d",
        version_no=1,
        state="draft",
        family_version="1.0",
        seed="s",
        spec_sha256="h",
        spec={"a": 1},
        spec_version="1.0",
    )
    base.update(kw)
    return ChallengeVersion(**base)


class ChallengeDefinitionTests(unittest.TestCase):
    def test_valid(self) -> None:
        d = ChallengeDefinition(family="web", slug="x", title="T")
        self.assertEqual(d.slug, "x")

    def test_rejects_empty(self) -> None:
        for kw in ({"family": " "}, {"slug": ""}, {"title": "\t"}):
            fields = {"family": "web", "slug": "x", "title": "T", **kw}
            with self.assertRaises(ValueError):
                ChallengeDefinition(**fields)


class ChallengeVersionTests(unittest.TestCase):
    def test_valid_draft(self) -> None:
        v = _version()
        self.assertEqual(v.state, "draft")
        self.assertIsNone(v.published_at)

    def test_valid_published(self) -> None:
        v = _version(state="published", published_at=_TS)
        self.assertEqual(v.state, "published")

    def test_valid_archived_keeps_timestamp(self) -> None:
        v = _version(state="archived", published_at=_TS)
        self.assertEqual(v.published_at, _TS)

    def test_draft_with_timestamp_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _version(state="draft", published_at=_TS)

    def test_published_without_timestamp_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _version(state="published", published_at=None)

    def test_archived_without_timestamp_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _version(state="archived", published_at=None)

    def test_bad_state_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _version(state="live")

    def test_version_no_must_be_positive(self) -> None:
        with self.assertRaises(ValueError):
            _version(version_no=0)

    def test_spec_must_be_mapping(self) -> None:
        with self.assertRaises(ValueError):
            _version(spec="not-a-mapping")

    def test_spec_excluded_from_equality_and_hashable(self) -> None:
        # spec_sha256 is the identity; the spec mapping (jsonb, not
        # byte-identity-preserving) is excluded from __eq__/__hash__.
        a = _version(spec={"x": 1})
        b = _version(spec={"x": 2})  # different spec, same identity fields
        self.assertEqual(a, b)
        # Hashable despite holding a dict (spec is compare=False -> not hashed).
        self.assertEqual(len({a, b}), 1)


class ChallengeBuildTests(unittest.TestCase):
    def test_valid(self) -> None:
        b = ChallengeBuild(
            build_sha256="bh",
            definition_slug="d",
            version_no=1,
            family="web",
            seed="s",
            spec_sha256="h",
            generator_version="0.9",
            manifest={"files": []},
        )
        self.assertIsNone(b.family_version)

    def test_rejects_empty_build_hash(self) -> None:
        with self.assertRaises(ValueError):
            ChallengeBuild(
                build_sha256="",
                definition_slug="d",
                version_no=1,
                family="web",
                seed="s",
                spec_sha256="h",
                generator_version="0.9",
                manifest={},
            )

    def test_manifest_excluded_from_equality_and_hashable(self) -> None:
        def build(manifest):
            return ChallengeBuild(
                build_sha256="bh",
                definition_slug="d",
                version_no=1,
                family="web",
                seed="s",
                spec_sha256="h",
                generator_version="0.9",
                manifest=manifest,
            )

        self.assertEqual(build({"a": 1}), build({"a": 2}))
        self.assertEqual(len({build({"a": 1}), build({"a": 2})}), 1)


class ChallengePublicationTests(unittest.TestCase):
    def test_defaults(self) -> None:
        p = ChallengePublication("c", "d", 1)
        self.assertEqual(p.initial_value, 500)
        self.assertEqual(p.minimum_value, 100)
        self.assertEqual(p.decay_function, "static")

    def test_minimum_gt_initial_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ChallengePublication("c", "d", 1, initial_value=100, minimum_value=200)

    def test_negative_initial_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ChallengePublication("c", "d", 1, initial_value=-1, minimum_value=-1)

    def test_bad_decay_function_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ChallengePublication("c", "d", 1, decay_function="exp")


if __name__ == "__main__":
    unittest.main()
