"""Consolidated generator-determinism conformance suite (Milestone 20).

This is the single, *named* entry point for the generator's conformance
guarantees. It does two things:

1. Aggregates the pre-existing, scattered conformance tests so that a single
   ``unittest test_conformance_suite`` run executes the whole set. The
   constituent suites (loaded via the ``load_tests`` protocol below, NOT
   re-implemented here) are:

   * ``test_baseline_fixtures`` -- byte-stable golden manifests per (family,
     seed) + the no-private-content-in-public invariant.
   * ``test_replay_validator`` -- cross-seed replay (a sibling's solver must
     NOT solve a differently-seeded sibling's instance).
   * ``test_sibling_validator`` -- cross-sibling token uniqueness.
   * ``test_schema_versioning`` -- spec/manifest schema + family capability
     contracts.
   * ``test_models_golden`` -- golden default ``ChallengeSpec.to_mapping()``
     serialization shape.

2. Adds a NEW, non-vacuous conformance assertion that the two load-bearing
   generator invariants hold *directly, run-to-run* (not merely against a
   committed golden):

   * DETERMINISM: the same ``(family, spec, seed)`` generated twice produces a
     byte-identical file tree, including every provenance stamp.
   * NO WALL-CLOCK IN PROVENANCE: the provenance recorded by the generator
     (the ``.ctfgen-build`` ownership marker and ``private/manifest.json`` /
     ``public/manifest.json``) contains NO current-time field -- no value that
     differs between two runs, and no value that parses as a timestamp of
     "now". The only content-derived field, ``spec_sha256``, is asserted
     identical across the two runs (deterministic by construction).

Provenance field names are read from the real writer (``build.py``:
``_build_manifests`` / ``write_build``), not invented: marker = {schema,
schema_version, generator_version, family, seed}; manifests add {spec_version,
family_version, spec_sha256, file_count, ...} and a per-file {sha256, size}
map. None are wall-clock; this suite asserts that property mechanically and is
guarded by a self-test proving the detector actually fires on a planted "now".
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path

from ctf_generator.build import (
    BUILD_MARKER_NAME,
    PRIVATE_MANIFEST,
    PUBLIC_MANIFEST,
)
from ctf_generator.families import family_names
from ctf_generator.generator import create_challenge

# Constituent conformance modules, aggregated (not duplicated) by load_tests.
_CONSTITUENT_MODULES = (
    "test_baseline_fixtures",
    "test_replay_validator",
    "test_sibling_validator",
    "test_schema_versioning",
    "test_models_golden",
)

# Fields that legitimately carry a content-derived value; they must be
# byte-identical across two runs of the same (family, spec, seed).
_CONTENT_DERIVED_FIELDS = ("spec_sha256",)

# A value counts as "wall-clock-like" if it is within this window of the run.
_NOW_WINDOW_SECONDS = 24 * 60 * 60


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_manifest(root: Path) -> dict[str, str]:
    """Map every file (POSIX rel path) under ``root`` to its content SHA-256."""
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out[path.relative_to(root).as_posix()] = _sha256(path)
    return out


def _iter_scalars(obj: object):
    """Yield every scalar (leaf) value in a nested JSON structure."""
    if isinstance(obj, dict):
        for value in obj.values():
            yield from _iter_scalars(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _iter_scalars(value)
    else:
        yield obj


def _looks_like_now(value: object, ref_epoch: float) -> bool:
    """True if ``value`` plausibly encodes the current wall-clock time.

    Catches both numeric epochs (seconds and milliseconds) and ISO-8601
    strings within ``_NOW_WINDOW_SECONDS`` of ``ref_epoch``. Hex digests,
    versions, seeds, family names, sizes and counts do not match.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        for candidate in (float(value), float(value) / 1000.0):
            if abs(candidate - ref_epoch) <= _NOW_WINDOW_SECONDS:
                return True
        return False
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return False
        parsed: datetime | None = None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return abs(parsed.timestamp() - ref_epoch) <= _NOW_WINDOW_SECONDS
    return False


def _load_provenance(root: Path) -> dict[str, dict]:
    """Read the generator's provenance stamps from a published build."""
    provenance: dict[str, dict] = {}
    for name in (BUILD_MARKER_NAME, PRIVATE_MANIFEST, PUBLIC_MANIFEST):
        path = root / name
        if path.is_file():
            provenance[name] = json.loads(path.read_text(encoding="utf-8"))
    return provenance


class DeterminismNoWallClockConformanceTests(unittest.TestCase):
    """Direct, run-to-run determinism + no-wall-clock-in-provenance proof."""

    # One representative family with a public surface (so BOTH manifests +
    # the marker are exercised) plus the fixed spec a bare `ctfgen create` uses.
    FAMILY = "web_business_logic_tenant_export"
    SEED = "conformance:m20"
    TITLE = "Invoice Drift"
    DIFFICULTY = "medium"

    def _generate(self, out: Path) -> None:
        create_challenge(
            output_dir=out,
            seed=self.SEED,
            title=self.TITLE,
            difficulty=self.DIFFICULTY,
            family=self.FAMILY,
            force=True,
        )

    def test_representative_family_is_in_registry(self) -> None:
        # Guard: if the representative family is ever renamed, fail loudly here
        # rather than silently skipping the real assertions below.
        self.assertIn(self.FAMILY, family_names())

    def test_detector_fires_on_planted_now(self) -> None:
        """Non-vacuity guard: the wall-clock detector MUST flag a real 'now'.

        Without this, ``test_provenance_carries_no_wall_clock`` could pass
        simply because the detector never triggers on anything.
        """
        now = time.time()
        self.assertTrue(_looks_like_now(now, now), "epoch-seconds not detected")
        self.assertTrue(_looks_like_now(now * 1000.0, now), "epoch-ms not detected")
        iso = datetime.now(UTC).isoformat()
        self.assertTrue(_looks_like_now(iso, now), "ISO-8601 'now' not detected")
        iso_z = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        self.assertTrue(_looks_like_now(iso_z, now), "ISO-8601 'now' (Z) not detected")
        # ...and does NOT flag the actual provenance-shaped values.
        for benign in ("1.0", "web_business_logic_tenant_export", "medium", 64, 0,
                       "a" * 64, self.SEED):
            self.assertFalse(
                _looks_like_now(benign, now), f"false positive on {benign!r}"
            )

    def test_same_seed_produces_byte_identical_tree_and_provenance(self) -> None:
        """DETERMINISM: two runs of the same (family, spec, seed) match byte-for-byte."""
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "run-a"
            b = Path(tmp) / "run-b"
            self._generate(a)
            self._generate(b)
            manifest_a = _tree_manifest(a)
            manifest_b = _tree_manifest(b)

        self.assertEqual(
            set(manifest_a), set(manifest_b), "generated file SET drifted between runs"
        )
        self.assertTrue(manifest_a, "generator produced no files")
        for rel, digest in manifest_a.items():
            self.assertEqual(
                digest, manifest_b[rel], f"content of {rel} differs between two runs"
            )
        # The provenance stamps are part of the tree, so this also proves the
        # marker + manifests are byte-identical -- i.e. no field varies.
        for name in (BUILD_MARKER_NAME, PRIVATE_MANIFEST):
            self.assertIn(name, manifest_a, f"expected provenance stamp {name} missing")

    def test_provenance_carries_no_wall_clock(self) -> None:
        """NO WALL-CLOCK: no provenance value varies run-to-run or matches 'now'."""
        before = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "run-a"
            b = Path(tmp) / "run-b"
            self._generate(a)
            self._generate(b)
            prov_a = _load_provenance(a)
            prov_b = _load_provenance(b)
        after = time.time()
        ref = (before + after) / 2.0

        self.assertTrue(prov_a, "no provenance stamps were found")
        self.assertEqual(
            set(prov_a), set(prov_b), "provenance stamp SET differs between runs"
        )

        for name, doc_a in prov_a.items():
            doc_b = prov_b[name]
            # (a) No field changes between two runs -> nothing wall-clock/random.
            self.assertEqual(
                doc_a, doc_b, f"provenance stamp {name} is not run-to-run stable"
            )
            # (b) No scalar value looks like the current time.
            for value in _iter_scalars(doc_a):
                self.assertFalse(
                    _looks_like_now(value, ref),
                    f"provenance stamp {name} carries a wall-clock-like value: {value!r}",
                )

        # The one legitimately content-derived field is present and identical
        # across the two runs by construction (spec hash, not a timestamp).
        private_a = prov_a[PRIVATE_MANIFEST]
        private_b = prov_b[PRIVATE_MANIFEST]
        for field in _CONTENT_DERIVED_FIELDS:
            self.assertIn(field, private_a, f"expected content-derived field {field}")
            self.assertEqual(
                private_a[field],
                private_b[field],
                f"content-derived field {field} drifted between two runs",
            )
            self.assertRegex(
                str(private_a[field]), r"^[0-9a-f]{64}$",
                f"{field} is not a SHA-256 digest",
            )


def load_tests(loader: unittest.TestLoader, standard_tests: unittest.TestSuite, pattern):
    """unittest ``load_tests`` protocol: fold the constituent conformance
    suites in so ``unittest test_conformance_suite`` runs the whole set without
    re-implementing any of their logic. Importing here (not at module top)
    keeps the aggregation contained to test collection.
    """
    import importlib

    suite = unittest.TestSuite()
    suite.addTests(standard_tests)  # this module's own new assertions
    for mod_name in _CONSTITUENT_MODULES:
        module = importlib.import_module(mod_name)
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


if __name__ == "__main__":
    unittest.main()
