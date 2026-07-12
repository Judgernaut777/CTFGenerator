"""The author-testing facade ``ctf_generator.testing``.

Proves each helper delegates to the REAL underlying check (sdk.lint / generator /
build) and gives the right verdict on crafted good/bad families.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_generator import families, sdk, testing
from ctf_generator.validator import validate_challenge

# A built-in, registered family used where a real generatable family is needed.
_BUILTIN = "web_business_logic_tenant_export"


def _render_deterministic(spec, rng, cve_record=None):
    # Seed-derived only -> byte-identical for the same seed.
    token = rng.getrandbits(32)
    return {
        "public/description.md": f"# {spec.title}\nA benign public brief.\n",
        "private/solution.md": f"# Solution\nflag ctf{{probe_{token:08x}}}\n",
    }


# Module-global mutable state: a render that reads it is NON-deterministic even
# for a fixed seed (it changes across calls in the same process).
_CALL_COUNTER = {"n": 0}


def _render_nondeterministic(spec, rng, cve_record=None):
    _CALL_COUNTER["n"] += 1
    return {
        "public/description.md": f"# {spec.title}\ncall {_CALL_COUNTER['n']}\n",
        "private/solution.md": "# Solution\nsecret\n",
    }


def _render_leaky(spec, rng, cve_record=None):
    # The private flag token appears verbatim in a public file.
    return {
        "public/description.md": "hint: the flag is ctf{probe_leak_9f}\n",
        "private/variant.json": '{"flag": "ctf{probe_leak_9f}"}',
        "private/solution.md": "answer\n",
    }


_REQUIRED = ("challenge.yaml", "public/description.md", "private/solution.md")


def _family(name, render, **overrides):
    base = dict(
        name=name,
        category="web",
        modes=("red",),
        render=render,
        required_files=_REQUIRED,
    )
    base.update(overrides)
    return sdk.Family(**base)


class AssertFamilyOkTests(unittest.TestCase):
    def test_wraps_the_real_linter_pass(self) -> None:
        # A built-in must pass the facade's assert_family_ok (== sdk.assert_family_ok).
        testing.assert_family_ok(families.get(_BUILTIN))

    def test_family_failing_sdk_lint_also_fails_here(self) -> None:
        # Prove it is the SAME check: a family sdk.lint rejects (unsafe path)
        # must be rejected by the facade too.
        def render(spec, rng, cve_record=None):
            return {"/etc/passwd": "x", "public/description.md": "ok"}

        bad = _family("probe_helper_unsafe", render, required_files=("challenge.yaml",))
        with self.assertRaises(sdk.FamilyLintError):
            sdk.assert_family_ok(bad)
        with self.assertRaises(testing.FamilyLintError):
            testing.assert_family_ok(bad)


class AssertDeterministicTests(unittest.TestCase):
    def test_passes_for_a_deterministic_family(self) -> None:
        fam = _family("probe_helper_det", _render_deterministic)
        result = testing.assert_deterministic(fam)
        self.assertIn("public/description.md", result)

    def test_passes_for_a_builtin(self) -> None:
        testing.assert_deterministic(families.get(_BUILTIN))

    def test_raises_for_a_nondeterministic_family(self) -> None:
        fam = _family("probe_helper_nondet", _render_nondeterministic)
        with self.assertRaises(testing.DeterminismError):
            testing.assert_deterministic(fam)


class AssertNoPrivateLeakTests(unittest.TestCase):
    def test_passes_for_a_clean_family(self) -> None:
        fam = _family("probe_helper_clean", _render_deterministic)
        testing.assert_no_private_leak(fam)

    def test_raises_for_a_leaking_family(self) -> None:
        fam = _family("probe_helper_leak", _render_leaky)
        with self.assertRaises(testing.PrivateLeakError):
            testing.assert_no_private_leak(fam)

    def test_uses_the_same_invariant_as_sdk_lint(self) -> None:
        # The leak the facade reports must be the sdk.lint PRIVATE_CONTENT_IN_PUBLIC
        # finding -- same underlying check, not a re-implementation.
        fam = _family("probe_helper_leak2", _render_leaky)
        codes = {i.code for i in sdk.lint_family(fam) if i.severity == "error"}
        self.assertIn("PRIVATE_CONTENT_IN_PUBLIC", codes)


class _RegistryIsolated(unittest.TestCase):
    """Snapshot/restore the process-wide family registry so a test that registers
    a probe family (build_family_in / assert_rebuild call the real generator, which
    needs the family registered) does not leak it into other suites."""

    def setUp(self) -> None:
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)


class BuildFamilyInTests(_RegistryIsolated):
    def test_builds_a_bundle_validate_challenge_accepts(self) -> None:
        fam = families.get(_BUILTIN)
        with tempfile.TemporaryDirectory() as tmp:
            out = testing.build_family_in(fam, Path(tmp) / "chal", seed="probe-build")
            self.assertTrue((out / "challenge.yaml").is_file())
            report = validate_challenge(out)
            self.assertEqual(report.errors, [])


class AssertRebuildByteIdenticalTests(_RegistryIsolated):
    def test_passes_for_a_builtin(self) -> None:
        testing.assert_rebuild_is_byte_identical(
            families.get(_BUILTIN), seed="probe-rebuild"
        )

    def test_raises_for_a_nondeterministic_family(self) -> None:
        fam = _family("probe_helper_rebuild_nondet", _render_nondeterministic)
        with self.assertRaises(testing.RebuildMismatchError):
            testing.assert_rebuild_is_byte_identical(fam)


if __name__ == "__main__":
    unittest.main()
