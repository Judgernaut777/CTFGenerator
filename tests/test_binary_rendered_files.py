"""RED-GREEN tests for PR A: Binary-safe generated files.

Tests that the new RenderedFile/rendered-bytes contract preserves exact bytes,
handles non-UTF-8, integrates with manifests, deterministic rebuilds, private
leak detection, file limits, and text-family compatibility.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_generator import build, families, generator, sdk
from ctf_generator.sdk import lint
from ctf_generator.spec_generator import default_spec


class RenderedFileContractTests(unittest.TestCase):
    """Task A1: Public rendered-file value preserves bytes and UTF-8."""

    def setUp(self) -> None:
        # Snapshot the registry so we can register probe families
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        # Restore registry
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)

    def test_rendered_file_preserves_exact_bytes(self) -> None:
        """A renderer returning bytes writes those exact bytes to disk."""

        # This test will fail until RenderedFile/normalizer is implemented
        def render(spec, rng, cve_record=None):
            binary_payload = b"\x00\x01\x02\x03\xff\xfe\xfd\xfc" + b"text"
            return {"public/evidence/sample.bin": binary_payload}

        fam = self._make_family("probe_binary_exact", render)
        families.register(fam)  # Register for generator.create_challenge
        spec = default_spec(seed="bin-seed-1", title="Bin", difficulty="medium", family=fam.name)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )
            data = (out / "public/evidence/sample.bin").read_bytes()
            self.assertEqual(data, b"\x00\x01\x02\x03\xff\xfe\xfd\xfc" + b"text")

    def test_rendered_file_utf8_string_roundtrip(self) -> None:
        """A renderer returning str encodes as UTF-8 and writes exact bytes."""

        def render(spec, rng, cve_record=None):
            return {"public/description.md": "hello \u00e9 \u2665\n"}

        fam = self._make_family("probe_utf8_str", render)
        families.register(fam)
        spec = default_spec(seed="bin-seed-2", title="UTF8", difficulty="medium", family=fam.name)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )
            data = (out / "public/description.md").read_bytes()
            self.assertEqual(data, "hello \u00e9 \u2665\n".encode("utf-8"))

    def test_rendered_file_mixed_str_and_bytes(self) -> None:
        """A renderer can return both str and bytes in the same bundle."""

        def render(spec, rng, cve_record=None):
            return {
                "public/text.txt": "plain text\n",
                "public/binary.bin": b"\xde\xad\xbe\xef",
            }

        fam = self._make_family("probe_mixed", render)
        families.register(fam)
        spec = default_spec(seed="bin-seed-3", title="Mixed", difficulty="medium", family=fam.name)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )
            self.assertEqual((out / "public/text.txt").read_bytes(), b"plain text\n")
            self.assertEqual((out / "public/binary.bin").read_bytes(), b"\xde\xad\xbe\xef")

    def test_rendered_file_empty_bytes(self) -> None:
        """Empty bytes payload is preserved as zero-length file."""

        def render(spec, rng, cve_record=None):
            return {"public/empty.bin": b""}

        fam = self._make_family("probe_empty_bytes", render)
        families.register(fam)
        spec = default_spec(seed="bin-seed-4", title="Empty", difficulty="medium", family=fam.name)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )
            self.assertEqual((out / "public/empty.bin").read_bytes(), b"")

    def test_rendered_file_non_utf8_sequences(self) -> None:
        """Arbitrary byte sequences including invalid UTF-8 are preserved."""

        def render(spec, rng, cve_record=None):
            # Valid UTF-8, invalid UTF-8, lone surrogates encoded as bytes
            return {"public/evidence/corrupt.bin": b"\x80\x81\xc0\xc1\xff\xfe"}

        fam = self._make_family("probe_nonutf8", render)
        families.register(fam)
        spec = default_spec(
            seed="bin-seed-5", title="NonUTF8", difficulty="medium", family=fam.name
        )

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )
            data = (out / "public/evidence/corrupt.bin").read_bytes()
            self.assertEqual(data, b"\x80\x81\xc0\xc1\xff\xfe")

    def _make_family(self, name: str, render):
        return sdk.Family(
            name=name,
            category="web",
            modes=("red",),
            render=render,
            required_files=("challenge.yaml", "public/description.md"),
        )


class StrictTypeRejectionTests(unittest.TestCase):
    """Reviewer follow-up: bytearray/memoryview/int/None raise TypeError."""

    def setUp(self) -> None:
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)

    def test_from_value_rejects_non_str_bytes(self) -> None:
        from ctf_generator.families import RenderedFile

        for bad in (bytearray(b"x"), memoryview(b"x"), 42, None, [b"x"]):
            with self.assertRaises(TypeError):
                RenderedFile.from_value(bad)  # type: ignore[arg-type]

    def test_normalize_renderer_output_rejects_mutable_buffers(self) -> None:
        from ctf_generator.families import normalize_renderer_output

        for bad in (bytearray(b"x"), memoryview(b"x"), None):
            with self.assertRaises(TypeError):
                normalize_renderer_output({"public/x.bin": bad})  # type: ignore[dict-item]

    def test_write_build_rejects_bad_value_kinds(self) -> None:
        spec = default_spec(
            seed="bin-seed-9", title="Reject", difficulty="medium", family="tenant_export"
        )
        for bad in (bytearray(b"x"), memoryview(b"x"), 7, None):
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(TypeError):
                    build.write_build(
                        build_dir=Path(tmp) / "out",
                        files={"public/evidence/sample.bin": bad},  # type: ignore[dict-item]
                        spec=spec,
                    )

    def _make_family(self, name: str, render):
        return sdk.Family(
            name=name,
            category="web",
            modes=("red",),
            render=render,
            required_files=("challenge.yaml", "public/description.md"),
        )


class BinaryFlagTokenLeakTests(unittest.TestCase):
    """Reviewer follow-up: flag token embedded inside binary public bytes is caught."""

    FLAG = "ctf{binary_token_leak}"

    def setUp(self) -> None:
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)

    def test_flag_token_inside_binary_public_is_detected(self) -> None:
        payload = b"\x00\x01HEADER" + self.FLAG.encode("utf-8") + b"\xff\xfe"

        def render(spec, rng, cve_record=None):
            return {
                "public/evidence/token.bin": payload,
                "private/answer.txt": f"flag: {self.FLAG}\n",
            }

        fam = sdk.Family(
            name="probe_binary_token_leak",
            category="web",
            modes=("red",),
            render=render,
            required_files=("challenge.yaml", "public/evidence/token.bin"),
        )
        families.register(fam)
        spec = default_spec(
            seed="bin-seed-10", title="TokenLeak", difficulty="medium", family=fam.name
        )
        findings = lint.lint_family(fam, sample_seed=spec.seed)
        codes = {getattr(f, "code", str(f)) for f in findings}
        self.assertTrue(
            any("PRIVATE" in str(c).upper() or "LEAK" in str(c).upper() for c in codes),
            f"expected a private-leak finding, got: {codes}",
        )

    def _make_family(self, name: str, render):
        return sdk.Family(
            name=name,
            category="web",
            modes=("red",),
            render=render,
            required_files=("challenge.yaml", "public/description.md"),
        )


class ManifestBinaryIntegrityTests(unittest.TestCase):
    """Task A2: Manifests hash real bytes (not re-encoded text)."""

    def setUp(self) -> None:
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)

    def test_private_manifest_hashes_binary_bytes(self) -> None:
        """Private manifest SHA-256 matches exact on-disk binary bytes."""

        def render(spec, rng, cve_record=None):
            return {
                "public/description.md": "public\n",
                "private/secret.bin": b"\x00\x01\x02\xff\xfe\xfd",
            }

        fam = self._make_family("probe_manifest_bin", render)
        families.register(fam)
        spec = default_spec(
            seed="man-seed-1", title="Manifest", difficulty="medium", family=fam.name
        )

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )
            manifest = json.loads((out / "private/manifest.json").read_text())
            file_entry = manifest["files"]["private/secret.bin"]
            expected_sha = hashlib.sha256(b"\x00\x01\x02\xff\xfe\xfd").hexdigest()
            self.assertEqual(file_entry["sha256"], expected_sha)
            self.assertEqual(file_entry["size"], 6)

    def test_public_manifest_hashes_binary_bytes(self) -> None:
        """Public manifest SHA-256 matches exact on-disk binary bytes."""

        def render(spec, rng, cve_record=None):
            return {
                "public/description.md": "public\n",
                "public/evidence/sample.bin": b"\xaa\xbb\xcc\xdd",
            }

        fam = self._make_family("probe_pub_manifest_bin", render)
        families.register(fam)
        spec = default_spec(seed="man-seed-2", title="PubMan", difficulty="medium", family=fam.name)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )
            manifest = json.loads((out / "public/manifest.json").read_text())
            file_entry = manifest["files"]["public/evidence/sample.bin"]
            expected_sha = hashlib.sha256(b"\xaa\xbb\xcc\xdd").hexdigest()
            self.assertEqual(file_entry["sha256"], expected_sha)
            self.assertEqual(file_entry["size"], 4)

    def test_manifest_size_is_byte_count_not_char_count(self) -> None:
        """Manifest size field is byte count, not character count."""

        def render(spec, rng, cve_record=None):
            # 4 chars but 6 bytes in UTF-8
            return {"public/description.md": "caf\u00e9\n"}

        fam = self._make_family("probe_size_bytes", render)
        families.register(fam)
        spec = default_spec(seed="man-seed-3", title="Size", difficulty="medium", family=fam.name)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            generator.create_challenge(
                output_dir=out,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )
            manifest = json.loads((out / "private/manifest.json").read_text())
            # "café\n" = 5 chars = 6 bytes in UTF-8
            self.assertEqual(manifest["files"]["public/description.md"]["size"], 6)

    def _make_family(self, name: str, render):
        return sdk.Family(
            name=name,
            category="web",
            modes=("red",),
            render=render,
            required_files=("challenge.yaml", "public/description.md"),
        )


class DeterministicRebuildTests(unittest.TestCase):
    """Task A2/A3: Same seed yields byte-identical builds including binary files."""

    def setUp(self) -> None:
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)

    def test_same_seed_produces_byte_identical_binary_files(self) -> None:
        """Two builds with same seed produce byte-identical binary outputs."""

        def render(spec, rng, cve_record=None):
            # Deterministic but binary
            token = rng.getrandbits(32).to_bytes(4, "big")
            return {
                "public/description.md": f"# {spec.title}\n",
                "public/evidence/artifact.bin": b"PREFIX_" + token + b"_SUFFIX",
                "private/solution.md": f"answer {token.hex()}\n",
            }

        fam = self._make_family("probe_deterministic_bin", render)
        families.register(fam)
        seed = "deterministic-seed-123"

        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out1 = Path(tmp1) / "chal"
            out2 = Path(tmp2) / "chal"
            spec = default_spec(seed=seed, title="Det", difficulty="medium", family=fam.name)

            generator.create_challenge(
                output_dir=out1,
                seed=seed,
                title="Det",
                difficulty="medium",
                family=fam.name,
                spec=spec,
            )
            generator.create_challenge(
                output_dir=out2,
                seed=seed,
                title="Det",
                difficulty="medium",
                family=fam.name,
                spec=spec,
            )

            # Every file must be byte-identical
            for path in out1.rglob("*"):
                if path.is_file():
                    rel = path.relative_to(out1)
                    other = out2 / rel
                    self.assertTrue(other.exists(), f"missing in rebuild: {rel}")
                    self.assertEqual(
                        path.read_bytes(), other.read_bytes(), f"byte mismatch in {rel}"
                    )

    def test_different_seeds_produce_different_binary_files(self) -> None:
        """Different seeds produce different binary outputs."""

        def render(spec, rng, cve_record=None):
            token = rng.getrandbits(32).to_bytes(4, "big")
            return {
                "public/description.md": f"# {spec.title}\n",
                "public/evidence/artifact.bin": b"PREFIX_" + token + b"_SUFFIX",
            }

        fam = self._make_family("probe_different_seeds", render)
        families.register(fam)

        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out1 = Path(tmp1) / "chal"
            out2 = Path(tmp2) / "chal"
            spec1 = default_spec(seed="seed-a", title="A", difficulty="medium", family=fam.name)
            spec2 = default_spec(seed="seed-b", title="B", difficulty="medium", family=fam.name)

            generator.create_challenge(
                output_dir=out1,
                seed="seed-a",
                title="A",
                difficulty="medium",
                family=fam.name,
                spec=spec1,
            )
            generator.create_challenge(
                output_dir=out2,
                seed="seed-b",
                title="B",
                difficulty="medium",
                family=fam.name,
                spec=spec2,
            )

            bin1 = (out1 / "public/evidence/artifact.bin").read_bytes()
            bin2 = (out2 / "public/evidence/artifact.bin").read_bytes()
            self.assertNotEqual(bin1, bin2)

    def test_text_only_families_unchanged_byte_identical(self) -> None:
        """Existing text-only families remain byte-identical across rebuilds."""
        # Use a real built-in family
        fam = families.get("web_business_logic_tenant_export")
        seed = "text-family-seed"

        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out1 = Path(tmp1) / "chal"
            out2 = Path(tmp2) / "chal"
            spec = default_spec(seed=seed, title="Text", difficulty="medium", family=fam.name)

            generator.create_challenge(
                output_dir=out1,
                seed=seed,
                title="Text",
                difficulty="medium",
                family=fam.name,
                spec=spec,
            )
            generator.create_challenge(
                output_dir=out2,
                seed=seed,
                title="Text",
                difficulty="medium",
                family=fam.name,
                spec=spec,
            )

            for path in out1.rglob("*"):
                if path.is_file():
                    rel = path.relative_to(out1)
                    other = out2 / rel
                    self.assertTrue(other.exists(), f"missing in rebuild: {rel}")
                    self.assertEqual(
                        path.read_bytes(), other.read_bytes(), f"text family byte mismatch in {rel}"
                    )

    def _make_family(self, name: str, render):
        return sdk.Family(
            name=name,
            category="web",
            modes=("red",),
            render=render,
            required_files=("challenge.yaml", "public/description.md"),
        )


class PrivateLeakDetectionTests(unittest.TestCase):
    """Task A3: Private leak detection works with binary content."""

    def setUp(self) -> None:
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)

    def test_byte_identical_private_public_binary_detected(self) -> None:
        """Identical binary content in private/ and public/ is flagged."""

        def render(spec, rng, cve_record=None):
            shared = b"\xde\xad\xbe\xef" * 100
            return {
                "private/answer.bin": shared,
                "public/leak.bin": shared,
            }

        fam = self._make_family("probe_leak_binary", render)
        issues = lint.lint_family(fam, sample_seed="leak-seed")
        codes = {i.code for i in issues if i.severity == "error"}
        self.assertIn("PRIVATE_CONTENT_IN_PUBLIC", codes)

    def test_flag_token_in_binary_private_leaks_to_text_public(self) -> None:
        """Flag token in binary private file detected when leaked to text public."""

        def render(spec, rng, cve_record=None):
            flag = b"ctf{binary_leak_123456}"
            return {
                "private/variant.json": json.dumps({"flag": flag.decode("utf-8")}),
                "public/description.md": f"hint: {flag.decode('utf-8')}\n",
            }

        fam = self._make_family("probe_flag_leak_bin2text", render)
        issues = lint.lint_family(fam, sample_seed="leak-seed-2")
        codes = {i.code for i in issues if i.severity == "error"}
        self.assertIn("PRIVATE_CONTENT_IN_PUBLIC", codes)

    def test_binary_flag_token_not_in_public_binary(self) -> None:
        """Flag token in binary private file not present in public binary."""

        def render(spec, rng, cve_record=None):
            flag = b"ctf{secret_flag_abcdef}"
            return {
                "private/variant.json": json.dumps({"flag": flag.decode("utf-8")}),
                "public/evidence/data.bin": b"some other binary data without flag",
            }

        fam = self._make_family("probe_flag_safe_bin", render)
        issues = lint.lint_family(fam, sample_seed="leak-seed-3")
        codes = {i.code for i in issues if i.severity == "error"}
        self.assertNotIn("PRIVATE_CONTENT_IN_PUBLIC", codes)

    def test_lint_private_leak_uses_real_rendered_bytes(self) -> None:
        """Lint renders through same path as build, so binary bytes are compared."""

        def render(spec, rng, cve_record=None):
            # This would pass text comparison but fail byte comparison
            # if the normalizer did something different
            return {
                "private/secret.bin": b"\x00\x01\x02",
                "public/leak.bin": b"\x00\x01\x02",
            }

        fam = self._make_family("probe_lint_bytes", render)
        issues = lint.lint_family(fam, sample_seed="lint-seed")
        codes = {i.code for i in issues if i.severity == "error"}
        self.assertIn("PRIVATE_CONTENT_IN_PUBLIC", codes)

    def _make_family(self, name: str, render):
        return sdk.Family(
            name=name,
            category="web",
            modes=("red",),
            render=render,
            required_files=("challenge.yaml", "public/description.md"),
        )


class FileLimitTests(unittest.TestCase):
    """Task A3: File count and byte limits enforced with binary files."""

    def setUp(self) -> None:
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)

    def test_file_count_limit_includes_binary_files(self) -> None:
        """File count limit counts binary files same as text files."""

        def render(spec, rng, cve_record=None):
            files = {f"public/f{i}.bin": b"x" for i in range(10)}
            files["public/description.md"] = b"desc\n"
            return files

        fam = self._make_family("probe_filecount", render)
        families.register(fam)
        spec = default_spec(seed="limit-seed", title="Limit", difficulty="medium", family=fam.name)

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            with mock.patch.object(build, "MAX_FILE_COUNT", 5):
                with self.assertRaises(build.BuildLimitError):
                    generator.create_challenge(
                        output_dir=out,
                        seed=spec.seed,
                        title=spec.title,
                        difficulty=spec.difficulty,
                        family=spec.family,
                        spec=spec,
                    )

    def test_total_size_limit_counts_binary_bytes(self) -> None:
        """Total byte limit counts actual binary bytes."""

        def render(spec, rng, cve_record=None):
            return {
                "public/description.md": b"x",
                "public/big.bin": b"y" * 10000,
            }

        fam = self._make_family("probe_size_limit", render)
        families.register(fam)
        spec = default_spec(
            seed="limit-seed-2", title="SizeLim", difficulty="medium", family=fam.name
        )

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            with mock.patch.object(build, "MAX_TOTAL_BYTES", 1000):
                with self.assertRaises(build.BuildLimitError):
                    generator.create_challenge(
                        output_dir=out,
                        seed=spec.seed,
                        title=spec.title,
                        difficulty=spec.difficulty,
                        family=spec.family,
                        spec=spec,
                    )

    def _make_family(self, name: str, render):
        return sdk.Family(
            name=name,
            category="web",
            modes=("red",),
            render=render,
            required_files=("challenge.yaml", "public/description.md"),
        )


class TextFamilyCompatibilityTests(unittest.TestCase):
    """Task A3: Existing text-only families unchanged and byte-identical."""

    def test_all_builtins_still_generate_and_validate(self) -> None:
        """All 8 built-in families generate and validate cleanly."""
        for name in families.family_names():
            with self.subTest(family=name):
                families.get(name)  # existence + retrieval check
                spec = default_spec(
                    seed=f"compat-{name}", title="Compat", difficulty="medium", family=name
                )
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / "chal"
                    generator.create_challenge(
                        output_dir=out,
                        seed=spec.seed,
                        title=spec.title,
                        difficulty=spec.difficulty,
                        family=spec.family,
                        spec=spec,
                    )
                    # validator.validate_challenge accepts it
                    from ctf_generator import validator

                    report = validator.validate_challenge(out)
                    self.assertEqual(
                        report.errors, [], f"{name} validation failed: {report.errors}"
                    )

    def test_builtin_family_outputs_byte_identical_across_runs(self) -> None:
        """Each built-in family produces byte-identical output for same seed."""
        for name in families.family_names():
            with self.subTest(family=name):
                families.get(name)  # existence + retrieval check
                seed = f"compat-seed-{name}"
                spec = default_spec(seed=seed, title="Compat", difficulty="medium", family=name)

                with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
                    out1 = Path(tmp1) / "chal"
                    out2 = Path(tmp2) / "chal"
                    generator.create_challenge(
                        output_dir=out1,
                        seed=seed,
                        title="Compat",
                        difficulty="medium",
                        family=name,
                        spec=spec,
                    )
                    generator.create_challenge(
                        output_dir=out2,
                        seed=seed,
                        title="Compat",
                        difficulty="medium",
                        family=name,
                        spec=spec,
                    )

                    for path in out1.rglob("*"):
                        if path.is_file():
                            rel = path.relative_to(out1)
                            other = out2 / rel
                            self.assertTrue(other.exists(), f"{name}: missing {rel} in rebuild")
                            self.assertEqual(
                                path.read_bytes(),
                                other.read_bytes(),
                                f"{name}: byte mismatch in {rel}",
                            )

    def test_sdk_lint_passes_for_all_builtins(self) -> None:
        """All built-in families pass sdk.lint (no new errors)."""
        for name in families.family_names():
            with self.subTest(family=name):
                fam = families.get(name)
                issues = lint.lint_family(fam)
                errors = [i for i in issues if i.severity == "error"]
                self.assertEqual(errors, [], f"{name} lint errors: {[str(e) for e in errors]}")

    def test_testing_facade_works_for_builtins(self) -> None:
        """ctf_generator.testing helpers work for all builtins."""
        from ctf_generator import testing

        for name in families.family_names():
            with self.subTest(family=name):
                fam = families.get(name)
                testing.assert_family_ok(fam)
                testing.assert_deterministic(fam)
                testing.assert_no_private_leak(fam)
                with tempfile.TemporaryDirectory() as tmp:
                    out = testing.build_family_in(fam, Path(tmp) / "chal", seed=f"testing-{name}")
                    self.assertTrue((out / "challenge.yaml").is_file())
                testing.assert_rebuild_is_byte_identical(fam, seed=f"testing-rebuild-{name}")


class BuildHardeningBinaryTests(unittest.TestCase):
    """Task A2: build.py handles binary content correctly."""

    def test_write_build_writes_bytes_directly_no_double_encode(self) -> None:
        """build.write_build writes binary content without .encode() on bytes."""
        # This tests the internal write_build directly with binary content
        meta = build.BuildMeta(family="test", seed="s1", spec_sha256="deadbeef")
        files = {
            "challenge.yaml": "title: x\n",
            "public/binary.bin": b"\x00\x01\x02\xff\xfe\xfd",
        }

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            build.write_build(out, files, meta=meta)
            data = (out / "public/binary.bin").read_bytes()
            self.assertEqual(data, b"\x00\x01\x02\xff\xfe\xfd")

    def test_write_build_manifest_hashes_binary_content(self) -> None:
        """Manifest hashes binary content bytes, not text representation."""
        meta = build.BuildMeta(family="test", seed="s1", spec_sha256="deadbeef")
        files = {
            "challenge.yaml": "title: x\n",
            "public/data.bin": b"\xde\xad\xbe\xef",
        }

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            build.write_build(out, files, meta=meta)
            manifest = json.loads((out / "private/manifest.json").read_text())
            entry = manifest["files"]["public/data.bin"]
            self.assertEqual(entry["sha256"], hashlib.sha256(b"\xde\xad\xbe\xef").hexdigest())
            self.assertEqual(entry["size"], 4)

    def test_write_build_atomic_publish_preserves_binary(self) -> None:
        """Atomic publish (os.replace) preserves binary content."""
        meta = build.BuildMeta(family="test", seed="s1", spec_sha256="deadbeef")
        files_v1 = {"challenge.yaml": "v1\n", "public/data.bin": b"V1_BIN"}
        files_v2 = {"challenge.yaml": "v2\n", "public/data.bin": b"V2_BIN"}

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            build.write_build(out, files_v1, meta=meta)
            # Overwrite with force
            build.write_build(out, files_v2, meta=meta, force=True)
            data = (out / "public/data.bin").read_bytes()
            self.assertEqual(data, b"V2_BIN")

    def test_write_build_failure_keeps_original_binary(self) -> None:
        """Failed build keeps original binary build intact."""
        meta = build.BuildMeta(family="test", seed="s1", spec_sha256="deadbeef")
        files_good = {"challenge.yaml": "good\n", "public/data.bin": b"GOOD_BIN"}
        files_bad = {"challenge.yaml": "bad\n", "public/data.bin": b"BAD_BIN"}

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            build.write_build(out, files_good, meta=meta)
            good_hash = (out / "public/data.bin").read_bytes()

            # Force a failure during manifest generation
            with mock.patch.object(build, "_build_manifests", side_effect=RuntimeError("boom")):
                with self.assertRaises(RuntimeError):
                    build.write_build(out, files_bad, meta=meta, force=True)

            # Original preserved
            self.assertEqual((out / "public/data.bin").read_bytes(), good_hash)


class BinaryRendererModuleTests(unittest.TestCase):
    """Task A3: External renderer modules can return bytes."""

    def test_external_module_rendering_binary_works(self) -> None:
        """A renderer module returning binary bytes adapts and builds."""

        # Use a proper class with the required attributes instead of ModuleType
        class ExternalBinaryModule:
            FAMILY_NAME = "external_binary"
            CATEGORY = "web"
            MODES = ("red",)
            DIFFICULTIES = ("easy", "medium", "hard")
            CVE_DRIVEN = False
            LLM_BRIEF = "binary test"
            COMPOSE_MARKERS = ()
            SCORING_HINTS = {}
            REQUIRED_FILES = ("challenge.yaml", "public/description.md", "public/data.bin")

            @staticmethod
            def render(spec, rng, cve_record=None):
                # Include a concrete flag in variant.json so the global leak test passes
                flag = f"ctf{{extbin_{rng.getrandbits(24):06x}}}"
                return {
                    "public/description.md": f"# {spec.title}\n",
                    "public/data.bin": rng.randbytes(32),
                    "private/variant.json": f'{{"flag": "{flag}"}}',
                }

        # Adapter should work
        from ctf_generator.sdk.adapter import family_from_module

        fam = family_from_module(ExternalBinaryModule)
        self.assertEqual(fam.name, "external_binary")

        # Lint should pass
        lint.assert_family_ok(fam)

        # Register the family so generator can find it (temporarily)
        families.register(fam)
        try:
            # Generation should work
            spec = default_spec(
                seed="ext-bin-seed", title="ExtBin", difficulty="medium", family=fam.name
            )
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "chal"
                generator.create_challenge(
                    output_dir=out,
                    seed=spec.seed,
                    title=spec.title,
                    difficulty=spec.difficulty,
                    family=spec.family,
                    spec=spec,
                )
                self.assertTrue((out / "public/data.bin").is_file())
                self.assertEqual(len((out / "public/data.bin").read_bytes()), 32)
        finally:
            families._REGISTRY.pop("external_binary", None)

    def test_sdk_testing_helpers_work_with_binary_family(self) -> None:
        """ctf_generator.testing facade works with binary-returning family."""
        from ctf_generator import testing

        def render(spec, rng, cve_record=None):
            # Include a concrete flag in variant.json so the global leak test passes
            flag = f"ctf{{testbin_{rng.getrandbits(24):06x}}}"
            return {
                "public/description.md": f"# {spec.title}\n",
                "public/evidence.bin": b"\x00\x01\x02\x03",
                "private/solution.md": "answer\n",
                "private/variant.json": f'{{"flag": "{flag}"}}',
            }

        fam = sdk.Family(
            name="probe_testing_bin",
            category="web",
            modes=("red",),
            render=render,
            required_files=(
                "challenge.yaml",
                "public/description.md",
                "private/solution.md",
                "private/variant.json",
            ),
        )

        testing.assert_family_ok(fam)
        testing.assert_deterministic(fam)
        testing.assert_no_private_leak(fam)
        with tempfile.TemporaryDirectory() as tmp:
            out = testing.build_family_in(fam, Path(tmp) / "chal", seed="test-bin")
            self.assertTrue((out / "public/evidence.bin").is_file())
        testing.assert_rebuild_is_byte_identical(fam, seed="test-bin-rebuild")

        # Clean up test family from registry
        families._REGISTRY.pop("probe_testing_bin", None)


if __name__ == "__main__":
    unittest.main()
