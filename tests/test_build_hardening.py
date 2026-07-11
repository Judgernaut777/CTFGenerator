"""Adversarial tests for the Milestone 3 build-hardening layer (``build.py``).

Covers every attack/edge case the productization plan enumerates: traversal,
absolute paths, symlink escape, dangerous force targets, existing unmarked
directories, duplicate paths, oversized output, excessive file counts,
interrupted builds, partial publishes, and Unicode-confusable paths -- plus the
manifest guarantees.
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from ctf_generator import build
from ctf_generator.build import (
    BuildLimitError,
    BuildMeta,
    DangerousOutputRootError,
    DuplicatePathError,
    PathValidationError,
    UnsafeDeletionError,
    validate_relative_path,
    write_build,
)

_META = BuildMeta(family="crypto_token_forgery", seed="s1", spec_sha256="deadbeef")


def _files() -> dict[str, str]:
    return {
        "challenge.yaml": "title: x\n",
        "public/README.md": "hello\n",
        "private/solver.py": "print('solve')\n",
    }


class PathValidationTests(unittest.TestCase):
    def test_rejects_parent_traversal(self) -> None:
        for bad in ("../etc/passwd", "public/../../x", "a/../../b"):
            with self.assertRaises(PathValidationError):
                validate_relative_path(bad)

    def test_rejects_absolute(self) -> None:
        for bad in ("/etc/passwd", "/tmp/x"):
            with self.assertRaises(PathValidationError):
                validate_relative_path(bad)

    def test_rejects_backslash_and_nul(self) -> None:
        with self.assertRaises(PathValidationError):
            validate_relative_path("a\\b")
        with self.assertRaises(PathValidationError):
            validate_relative_path("a\x00b")

    def test_rejects_control_and_confusable(self) -> None:
        with self.assertRaises(PathValidationError):
            validate_relative_path("a\x1fb")  # control char
        with self.assertRaises(PathValidationError):
            validate_relative_path("public/‮evil.py")  # RTL override
        with self.assertRaises(PathValidationError):
            validate_relative_path("a﻿b")  # zero-width no-break

    def test_rejects_reserved_and_trailing(self) -> None:
        with self.assertRaises(PathValidationError):
            validate_relative_path("CON")
        with self.assertRaises(PathValidationError):
            validate_relative_path("dir/PRN.txt")
        with self.assertRaises(PathValidationError):
            validate_relative_path("name ")  # trailing space
        with self.assertRaises(PathValidationError):
            validate_relative_path("name.")  # trailing dot

    def test_rejects_overlong_component(self) -> None:
        with self.assertRaises(PathValidationError):
            validate_relative_path("a/" + "x" * 300)

    def test_normalizes_dot_segments(self) -> None:
        self.assertEqual(validate_relative_path("./public/./a.txt"), "public/a.txt")
        self.assertEqual(validate_relative_path("a/b.txt"), "a/b.txt")

    def test_rejects_reserved_build_paths(self) -> None:
        # A renderer must not forge the marker or shadow a manifest, even via a
        # case variant on a case-insensitive filesystem.
        for bad in (
            ".ctfgen-build",
            "public/manifest.json",
            "private/manifest.json",
            "Public/Manifest.json",
            ".CTFGEN-BUILD",
        ):
            with self.assertRaises(PathValidationError):
                validate_relative_path(bad)


class WriteBuildHappyPathTests(unittest.TestCase):
    def test_writes_marker_and_manifests(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            write_build(out, _files(), meta=_META)
            self.assertTrue((out / build.BUILD_MARKER_NAME).is_file())
            self.assertTrue(build.is_managed_build_dir(out))
            self.assertTrue((out / "public/manifest.json").is_file())
            self.assertTrue((out / "private/manifest.json").is_file())

            priv = json.loads((out / "private/manifest.json").read_text())
            self.assertEqual(priv["spec_sha256"], "deadbeef")
            self.assertIn("challenge.yaml", priv["files"])
            self.assertIn("private/solver.py", priv["files"])
            # every content file hashed
            self.assertEqual(
                priv["files"]["public/README.md"]["sha256"],
                __import__("hashlib").sha256(b"hello\n").hexdigest(),
            )

            pub = json.loads((out / "public/manifest.json").read_text())
            self.assertTrue(all(k.startswith("public/") for k in pub["files"]))
            self.assertNotIn("spec_sha256", pub)  # public manifest stays public
            # CRITICAL: the seed derives the flag, so it must never appear in a
            # player-facing artifact -- present in private, absent from public.
            self.assertNotIn("seed", pub)
            self.assertEqual(priv["seed"], "s1")

    def test_force_over_managed_dir(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            write_build(out, _files(), meta=_META)
            # regenerate with force -> allowed because it is a managed build
            write_build(out, _files(), meta=_META, force=True)
            self.assertTrue(build.is_managed_build_dir(out))

    def test_force_over_empty_existing_dir(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            out.mkdir()  # empty, unmarked (e.g. a pre-created tmp dir)
            write_build(out, _files(), meta=_META, force=True)
            self.assertTrue((out / "challenge.yaml").is_file())

    def test_no_force_over_existing_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            write_build(out, _files(), meta=_META)
            with self.assertRaises(FileExistsError):
                write_build(out, _files(), meta=_META, force=False)


class DeletionGuardTests(unittest.TestCase):
    def test_refuses_nonempty_unmarked_dir(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "victim"
            out.mkdir()
            (out / "important.txt").write_text("do not delete me")
            with self.assertRaises(UnsafeDeletionError):
                write_build(out, _files(), meta=_META, force=True)
            # the unmarked directory is untouched
            self.assertEqual((out / "important.txt").read_text(), "do not delete me")

    def test_refuses_symlink_output(self) -> None:
        with TemporaryDirectory() as tmp:
            real = Path(tmp) / "real"
            real.mkdir()
            (real / "keep.txt").write_text("keep")
            link = Path(tmp) / "chal"
            os.symlink(real, link)
            with self.assertRaises(UnsafeDeletionError):
                write_build(link, _files(), meta=_META, force=True)
            self.assertEqual((real / "keep.txt").read_text(), "keep")

    def test_rejects_dangerous_roots(self) -> None:
        with self.assertRaises(DangerousOutputRootError):
            write_build(Path("/"), _files(), meta=_META, force=True)
        with self.assertRaises(DangerousOutputRootError):
            write_build(Path("/etc"), _files(), meta=_META, force=True)
        with self.assertRaises(DangerousOutputRootError):
            write_build(Path.home(), _files(), meta=_META, force=True)
        with self.assertRaises(DangerousOutputRootError):
            write_build(Path.cwd(), _files(), meta=_META, force=True)


class SymlinkEscapeTests(unittest.TestCase):
    def test_assert_within_blocks_symlinked_component(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            # a symlinked subdirectory that points out of the build root
            os.symlink(outside, root / "sub")
            with self.assertRaises(PathValidationError):
                build._assert_within(os.path.realpath(root), root / "sub" / "file.txt")


class DuplicatePathTests(unittest.TestCase):
    def test_duplicate_after_normalization(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            files = {"a/b.txt": "1", "./a/b.txt": "2"}  # normalize to same path
            with self.assertRaises(DuplicatePathError):
                write_build(out, files, meta=_META)
            self.assertFalse(out.exists())  # nothing published

    def test_case_insensitive_collision_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            files = {"public/a.txt": "1", "public/A.txt": "2"}  # collide on case-insensitive FS
            with self.assertRaises(DuplicatePathError):
                write_build(out, files, meta=_META)
            self.assertFalse(out.exists())


class LimitTests(unittest.TestCase):
    def test_excessive_file_count(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            files = {f"f{i}.txt": "x" for i in range(20)}
            with mock.patch.object(build, "MAX_FILE_COUNT", 5):
                with self.assertRaises(BuildLimitError):
                    write_build(out, files, meta=_META)
            self.assertFalse(out.exists())

    def test_excessive_total_size(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            files = {"big.bin": "y" * 10_000}
            with mock.patch.object(build, "MAX_TOTAL_BYTES", 1000):
                with self.assertRaises(BuildLimitError):
                    write_build(out, files, meta=_META)
            self.assertFalse(out.exists())


class InterruptedBuildTests(unittest.TestCase):
    def test_failure_does_not_replace_valid_build_and_keeps_diagnostics(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            # a valid managed build exists first
            write_build(out, _files(), meta=_META)
            good_hash = json.loads((out / "private/manifest.json").read_text())["files"][
                "challenge.yaml"
            ]["sha256"]

            # a subsequent build fails mid-way (manifest generation blows up)
            with mock.patch.object(build, "_build_manifests", side_effect=RuntimeError("boom")):
                with self.assertRaises(RuntimeError):
                    write_build(out, {"challenge.yaml": "DIFFERENT\n"}, meta=_META, force=True)

            # original build is intact (atomic publish never happened)
            self.assertTrue(build.is_managed_build_dir(out))
            still = json.loads((out / "private/manifest.json").read_text())["files"][
                "challenge.yaml"
            ]["sha256"]
            self.assertEqual(still, good_hash)
            # failed partial build retained separately for diagnosis (unique name)
            self.assertTrue(any(Path(tmp).glob("chal.ctfgen-failed-*")))

    def test_diagnostics_never_clobbers_existing_dir(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            # an unrelated, pre-existing directory sharing the diagnostics stem
            victim = Path(tmp) / "chal.ctfgen-failed"
            victim.mkdir()
            (victim / "keep.txt").write_text("keep")
            with mock.patch.object(build, "_build_manifests", side_effect=RuntimeError("boom")):
                with self.assertRaises(RuntimeError):
                    write_build(out, _files(), meta=_META)
            # the pre-existing directory is untouched; diagnostics used a unique name
            self.assertEqual((victim / "keep.txt").read_text(), "keep")

    def test_restore_prior_build_when_publish_rename_fails(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            write_build(out, _files(), meta=_META)
            good_hash = json.loads((out / "private/manifest.json").read_text())["files"][
                "challenge.yaml"
            ]["sha256"]
            # Simulate the final atomic rename failing after the old build was
            # moved aside; the prior valid build must be restored.
            real_replace = os.replace

            def flaky_replace(src, dst):
                # Fail only the tmp->final publish rename, not the move-aside or
                # the restore, so we exercise the restore path.
                if "ctfgen-tmp" in Path(src).name and Path(dst) == out:
                    raise OSError("simulated rename failure")
                return real_replace(src, dst)

            with mock.patch("ctf_generator.build.os.replace", side_effect=flaky_replace):
                with self.assertRaises(OSError):
                    write_build(out, {"challenge.yaml": "DIFFERENT\n"}, meta=_META, force=True)
            self.assertTrue(build.is_managed_build_dir(out))
            restored = json.loads((out / "private/manifest.json").read_text())["files"][
                "challenge.yaml"
            ]["sha256"]
            self.assertEqual(restored, good_hash)

    def test_no_leftover_tmp_dirs_on_success(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "chal"
            write_build(out, _files(), meta=_META)
            leftovers = [p for p in Path(tmp).iterdir() if "ctfgen-tmp" in p.name]
            self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
