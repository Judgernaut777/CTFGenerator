"""The ``ctfgen new-family`` scaffold command.

A scaffolded family must be a working starting point: it lints clean and
``generator.create_challenge`` succeeds on it unedited. Name/path safety and the
no-clobber rule are enforced with clean nonzero exits (never a traceback / never
a write outside DEST).
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path

from ctf_generator import families, generator, sdk
from ctf_generator.cli import main


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ScaffoldWritesThreeFilesTests(unittest.TestCase):
    def test_writes_the_three_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "probe_scaffold_family"
            code, out, _ = _run(
                ["new-family", "probe_scaffold_family", "--category", "web", "--dest", str(dest)]
            )
            self.assertEqual(code, 0)
            self.assertTrue((dest / "probe_scaffold_family.py").is_file())
            self.assertTrue((dest / "test_probe_scaffold_family.py").is_file())
            self.assertTrue((dest / "ENTRY_POINT.md").is_file())
            # The created paths are printed for the author.
            self.assertIn("probe_scaffold_family.py", out)


class ScaffoldIsLintCleanAndGeneratableTests(unittest.TestCase):
    def setUp(self) -> None:
        # This class registers scaffolded probe families to exercise
        # generator.create_challenge; snapshot/restore so they never leak into
        # other suites (e.g. the "exactly 8 built-ins" registry assertion).
        self._registry_snapshot = dict(families._REGISTRY)

    def tearDown(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._registry_snapshot)

    def test_scaffold_lints_clean_and_generates_unedited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "probe_gen_family"
            code, _, _ = _run(
                ["new-family", "probe_gen_family", "--category", "web", "--dest", str(dest)]
            )
            self.assertEqual(code, 0)

            module = _load_module(dest / "probe_gen_family.py", "probe_gen_family")
            # The scaffolded renderer must NOT import ctf_generator.families.
            self.assertNotIn("import ctf_generator.families", (dest / "probe_gen_family.py").read_text())

            fam = sdk.family_from_module(module)
            sdk.assert_family_ok(fam)  # lint-clean, unedited

            sdk.register(fam)
            out = Path(tmp) / "built"
            result = generator.create_challenge(
                output_dir=out,
                seed="scaffold-seed",
                title="Scaffold Probe",
                difficulty="medium",
                family=fam.name,
                force=True,
            )
            self.assertTrue((result / "challenge.yaml").is_file())

    def test_modes_flag_is_honored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "probe_modes_family"
            code, _, _ = _run(
                [
                    "new-family", "probe_modes_family", "--category", "network",
                    "--modes", "red,purple", "--dest", str(dest),
                ]
            )
            self.assertEqual(code, 0)
            module = _load_module(dest / "probe_modes_family.py", "probe_modes_family")
            self.assertEqual(tuple(module.MODES), ("red", "purple"))
            self.assertEqual(module.CATEGORY, "network")
            sdk.assert_family_ok(sdk.family_from_module(module))


class ScaffoldNameAndPathSafetyTests(unittest.TestCase):
    def test_bad_names_exit_nonzero_and_write_nothing(self) -> None:
        for bad in ("../evil", "foo/bar", "foo\\bar", "1foo", "foo.bar", "class"):
            with self.subTest(name=bad), tempfile.TemporaryDirectory() as tmp:
                dest = Path(tmp) / "out"
                code, _, err = _run(
                    ["new-family", bad, "--category", "web", "--dest", str(dest)]
                )
                self.assertNotEqual(code, 0)
                self.assertNotEqual(err.strip(), "")  # a clean message, not a traceback
                self.assertFalse(dest.exists(), f"{bad!r} wrote into DEST")
                # Nothing escaped the tmp root either.
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_dest_is_an_existing_file_is_a_clean_error(self) -> None:
        # --dest pointing at a regular file must be a clean nonzero error, NOT a
        # raw FileExistsError traceback from mkdir.
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "a_file"
            dest.write_text("i am a file\n", encoding="utf-8")
            code, _, err = _run(
                ["new-family", "okname", "--category", "web", "--dest", str(dest)]
            )
            self.assertNotEqual(code, 0)
            self.assertNotEqual(err.strip(), "")
            self.assertEqual(dest.read_text(encoding="utf-8"), "i am a file\n")

    def test_symlink_target_is_refused_no_out_of_dest_write(self) -> None:
        # A symlink planted in DEST named like a scaffold target must NOT be
        # followed (which would write outside DEST). A DANGLING symlink also
        # bypasses an exists()-only guard, so is_symlink must catch it.
        for dangling in (True, False):
            with self.subTest(dangling=dangling), \
                    tempfile.TemporaryDirectory() as tmp:
                outside = Path(tmp) / "OUTSIDE.py"
                if not dangling:
                    outside.write_text("original\n", encoding="utf-8")
                dest = Path(tmp) / "out"
                dest.mkdir()
                link = dest / "sym_family.py"
                link.symlink_to(outside)
                code, _, err = _run(
                    ["new-family", "sym_family", "--category", "web",
                     "--dest", str(dest), "--force"]
                )
                self.assertNotEqual(code, 0, "must refuse a symlink target")
                self.assertIn("symlink", err.lower())
                # The out-of-dest file was NOT written/overwritten through the link.
                if dangling:
                    self.assertFalse(outside.exists())
                else:
                    self.assertEqual(outside.read_text(encoding="utf-8"), "original\n")

    def test_scaffolded_test_module_runs_green(self) -> None:
        # Guard the emitted test template: a freshly scaffolded family's OWN test
        # file must actually pass (run it as an author would, via unittest).
        import subprocess
        import sys

        src = str(Path(__file__).resolve().parent.parent / "src")
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "probe_selftest_family"
            code, _, _ = _run(
                ["new-family", "probe_selftest_family", "--category", "web",
                 "--dest", str(dest)]
            )
            self.assertEqual(code, 0)
            proc = subprocess.run(  # noqa: S603 - fixed args, our own scaffold output
                [sys.executable, "-m", "unittest", "test_probe_selftest_family", "-v"],
                cwd=str(dest),
                env={"PYTHONPATH": os.pathsep.join([src, str(dest)]),
                     "PATH": os.environ.get("PATH", "")},
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("OK", proc.stderr)

    def test_bad_category_and_mode_exit_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            code, _, _ = _run(
                ["new-family", "okname", "--category", "we b", "--dest", str(dest)]
            )
            self.assertNotEqual(code, 0)
            self.assertFalse(dest.exists())

            code, _, _ = _run(
                ["new-family", "okname", "--category", "web", "--modes", "red,pink", "--dest", str(dest)]
            )
            self.assertNotEqual(code, 0)
            self.assertFalse(dest.exists())


class ScaffoldNoClobberTests(unittest.TestCase):
    def test_rerun_without_force_does_not_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "probe_clobber_family"
            code, _, _ = _run(
                ["new-family", "probe_clobber_family", "--category", "web", "--dest", str(dest)]
            )
            self.assertEqual(code, 0)
            module_path = dest / "probe_clobber_family.py"
            module_path.write_text("# edited by the author\n", encoding="utf-8")

            code, _, err = _run(
                ["new-family", "probe_clobber_family", "--category", "web", "--dest", str(dest)]
            )
            self.assertNotEqual(code, 0)
            self.assertIn("overwrite", err.lower())
            # The author's edit is intact.
            self.assertEqual(module_path.read_text(encoding="utf-8"), "# edited by the author\n")

    def test_force_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "probe_force_family"
            _run(["new-family", "probe_force_family", "--category", "web", "--dest", str(dest)])
            module_path = dest / "probe_force_family.py"
            module_path.write_text("# stale\n", encoding="utf-8")
            code, _, _ = _run(
                ["new-family", "probe_force_family", "--category", "web", "--dest", str(dest), "--force"]
            )
            self.assertEqual(code, 0)
            self.assertIn("FAMILY_NAME", module_path.read_text(encoding="utf-8"))


class ScaffoldDeterministicOutputTests(unittest.TestCase):
    def test_output_is_deterministic_for_a_given_name(self) -> None:
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            d1, d2 = Path(t1) / "probe_det_family", Path(t2) / "probe_det_family"
            _run(["new-family", "probe_det_family", "--category", "web", "--dest", str(d1)])
            _run(["new-family", "probe_det_family", "--category", "web", "--dest", str(d2)])
            for fname in ("probe_det_family.py", "test_probe_det_family.py", "ENTRY_POINT.md"):
                self.assertEqual(
                    (d1 / fname).read_text(encoding="utf-8"),
                    (d2 / fname).read_text(encoding="utf-8"),
                    f"{fname} differs across runs",
                )


if __name__ == "__main__":
    unittest.main()
