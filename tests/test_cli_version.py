from __future__ import annotations

import contextlib
import io
import unittest

import ctf_generator
from ctf_generator.cli import FAMILIES, main


class VersionFlagTests(unittest.TestCase):
    def test_version_prints_package_version_and_exits_zero(self) -> None:
        stdout = io.StringIO()
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(stdout):
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        output = stdout.getvalue()
        self.assertIn(ctf_generator.__version__, output)
        self.assertIn("ctfgen", output)

    def test_version_matches_single_source_of_truth(self) -> None:
        # Guards the dynamic-version wiring: the CLI must report exactly the
        # value defined in ctf_generator.__version__ (no hard-coded duplicate).
        stdout = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(stdout):
            main(["--version"])
        self.assertEqual(stdout.getvalue().strip(), f"ctfgen {ctf_generator.__version__}")


class BareInvocationTests(unittest.TestCase):
    def test_no_command_returns_two_and_writes_help_to_stderr(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main([])
        self.assertEqual(code, 2)
        self.assertIn("usage", stderr.getvalue().lower())


class ListFamiliesTests(unittest.TestCase):
    def test_list_families_prints_each_family_and_exits_zero(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["list-families"])
        self.assertEqual(code, 0)
        printed = stdout.getvalue().splitlines()
        self.assertEqual(printed, FAMILIES)


if __name__ == "__main__":
    unittest.main()
