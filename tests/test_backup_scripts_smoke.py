"""Host smoke tests for the backup/restore shell scripts (M17 slice 17a).

No Docker / PostgreSQL required: exercises the fail-loud guards and the
secret-free property of the scripts, and unit-tests the DSN parser in
``_lib.sh``. The full dump/restore round-trip is covered (Docker-gated) by
``test_restore_verify_integration``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS = os.path.join(_REPO_ROOT, "scripts")
_BACKUP = os.path.join(_SCRIPTS, "backup.sh")
_RESTORE = os.path.join(_SCRIPTS, "restore.sh")
_LIB = os.path.join(_SCRIPTS, "_lib.sh")
_SECRET = "SuperSecretPw123"  # a password that must never appear in output
_DSN = f"postgresql+psycopg://ctfgen:{_SECRET}@db.example.internal:6543/ctfgen_prod"

_HAVE_BASH = shutil.which("bash") is not None
_BASH_REASON = "bash not available"


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _code_lines(text: str) -> str:
    """Non-comment lines only (so prose in header comments does not trip a
    literal-substring check)."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _run(argv, env_extra=None):
    env = {**os.environ}
    if env_extra is not None:
        env.update(env_extra)
    return subprocess.run(
        argv, env=env, capture_output=True, text=True, timeout=60
    )


@unittest.skipUnless(_HAVE_BASH, _BASH_REASON)
class ScriptStructureTests(unittest.TestCase):
    def test_scripts_exist_and_are_executable(self) -> None:
        for path in (_BACKUP, _RESTORE, _LIB):
            self.assertTrue(os.path.exists(path), path)
        for path in (_BACKUP, _RESTORE):
            self.assertTrue(os.access(path, os.X_OK), f"not executable: {path}")

    def test_scripts_are_fail_loud_and_custom_format(self) -> None:
        backup = _read(_BACKUP)
        restore = _read(_RESTORE)
        for text in (backup, restore):
            self.assertIn("set -euo pipefail", text)
            self.assertTrue(text.startswith("#!"), "missing shebang")
        # The dump is a restorable custom-format archive.
        self.assertIn("--format=custom", backup)
        # Restore must NOT use --clean (would DROP objects in a live target).
        self.assertNotIn("--clean", _code_lines(restore))

    def test_scripts_never_print_the_dsn_or_password(self) -> None:
        # Static guarantee: no script echoes/prints the DSN env var or PGPASSWORD.
        for path in (_BACKUP, _RESTORE, _LIB):
            text = _read(path)
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if ("echo" in stripped or "printf" in stripped) and (
                    "CTFGEN_DATABASE_URL" in stripped
                    or "PGPASSWORD" in stripped
                    or "target_dsn" in stripped
                ):
                    self.fail(f"{path} may print a secret: {stripped}")

    def test_shellcheck_clean_if_available(self) -> None:
        if shutil.which("shellcheck") is None:
            self.skipTest("shellcheck not installed")
        result = _run(["shellcheck", "-x", _BACKUP, _RESTORE, _LIB])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(_HAVE_BASH, _BASH_REASON)
class DsnParserTests(unittest.TestCase):
    def _parse(self, dsn: str) -> dict:
        # Source _lib.sh and print the parsed PG* vars (the TEST prints them; the
        # scripts themselves never do).
        script = (
            f'. "{_LIB}"; dsn_parse "{dsn}"; '
            'printf "%s\\n%s\\n%s\\n%s\\n%s\\n" '
            '"$PGHOST" "$PGPORT" "$PGUSER" "$PGPASSWORD" "$PGDATABASE"'
        )
        result = _run(["bash", "-c", script])
        self.assertEqual(result.returncode, 0, result.stderr)
        host, port, user, password, db = result.stdout.splitlines()[:5]
        return {
            "host": host, "port": port, "user": user,
            "password": password, "database": db,
        }

    def test_parses_driver_qualified_dsn(self) -> None:
        parsed = self._parse(_DSN)
        self.assertEqual(parsed["host"], "db.example.internal")
        self.assertEqual(parsed["port"], "6543")
        self.assertEqual(parsed["user"], "ctfgen")
        self.assertEqual(parsed["password"], _SECRET)
        self.assertEqual(parsed["database"], "ctfgen_prod")

    def test_defaults_port_when_absent(self) -> None:
        parsed = self._parse("postgresql://u:p@localhost/mydb")
        self.assertEqual(parsed["port"], "5432")
        self.assertEqual(parsed["database"], "mydb")

    def test_strips_query_string(self) -> None:
        parsed = self._parse("postgresql://u:p@h:5432/mydb?sslmode=require")
        self.assertEqual(parsed["database"], "mydb")


@unittest.skipUnless(_HAVE_BASH, _BASH_REASON)
class BackupGuardTests(unittest.TestCase):
    def test_backup_requires_dest_arg(self) -> None:
        result = _run(["bash", _BACKUP], env_extra={"CTFGEN_DATABASE_URL": _DSN})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage", (result.stdout + result.stderr).lower())

    def test_backup_requires_database_url(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "CTFGEN_DATABASE_URL"}
        env["CTFGEN_ARTIFACT_ROOT"] = tempfile.gettempdir()
        result = subprocess.run(
            ["bash", _BACKUP, tempfile.mkdtemp()],
            env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CTFGEN_DATABASE_URL", result.stdout + result.stderr)

    def test_backup_failure_path_never_leaks_password(self) -> None:
        # A secret-bearing DSN is set; force the dump tool to fail immediately.
        # The password must not appear anywhere in the output.
        dest = tempfile.mkdtemp()
        artifacts = tempfile.mkdtemp()
        try:
            result = _run(
                ["bash", _BACKUP, os.path.join(dest, "bk")],
                env_extra={
                    "CTFGEN_DATABASE_URL": _DSN,
                    "CTFGEN_ARTIFACT_ROOT": artifacts,
                    "CTFGEN_PG_DUMP": "/bin/false",
                    "CTFGEN_PSQL": "/bin/false",
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(_SECRET, result.stdout + result.stderr)
        finally:
            shutil.rmtree(dest, ignore_errors=True)
            shutil.rmtree(artifacts, ignore_errors=True)


@unittest.skipUnless(_HAVE_BASH, _BASH_REASON)
class RestoreGuardTests(unittest.TestCase):
    def test_restore_requires_two_positionals(self) -> None:
        result = _run(["bash", _RESTORE, "only-one"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage", (result.stdout + result.stderr).lower())

    def test_restore_fails_on_missing_dump(self) -> None:
        empty = tempfile.mkdtemp()
        try:
            result = _run(
                ["bash", _RESTORE, empty, _DSN],
                env_extra={"CTFGEN_ARTIFACT_ROOT": tempfile.gettempdir()},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("db.dump", result.stdout + result.stderr)
            self.assertNotIn(_SECRET, result.stdout + result.stderr)
        finally:
            shutil.rmtree(empty, ignore_errors=True)

    def test_restore_requires_artifact_root(self) -> None:
        src = tempfile.mkdtemp()
        for name in ("db.dump", "artifacts.tar"):
            with open(os.path.join(src, name), "wb"):
                pass
        env = {k: v for k, v in os.environ.items() if k != "CTFGEN_ARTIFACT_ROOT"}
        try:
            result = subprocess.run(
                ["bash", _RESTORE, src, _DSN],
                env=env, capture_output=True, text=True, timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("CTFGEN_ARTIFACT_ROOT", result.stdout + result.stderr)
            self.assertNotIn(_SECRET, result.stdout + result.stderr)
        finally:
            shutil.rmtree(src, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
