"""Guard: the readiness probe's code-declared migration head cannot drift.

``CODE_MIGRATION_HEAD`` (consumed by ``/system/ready``) must equal the actual
Alembic ScriptDirectory head, so a new migration that forgets to update the
constant is caught at CI time rather than making readiness falsely report
'behind'. Needs only ``alembic`` (no DB); skips cleanly when it is absent.
"""

from __future__ import annotations

import os
import unittest

try:
    from alembic.config import Config as AlembicConfig
    from alembic.script import ScriptDirectory

    from ctf_generator.infrastructure.database.migrations import CODE_MIGRATION_HEAD

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipUnless(_IMPORT_ERROR is None, f"alembic not importable ({_IMPORT_ERROR})")
class MigrationHeadConstantTests(unittest.TestCase):
    def test_constant_matches_script_directory_head(self) -> None:
        cfg = AlembicConfig(os.path.join(_REPO_ROOT, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(_REPO_ROOT, "alembic"))
        heads = ScriptDirectory.from_config(cfg).get_heads()
        self.assertEqual(len(heads), 1, f"expected a single head, got {heads!r}")
        self.assertEqual(CODE_MIGRATION_HEAD, heads[0])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
