"""Cross-family guard: a challenge's real flag must never appear in public/.

This is the family-agnostic sweep whose absence let the scada_ics family ship
its flag in ``public/evidence/register_write_log.jsonl`` for red mode (solvable
by ``grep`` with zero exploitation). It renders every registered family in
every mode and asserts the concrete, seed-derived flag token does not leak into
any file a player is handed under ``public/``.

Blue/purple modes legitimately hand the player an analysis artifact that
*contains* the flag (that is the defensive task), so this guard only covers
modes whose intended solve path is NOT "read a provided file" -- currently
every mode except a family's dedicated defensive (blue) mode. Purple bundles a
live-exploit path, so it is held to the same no-leak standard as red.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ctf_generator import families, generator
from ctf_generator.spec_generator import default_spec

# A concrete, seed-derived flag: ``ctf{...}`` ending in the hex suffix every
# family appends. Deliberately does NOT match placeholders like ``ctf{...}`` or
# ``ctf{FLAG}`` that legitimately appear in player-facing descriptions.
_CONCRETE_FLAG = re.compile(r"ctf\{[0-9a-z_]*[0-9a-f]{6}[0-9a-z_]*\}")

# Modes whose intended solve path is analysing a provided artifact; the flag is
# expected to be present in that artifact, so they are exempt from the sweep.
_ARTIFACT_MODES = {"blue"}


def _concrete_flags(root: Path) -> set[str]:
    flags: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        flags.update(_CONCRETE_FLAG.findall(text))
    return flags


class PublicFlagLeakTests(unittest.TestCase):
    def test_no_family_mode_leaks_its_flag_into_public(self) -> None:
        for name in families.family_names():
            family = families.get(name)
            for mode in family.modes:
                if mode in _ARTIFACT_MODES:
                    continue
                with self.subTest(family=name, mode=mode):
                    with tempfile.TemporaryDirectory() as tmp:
                        out = Path(tmp) / "chal"
                        spec = replace(
                            default_spec(
                                seed="leak-guard-seed",
                                title="Leak Guard",
                                difficulty="medium",
                                family=name,
                            ),
                            mode=mode,
                        )
                        generator.create_challenge(
                            output_dir=out,
                            seed="leak-guard-seed",
                            title="Leak Guard",
                            difficulty="medium",
                            family=name,
                            spec=spec,
                        )
                        real_flags = _concrete_flags(out)
                        self.assertTrue(
                            real_flags,
                            f"{name}/{mode}: no concrete flag found to check against",
                        )
                        public = out / "public"
                        if not public.exists():
                            continue
                        for path in public.rglob("*"):
                            if not path.is_file():
                                continue
                            try:
                                text = path.read_text(encoding="utf-8")
                            except (UnicodeDecodeError, OSError):
                                continue
                            leaked = sorted(f for f in real_flags if f in text)
                            self.assertEqual(
                                leaked,
                                [],
                                f"{name}/{mode}: flag(s) {leaked} leaked into "
                                f"public file {path.relative_to(out)}",
                            )


if __name__ == "__main__":
    unittest.main()
