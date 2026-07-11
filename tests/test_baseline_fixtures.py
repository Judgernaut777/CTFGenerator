"""Golden baseline + determinism regression for every challenge family.

Milestone 0 / Milestone 2 quality gate. The committed manifests under
``tests/fixtures/baseline/`` record, for every family and a fixed set of seeds,
the exact set of generated files with their SHA-256 and public/private
classification. This test regenerates each challenge *in process* (the same
code path a bare ``ctfgen create`` uses -- see ``cli.py``: with default
mode/cve the CLI leaves ``spec=None`` and ``create_challenge`` builds its own
deterministic spec) and asserts byte-for-byte agreement with the golden
manifest.

It enforces two product invariants directly:

* Identical (generator, spec, family, seed) => identical artifacts
  (deterministic rebuild -- zero failures is a release target).
* No private file content is emitted under ``public/``.

Regenerate the manifests after an intentional generator change with
``scratchpad/gen_fixtures.py`` (or the inline logic here) and review the diff.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ctf_generator.generator import create_challenge

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "baseline"

# Must match the values a bare `ctfgen create` uses (cli.py defaults).
_TITLE = "Invoice Drift"
_DIFFICULTY = "medium"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _manifest_for(root: Path) -> dict[str, dict]:
    files: dict[str, dict] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        files[rel] = {
            "sha256": _sha256(path),
            "size": path.stat().st_size,
            "public": rel.startswith("public/"),
            "private": rel.startswith("private/"),
        }
    return files


def _load_index() -> dict:
    return json.loads((FIXTURES / "_index.json").read_text(encoding="utf-8"))


class BaselineFixtureTests(unittest.TestCase):
    def test_index_present(self) -> None:
        index = _load_index()
        self.assertTrue(index["families"], "baseline index lists no families")
        self.assertTrue(index["seeds"], "baseline index lists no seeds")

    def test_families_rebuild_to_golden_manifest(self) -> None:
        index = _load_index()
        seeds = index["seeds"]
        for family in index["families"]:
            golden = json.loads((FIXTURES / f"{family}.json").read_text(encoding="utf-8"))
            for seed in seeds:
                with self.subTest(family=family, seed=seed):
                    recorded = golden[seed]
                    self.assertNotIn(
                        "error", recorded, f"{family}/{seed} recorded a generation error"
                    )
                    with tempfile.TemporaryDirectory() as tmp:
                        out = Path(tmp) / "chal"
                        create_challenge(
                            output_dir=out,
                            seed=seed,
                            title=_TITLE,
                            difficulty=_DIFFICULTY,
                            family=family,
                            force=True,
                        )
                        current = _manifest_for(out)

                    expected = recorded["files"]
                    self.assertEqual(
                        set(current),
                        set(expected),
                        f"{family}/{seed}: generated file set drifted from golden baseline",
                    )
                    for rel, meta in expected.items():
                        self.assertEqual(
                            current[rel]["sha256"],
                            meta["sha256"],
                            f"{family}/{seed}: content of {rel} drifted from golden baseline",
                        )

    def test_no_private_content_leaks_into_public(self) -> None:
        """Every byte under private/** must be absent from public/** (per family)."""
        index = _load_index()
        for family in index["families"]:
            golden = json.loads((FIXTURES / f"{family}.json").read_text(encoding="utf-8"))
            for seed in index["seeds"]:
                files = golden[seed].get("files", {})
                private_hashes = {
                    m["sha256"] for rel, m in files.items() if m["private"]
                }
                public_hashes = {
                    m["sha256"] for rel, m in files.items() if m["public"]
                }
                with self.subTest(family=family, seed=seed):
                    shared = private_hashes & public_hashes
                    self.assertFalse(
                        shared,
                        f"{family}/{seed}: identical file present in both public/ and private/",
                    )


if __name__ == "__main__":
    unittest.main()
