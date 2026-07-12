"""Host unit tests for the local-filesystem artifact store (M14 slice 14c-1).

Pure stdlib -- no database, no Docker. Exercises the ArtifactStore contract
(round-trip / list), immutability + content-addressed idempotency, path safety
(a hostile key never writes or reads outside root), and atomic-put cleanliness.

    PYTHONPATH=src:tests python3 -m unittest test_artifact_local_store_unit
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_generator.infrastructure.artifacts.local_store import (
    ArtifactStoreError,
    InMemoryArtifactStore,
    LocalFilesystemArtifactStore,
)


class LocalFilesystemArtifactStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="artifact-store-test-")
        self.root = Path(self._tmp.name) / "store"
        self.store = LocalFilesystemArtifactStore(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_put_get_exists_round_trip(self) -> None:
        self.assertFalse(self.store.exists("builds/ab/one.tar"))
        self.assertIsNone(self.store.get("builds/ab/one.tar"))
        self.store.put("builds/ab/one.tar", b"payload-1")
        self.assertTrue(self.store.exists("builds/ab/one.tar"))
        self.assertEqual(self.store.get("builds/ab/one.tar"), b"payload-1")

    def test_list_prefix(self) -> None:
        self.store.put("builds/ab/one.tar", b"a")
        self.store.put("builds/cd/two.tar", b"b")
        self.store.put("other/three.txt", b"c")
        self.assertEqual(
            self.store.list("builds/"),
            ["builds/ab/one.tar", "builds/cd/two.tar"],
        )
        self.assertEqual(
            self.store.list(),
            ["builds/ab/one.tar", "builds/cd/two.tar", "other/three.txt"],
        )

    def test_immutable_same_bytes_is_noop(self) -> None:
        self.store.put("k/x.tar", b"same")
        # Re-putting identical bytes is a content-addressed no-op (no raise).
        self.store.put("k/x.tar", b"same")
        self.assertEqual(self.store.get("k/x.tar"), b"same")

    def test_immutable_different_bytes_raises_and_preserves_original(self) -> None:
        self.store.put("k/x.tar", b"original")
        with self.assertRaises(ArtifactStoreError):
            self.store.put("k/x.tar", b"tampered")
        # The original bytes are untouched.
        self.assertEqual(self.store.get("k/x.tar"), b"original")

    def test_non_bytes_payload_raises(self) -> None:
        with self.assertRaises(ArtifactStoreError):
            self.store.put("k/x.tar", "not-bytes")  # type: ignore[arg-type]

    def test_hostile_keys_raise_and_write_nothing_outside_root(self) -> None:
        outside = Path(self._tmp.name) / "escape.txt"
        hostile = [
            "/etc/passwd",  # absolute
            "../escape.txt",  # traversal
            "builds/../../escape.txt",  # traversal through a subdir
            "a/\x00b",  # NUL
            "a\\b",  # backslash
            "a/‮b.tar",  # bidi override
        ]
        for key in hostile:
            with self.subTest(key=key):
                with self.assertRaises(ArtifactStoreError):
                    self.store.put(key, b"evil")
                with self.assertRaises(ArtifactStoreError):
                    self.store.get(key)
                with self.assertRaises(ArtifactStoreError):
                    self.store.exists(key)
        self.assertFalse(outside.exists(), "a hostile key wrote outside the root")

    def test_symlinked_intermediate_dir_cannot_escape(self) -> None:
        # A pre-existing symlink under root pointing outside must not let a key
        # resolve outside root.
        outside_dir = Path(self._tmp.name) / "outside"
        outside_dir.mkdir()
        link = self.root / "link"
        link.symlink_to(outside_dir, target_is_directory=True)
        with self.assertRaises(ArtifactStoreError):
            self.store.put("link/evil.tar", b"evil")
        self.assertFalse((outside_dir / "evil.tar").exists())

    def test_put_is_atomic_leaves_no_temp_files(self) -> None:
        self.store.put("builds/ab/one.tar", b"payload")
        # A completed put leaves the final file and no leftover ".tmp-*" sibling.
        leftovers = [p.name for p in (self.root / "builds" / "ab").iterdir()]
        self.assertEqual(leftovers, ["one.tar"])
        self.assertFalse(any(name.startswith(".tmp-") for name in leftovers))

    def test_created_file_is_readable_mode(self) -> None:
        self.store.put("builds/ab/one.tar", b"payload")
        mode = (self.root / "builds" / "ab" / "one.tar").stat().st_mode & 0o777
        self.assertEqual(mode, 0o644)

    def test_list_rejects_hostile_prefix(self) -> None:
        for prefix in ("/abs", "../up", "a\\b", "a\x00b"):
            with self.subTest(prefix=prefix):
                with self.assertRaises(ArtifactStoreError):
                    self.store.list(prefix)


class InMemoryArtifactStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryArtifactStore()

    def test_round_trip_and_list(self) -> None:
        self.store.put("builds/x.tar", b"a")
        self.store.put("builds/y.tar", b"b")
        self.assertEqual(self.store.get("builds/x.tar"), b"a")
        self.assertTrue(self.store.exists("builds/y.tar"))
        self.assertEqual(self.store.list("builds/"), ["builds/x.tar", "builds/y.tar"])

    def test_immutability(self) -> None:
        self.store.put("k", b"one")
        self.store.put("k", b"one")  # identical -> no-op
        with self.assertRaises(ArtifactStoreError):
            self.store.put("k", b"two")

    def test_hostile_key_raises(self) -> None:
        with self.assertRaises(ArtifactStoreError):
            self.store.put("../escape", b"x")


if __name__ == "__main__":
    unittest.main()
