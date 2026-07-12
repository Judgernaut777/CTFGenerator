"""Content-addressed, immutable, path-safe artifact stores.

Concrete implementations of the domain
:class:`ctf_generator.domain.repositories.ArtifactStore` Protocol
(``put`` / ``get`` / ``exists`` / ``list``). Two backends live here:

* :class:`LocalFilesystemArtifactStore` -- the deliverable: bytes on disk under a
  single ``root``, addressed by an opaque caller-supplied key.
* :class:`InMemoryArtifactStore` -- a dict-backed double with identical
  validation/immutability semantics, for fast unit tests and offline wiring.

Three guarantees hold for both:

* **Path safety.** Every key is validated (via the hardened
  :func:`ctf_generator.build.validate_relative_path`: no absolute path, no ``..``
  traversal, no control/bidi-confusable characters, no NUL/backslash) AND, for
  the filesystem store, the resolved real path must stay inside the real root
  (a symlink-aware ``realpath`` containment check). A hostile key raises
  :class:`ArtifactStoreError` and never reads or writes outside ``root``.
* **Immutability + content addressing.** ``put`` of a key that already holds the
  SAME bytes is a no-op (content-addressed idempotency); ``put`` of a key that
  already holds DIFFERENT bytes raises :class:`ArtifactStoreError`. A stored
  artifact is never silently overwritten with different content.
* **Atomicity.** The filesystem store writes to a temp file in the destination
  directory and ``os.replace``\\s it into place, so a reader ever sees either the
  complete artifact or nothing -- never a half-written file.

An object-store backend (S3/GCS/MinIO) is the SAME Protocol -- an
``S3ArtifactStore`` would map ``put``/``get``/``exists``/``list`` onto
PutObject/GetObject/HeadObject/ListObjectsV2 with the identical content-address
key. It is intentionally NOT implemented here: it needs live cloud credentials
(credential-blocked) and belongs to the deployment/packaging milestone. The
contract above is the seam a later slice swaps a bucket in behind.
"""

from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path, PurePosixPath

from ctf_generator import build as _build


class ArtifactStoreError(Exception):
    """An artifact-store operation was rejected.

    Raised for an unsafe/escaping key, a non-bytes payload, or an attempt to
    overwrite an existing artifact with different bytes (immutability).
    """


def _validate_key(key: str) -> str:
    """Validate a caller-supplied key and return its normalized POSIX form.

    Delegates the hardened string checks (absolute / traversal / control / bidi /
    NUL / backslash / reserved) to :func:`ctf_generator.build.validate_relative_path`.
    Raises :class:`ArtifactStoreError` (never leaking the build-layer exception).
    """
    if not isinstance(key, str):
        raise ArtifactStoreError(f"artifact key must be a string, got {type(key)!r}")
    try:
        return _build.validate_relative_path(key)
    except _build.PathValidationError as exc:
        raise ArtifactStoreError(f"unsafe artifact key {key!r}: {exc}") from exc


def _validate_prefix(prefix: str) -> None:
    """Reject an escaping/hostile ``list`` prefix. A prefix need not name a whole
    path component, so it is checked more loosely than a key -- but it may never
    be absolute, contain ``..``, or carry NUL/backslash. (Listing only ever walks
    the store root, so a prefix can never enumerate outside it regardless; this is
    defense-in-depth so a hostile prefix fails loudly instead of silently.)"""
    if not isinstance(prefix, str):
        raise ArtifactStoreError(f"prefix must be a string, got {type(prefix)!r}")
    if not prefix:
        return
    if "\x00" in prefix or "\\" in prefix:
        raise ArtifactStoreError(f"unsafe list prefix: {prefix!r}")
    pure = PurePosixPath(prefix)
    if pure.is_absolute() or ".." in pure.parts:
        raise ArtifactStoreError(f"unsafe list prefix: {prefix!r}")


def _fsync_dir(path: Path) -> None:
    """fsync a directory so a rename/link into it is crash-durable. Best-effort:
    platforms that cannot open a directory for fsync are tolerated."""
    try:
        dir_fd = os.open(str(path), os.O_RDONLY)
    except OSError:  # pragma: no cover - platform without dir-fd support
        return
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - fsync on a dir not supported
        pass
    finally:
        os.close(dir_fd)


class LocalFilesystemArtifactStore:
    """Store opaque artifact bytes on disk under ``root``, keyed by a validated,
    content-addressed relative key. Immutable, atomic, path-safe."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        # realpath (not abspath) so a symlinked root resolves once, up front, and
        # the per-key containment check compares like-for-like.
        self._root_real = os.path.realpath(self._root)

    def _target(self, key: str) -> Path:
        """Map a validated key to its on-disk path, asserting the resolved path
        stays inside the real root (symlink-aware). Raises on any escape."""
        norm = _validate_key(key)
        target = self._root / norm
        # The target's real parent must resolve inside the real root (blocks a
        # symlinked intermediate dir), and the target itself must not resolve
        # outside root. realpath resolves the existing prefix and appends any
        # not-yet-created tail lexically, so this is safe before mkdir.
        real_parent = os.path.realpath(target.parent)
        real_target = os.path.realpath(target)
        for candidate in (real_parent, real_target):
            try:
                inside = (
                    os.path.commonpath([self._root_real, candidate]) == self._root_real
                )
            except ValueError:
                inside = False
            if not inside:
                raise ArtifactStoreError(f"artifact key escapes store root: {key!r}")
        return target

    def put(self, key: str, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise ArtifactStoreError("artifact data must be bytes")
        data = bytes(data)
        target = self._target(key)
        if target.exists() and not target.is_file():
            raise ArtifactStoreError(f"artifact key is not a regular file: {key!r}")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Write a sibling temp file (same dir), fsync its data, then publish via an
        # ATOMIC os.link into place. os.link fails with FileExistsError if the key
        # already exists -- so immutability is enforced atomically even under
        # concurrent puts (exactly one linker wins; a loser observing an existing
        # key does the identical-bytes check below), and a crash mid-write leaves
        # the temp file (or nothing), never a half-written target. The parent dir
        # is fsync'd after the link so the rename is durable (the companion to the
        # data fsync) -- a ChallengeBuild row must never point at a lost file.
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(target.parent))
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o644)
            try:
                os.link(tmp, target)
            except FileExistsError:
                # Immutability: the key already holds bytes. Identical -> no-op;
                # different -> refuse (never silently overwrite).
                existing = target.read_bytes()
                if existing != data:
                    raise ArtifactStoreError(
                        f"artifact already exists with different bytes "
                        f"(immutable): {key!r}"
                    ) from None
                return
            _fsync_dir(target.parent)
        finally:
            tmp.unlink(missing_ok=True)

    def get(self, key: str) -> bytes | None:
        target = self._target(key)
        if not target.is_file():
            return None
        return target.read_bytes()

    def exists(self, key: str) -> bool:
        return self._target(key).is_file()

    def list(self, prefix: str = "") -> list[str]:
        _validate_prefix(prefix)
        keys: list[str] = []
        for path in self._root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(self._root).as_posix()
            if rel.startswith(prefix):
                keys.append(rel)
        return sorted(keys)


class InMemoryArtifactStore:
    """A dict-backed :class:`ArtifactStore` double with the same key-validation
    and immutability semantics as the filesystem store (no atomicity concern --
    a dict assignment is already atomic). Handy for unit tests and offline
    wiring; not durable."""

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def put(self, key: str, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise ArtifactStoreError("artifact data must be bytes")
        data = bytes(data)
        norm = _validate_key(key)
        # Lock the check-then-set so concurrent puts of the same key with
        # different bytes cannot both slip past the immutability check.
        with self._lock:
            existing = self._data.get(norm)
            if existing is not None:
                if existing == data:
                    return
                raise ArtifactStoreError(
                    f"artifact already exists with different bytes (immutable): {key!r}"
                )
            self._data[norm] = data

    def get(self, key: str) -> bytes | None:
        return self._data.get(_validate_key(key))

    def exists(self, key: str) -> bool:
        return _validate_key(key) in self._data

    def list(self, prefix: str = "") -> list[str]:
        _validate_prefix(prefix)
        return sorted(k for k in self._data if k.startswith(prefix))
