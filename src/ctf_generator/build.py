"""Safe, atomic challenge-build publishing with cryptographic manifests.

Milestone 3 (filesystem & generation hardening). Every challenge is rendered by
a family into a ``{relative_path: text}`` mapping; this module is the single
choke point that turns that mapping into an on-disk bundle safely:

* Renderer paths are validated (no absolute paths, no ``..`` traversal, no
  control/bidi-confusable characters, no reserved names, bounded length) and
  duplicate normalized paths are rejected.
* Output is written into a temporary sibling directory, then **atomically
  published** with ``os.replace`` so a failed or interrupted build can never
  replace a valid one; a failed build's diagnostics are retained separately.
* The build directory is stamped with an ownership **marker**
  (``.ctfgen-build``); recursive deletion (``--force`` regeneration) refuses any
  non-empty directory that is not a CTFGenerator-managed build, so the tool can
  never ``rmtree`` an arbitrary path.
* File-count and aggregate-size limits are enforced.
* A complete **artifact manifest** with a SHA-256 of every file is generated,
  split into a public manifest (safe to serve to contestants) and a full
  private manifest, and the generator/spec versions are recorded.

This is applied inside ``generator.create_challenge`` so *every* entry point
(CLI ``create``/``create-from-cve``, MCP tools) is hardened uniformly, not just
the MCP workspace seam.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import __version__
from .models import SPEC_VERSION

# --- Limits -------------------------------------------------------------------
# Generous enough for every current family (largest bundle is ~50 files) but
# bounded so a runaway or malicious renderer cannot exhaust the disk.
MAX_FILE_COUNT = 2000
MAX_TOTAL_BYTES = 64 * 1024 * 1024  # 64 MiB
MAX_COMPONENT_BYTES = 255  # per path component, matches common filesystem limits

BUILD_MARKER_NAME = ".ctfgen-build"
PUBLIC_MANIFEST = "public/manifest.json"
PRIVATE_MANIFEST = "private/manifest.json"
_MANIFEST_SCHEMA = "ctfgen.build-manifest"
_MARKER_SCHEMA = "ctfgen.build-marker"
_SCHEMA_VERSION = "1.0"

# Files this module writes itself; excluded from the manifest so it never tries
# to hash itself. Matched case-insensitively so a case-insensitive filesystem
# cannot desync the manifest from disk via a case variant.
_EXCLUDED_FROM_MANIFEST = frozenset({BUILD_MARKER_NAME, PUBLIC_MANIFEST, PRIVATE_MANIFEST})
_EXCLUDED_FROM_MANIFEST_CF = frozenset(p.casefold() for p in _EXCLUDED_FROM_MANIFEST)
# A renderer may never supply these paths (would forge the marker or shadow a
# manifest); rejected case-insensitively in validate_relative_path.
_RESERVED_OUTPUT_PATHS_CF = _EXCLUDED_FROM_MANIFEST_CF

# Unicode format/bidi characters that make a filename lie about its true path.
_CONFUSABLE_CHARS = frozenset(
    chr(c)
    for c in (
        *range(0x200B, 0x2010),  # zero-width space .. RTL/LTR marks
        *range(0x202A, 0x202F),  # bidi embeddings/overrides
        *range(0x2066, 0x206A),  # bidi isolates
        0xFEFF,  # zero-width no-break space / BOM
    )
)

# Windows reserved device names (portability + confusion avoidance).
_WIN_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
)


class BuildError(Exception):
    """Base class for all build-safety failures."""


class PathValidationError(BuildError):
    """A renderer-supplied relative path is unsafe or malformed."""


class DuplicatePathError(BuildError):
    """Two renderer paths normalize to the same destination."""


class DangerousOutputRootError(BuildError):
    """The requested output directory is a path we refuse to manage/delete."""


class UnsafeDeletionError(BuildError):
    """The output directory exists but is not a CTFGenerator-managed build."""


class BuildLimitError(BuildError):
    """The build exceeded the file-count or aggregate-size limit."""


@dataclass(frozen=True)
class BuildMeta:
    """Provenance recorded into the marker and manifests. Deterministic."""

    family: str
    seed: str
    spec_sha256: str
    # Per-family versioning arrives in Milestone 4; reserve the field now so the
    # manifest shape is forward-compatible.
    family_version: str | None = None


def validate_relative_path(rel: str) -> str:
    """Validate and normalize a renderer-supplied relative path.

    Returns the normalized POSIX path. Raises :class:`PathValidationError` for
    absolute paths, traversal, control/bidi-confusable characters, reserved
    names, or over-long components.
    """
    if not isinstance(rel, str) or not rel:
        raise PathValidationError("empty or non-string path")
    if "\x00" in rel:
        raise PathValidationError(f"NUL byte in path: {rel!r}")
    if "\\" in rel:
        raise PathValidationError(f"backslash not allowed in path: {rel!r}")

    pure = PurePosixPath(rel)
    if pure.is_absolute():
        raise PathValidationError(f"absolute path not allowed: {rel!r}")

    parts = [p for p in pure.parts if p != "."]
    if not parts:
        raise PathValidationError(f"path resolves to nothing: {rel!r}")

    for part in parts:
        if part == "..":
            raise PathValidationError(f"path traversal ('..') not allowed: {rel!r}")
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in part):
            raise PathValidationError(f"control character in path component: {rel!r}")
        if any(c in _CONFUSABLE_CHARS for c in part):
            raise PathValidationError(f"bidi/zero-width character in path component: {rel!r}")
        if len(part.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise PathValidationError(f"path component too long: {rel!r}")
        if part != part.rstrip(" ."):
            raise PathValidationError(f"trailing space/dot in path component: {rel!r}")
        stem = part.split(".", 1)[0].upper()
        if stem in _WIN_RESERVED:
            raise PathValidationError(f"reserved filename: {rel!r}")

    norm = "/".join(parts)
    # A renderer must never write the build-management files itself: doing so
    # would forge the ownership marker or shadow a generated manifest. Compared
    # case-insensitively so a case-insensitive filesystem can't sneak a variant
    # (e.g. ``Public/Manifest.json``) past the check.
    if norm.casefold() in _RESERVED_OUTPUT_PATHS_CF:
        raise PathValidationError(f"reserved build path may not be supplied by a renderer: {rel!r}")
    return norm


def is_managed_build_dir(path: Path) -> bool:
    """True if ``path`` is a directory carrying the CTFGenerator build marker."""
    return path.is_dir() and (path / BUILD_MARKER_NAME).is_file()


def _reject_dangerous_output_root(final: Path) -> None:
    # realpath (not abspath) so a symlinked path to home/cwd/root is caught, and
    # so the comparison is symmetric with the realpath'd home/cwd below.
    resolved = Path(os.path.realpath(final))
    if resolved == Path(resolved.anchor):
        raise DangerousOutputRootError(f"refusing filesystem root as output: {resolved}")
    if resolved.is_absolute() and len(resolved.parts) <= 2:
        # e.g. '/etc', '/home' -- too shallow to be a challenge build dir.
        raise DangerousOutputRootError(f"refusing shallow system path as output: {resolved}")
    home = Path(os.path.realpath(Path.home()))
    if resolved == home:
        raise DangerousOutputRootError(f"refusing home directory as output: {resolved}")
    cwd = Path(os.path.realpath(Path.cwd()))
    if resolved == cwd or resolved in cwd.parents:
        raise DangerousOutputRootError(
            f"refusing to overwrite the current working directory or an ancestor: {resolved}"
        )


def _is_nonempty_dir(path: Path) -> bool:
    return path.is_dir() and any(path.iterdir())


def _assert_within(root_real: str, target: Path) -> None:
    """Belt-and-suspenders symlink guard: the target's real parent must stay
    inside the real build root."""
    real_parent = os.path.realpath(target.parent)
    try:
        inside = os.path.commonpath([root_real, real_parent]) == root_real
    except ValueError:
        # Different drives / mixed absolute-relative: not provably inside.
        inside = False
    if not inside:
        raise PathValidationError(f"path escapes build root via symlink: {target}")


def _reserve_sibling(parent: Path, prefix: str) -> Path:
    """Return a unique, currently-free path under ``parent`` for an atomic
    ``os.replace`` target (used for the move-aside backup and failed-build
    diagnostics). ``mkdtemp`` guarantees a fresh name; we free it so the rename
    can claim it, never clobbering a pre-existing directory."""
    reserved = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    os.rmdir(reserved)
    return reserved


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_manifests(build_root: Path, meta: BuildMeta) -> None:
    entries: list[tuple[str, str, int]] = []
    for path in sorted(build_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(build_root).as_posix()
        if rel.casefold() in _EXCLUDED_FROM_MANIFEST_CF:
            continue
        data = path.read_bytes()
        entries.append((rel, _sha256_bytes(data), len(data)))

    all_files = {rel: {"sha256": h, "size": s} for rel, h, s in entries}
    public_files = {rel: v for rel, v in all_files.items() if rel.startswith("public/")}
    total_bytes = sum(s for _, _, s in entries)

    # Provenance safe to hand a contestant: NO seed and NO spec hash. The seed
    # deterministically derives the flag (create_challenge seeds the family RNG
    # from it), so it must never appear in a player-facing artifact.
    public_base = {
        "schema": _MANIFEST_SCHEMA,
        "schema_version": _SCHEMA_VERSION,
        "generator_version": __version__,
        "spec_version": SPEC_VERSION,
        "family": meta.family,
        "family_version": meta.family_version,
    }

    # Public manifest: hashes of player-facing files only. Only written when
    # there is a public surface, so artifact-only families don't grow an empty
    # public/ dir.
    if public_files:
        _write_json(
            build_root / PUBLIC_MANIFEST,
            {**public_base, "file_count": len(public_files), "files": public_files},
        )

    # Private manifest: the complete cryptographic manifest of the whole bundle,
    # including the seed and spec hash. Never served to contestants.
    _write_json(
        build_root / PRIVATE_MANIFEST,
        {
            **public_base,
            "seed": meta.seed,
            "spec_sha256": meta.spec_sha256,
            "file_count": len(all_files),
            "public_file_count": len(public_files),
            "total_bytes": total_bytes,
            "files": all_files,
        },
    )


def write_build(
    final_dir: Path,
    files: dict[str, str],
    *,
    meta: BuildMeta,
    force: bool = False,
) -> Path:
    """Validate, write, and atomically publish a challenge build.

    ``files`` maps renderer-supplied relative paths to text content. Writes into
    a temporary sibling directory, generates manifests, then atomically replaces
    ``final_dir``. On any failure the partial build is moved to
    ``<final_dir>.ctfgen-failed`` for diagnosis and the error is re-raised.
    """
    final = Path(final_dir)
    _reject_dangerous_output_root(final)

    # Decide up-front whether an existing target may be replaced, before doing
    # any work, so we fail fast and never partially build over a live dir.
    if final.exists():
        if final.is_symlink():
            raise UnsafeDeletionError(f"output path is a symlink; refusing to write through it: {final}")
        if not force:
            raise FileExistsError(f"{final} already exists; pass force=True to overwrite")
        if _is_nonempty_dir(final) and not is_managed_build_dir(final):
            raise UnsafeDeletionError(
                f"refusing to delete non-empty, unmarked directory {final}; "
                f"only CTFGenerator-managed builds (containing {BUILD_MARKER_NAME}) are replaceable"
            )

    parent = final.parent
    parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=f".{final.name}.ctfgen-tmp-", dir=parent))
    tmp_real = os.path.realpath(tmp)

    try:
        # Ownership marker first: deterministic, no wall-clock.
        _write_json(
            tmp / BUILD_MARKER_NAME,
            {
                "schema": _MARKER_SCHEMA,
                "schema_version": _SCHEMA_VERSION,
                "generator_version": __version__,
                "family": meta.family,
                "seed": meta.seed,
            },
        )

        # Validate + de-duplicate every renderer path before writing anything.
        # Collision detection is case-insensitive so two paths that differ only
        # in case (which collide on a case-insensitive filesystem) are rejected
        # rather than silently clobbering each other.
        normalized: dict[str, str] = {}
        seen_casefold: set[str] = set()
        for rel, content in files.items():
            norm = validate_relative_path(rel)
            cf = norm.casefold()
            if cf in seen_casefold:
                raise DuplicatePathError(f"duplicate renderer path after normalization: {norm!r}")
            seen_casefold.add(cf)
            normalized[norm] = content

        if len(normalized) > MAX_FILE_COUNT:
            raise BuildLimitError(f"file count {len(normalized)} exceeds limit {MAX_FILE_COUNT}")

        total = 0
        for norm, content in normalized.items():
            target = tmp / norm
            target.parent.mkdir(parents=True, exist_ok=True)
            _assert_within(tmp_real, target)
            data = content.encode("utf-8")
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise BuildLimitError(
                    f"aggregate size exceeds limit {MAX_TOTAL_BYTES} bytes"
                )
            target.write_bytes(data)

        _build_manifests(tmp, meta)

        # Atomic publish. Move any existing (managed/empty) target ASIDE first,
        # then rename the new build in. If the final rename fails, the prior
        # valid build is restored -- so a failed publish can never leave the
        # destination empty or half-written.
        backup: Path | None = None
        if final.exists():
            # Re-verify immediately before the destructive step to narrow the
            # TOCTOU window between the up-front check and here.
            if final.is_symlink():
                raise UnsafeDeletionError(f"output path became a symlink: {final}")
            if _is_nonempty_dir(final) and not is_managed_build_dir(final):
                raise UnsafeDeletionError(f"output path is no longer a managed build: {final}")
            backup = _reserve_sibling(parent, f".{final.name}.ctfgen-old-")
            os.replace(final, backup)
        published = False
        try:
            os.replace(tmp, final)
            published = True
        finally:
            if backup is not None:
                if not published and not final.exists():
                    # publish failed and the slot is free -> restore prior build
                    os.replace(backup, final)
                # Whether restored, superseded by a racing writer, or replaced on
                # success, never leave the move-aside backup orphaned.
                if backup.exists():
                    shutil.rmtree(backup, ignore_errors=True)
        return final
    except Exception:
        # Retain the partial build for diagnosis under a UNIQUE name so an
        # unrelated pre-existing directory is never clobbered.
        try:
            diag = _reserve_sibling(parent, f"{final.name}.ctfgen-failed-")
            os.replace(tmp, diag)
        except OSError:
            shutil.rmtree(tmp, ignore_errors=True)
        raise
