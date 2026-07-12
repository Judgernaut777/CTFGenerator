"""Materialize a published challenge version's downloadable PUBLIC bundle.

``BuildMaterializationService.materialize`` turns a *published* challenge version
into the content-addressed, contestant-safe artifact bytes that back the download
endpoint (wired in slice 14c-2), persists those bytes through an
:class:`~ctf_generator.domain.repositories.ArtifactStore`, and records a
:class:`~ctf_generator.domain.authoring.models.ChallengeBuild` row pointing at
them.

RENDER vs EXECUTE (ADR-001 boundary -- the crux)
------------------------------------------------
ADR-001 forbids the control plane from EXECUTING a challenge's vulnerable
workload (the Docker image build/run). It does NOT forbid RENDERING a bundle:
:func:`ctf_generator.generator.create_challenge` only writes deterministic
template TEXT to files -- exactly what the CLI and MCP server already do on the
control plane. So materializing the PUBLIC bundle (render -> strip ``private/``
-> persist the public bytes) is pure, control-plane-safe work. The effectful
``build_challenge`` worker job (the Docker IMAGE build/run) is SEPARATE and stays
the worker's; it is NOT implemented here and is unchanged by this slice.

Flow
----
1. Load the ``ChallengeVersion``; require it exists and is ``published`` (a
   draft/missing version is a clear error, never a silent build).
2. Reconstruct the ``ChallengeSpec`` from the stored spec mapping.
3. Render the FULL bundle deterministically into a throwaway temp dir.
4. STRIP to the ``public/`` subtree only, asserting no private/forbidden path
   survives (the R-22 no-leak backstop).
5. Package the public files into a NORMALIZED, byte-deterministic tar so the same
   version always yields the same ``build_sha256`` (content addressing).
6. ``put`` the bytes FIRST (crash-safe: a build row never references absent
   bytes), then write the ``ChallengeBuild`` row. Idempotent: an already-
   materialized version returns its existing row without a duplicate write.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
from pathlib import Path

from sqlalchemy.exc import IntegrityError

from ctf_generator import __version__
from ctf_generator import generator as _generator_module
from ctf_generator.domain.authoring.models import ChallengeBuild
from ctf_generator.domain.repositories import ArtifactStore
from ctf_generator.infrastructure.database.challenge_build_repository import (
    SqlAlchemyChallengeBuildRepository,
)
from ctf_generator.infrastructure.database.challenge_version_repository import (
    SqlAlchemyChallengeVersionRepository,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.spec_generator import spec_from_dict

# A contestant-safe artifact carries ONLY files under public/. These prefixes /
# names must NEVER appear in it; their presence is a leak and aborts the build.
_FORBIDDEN_PREFIXES = ("private/", "services/", "tests/")
_FORBIDDEN_BASENAMES = frozenset(
    {"docker-compose.yml", "docker-compose.yaml", ".env", ".env.example"}
)


class MaterializationError(Exception):
    """A rendered bundle failed the contestant-safety invariant (a private or
    otherwise non-public path was about to enter the artifact)."""


def _storage_key(build_sha256: str) -> str:
    """Content-addressed, sharded storage key for a build's tar blob."""
    return f"builds/{build_sha256[:2]}/{build_sha256}.tar"


def _is_public_path(rel: str) -> bool:
    return rel.startswith("public/")


def _assert_contestant_safe(rel: str) -> None:
    """Defense-in-depth: raise unless ``rel`` is a public, contestant-safe path.

    The selection filter already keeps only ``public/`` files, so this should
    never fire -- it is the belt to the suspenders, guaranteeing the private
    flag / solver / solution can never reach a persisted artifact even if the
    renderer's layout changes underneath us.
    """
    lowered = rel.lower()
    if not _is_public_path(rel):
        raise MaterializationError(f"non-public path in artifact bundle: {rel!r}")
    for prefix in _FORBIDDEN_PREFIXES:
        if lowered.startswith(prefix):
            raise MaterializationError(f"forbidden path in artifact bundle: {rel!r}")
    basename = rel.rsplit("/", 1)[-1]
    if basename in _FORBIDDEN_BASENAMES:
        raise MaterializationError(f"forbidden file in artifact bundle: {rel!r}")


def _select_public_files(bundle_root: Path) -> dict[str, bytes]:
    """Collect ONLY the ``public/`` subtree of a rendered bundle as
    ``{relative_posix_path: bytes}``, asserting each kept path is contestant-safe.
    """
    selected: dict[str, bytes] = {}
    for path in sorted(bundle_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle_root).as_posix()
        if _is_public_path(rel):
            selected[rel] = path.read_bytes()
    # Every kept path must pass the contestant-safety assertion (R-22 backstop).
    for rel in selected:
        _assert_contestant_safe(rel)
    return selected


def _deterministic_tar(files: dict[str, bytes]) -> bytes:
    """Package files into a byte-DETERMINISTIC USTAR archive.

    Entries are emitted in sorted name order with every non-deterministic field
    pinned (``mtime=0``, ``uid=gid=0``, ``uname=gname=""``, ``mode=0644``,
    regular-file type). USTAR (not PAX) avoids per-entry extended headers that
    would embed timestamps. Result: the same public file set always hashes to the
    same ``build_sha256`` -- the invariant content addressing depends on.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.type = tarfile.REGTYPE
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class BuildMaterializationService:
    """Render -> strip -> content-address -> persist a published version's public
    bundle. Owns the unit of work; returns the domain ``ChallengeBuild``."""

    def __init__(
        self,
        database: Database,
        artifact_store: ArtifactStore,
        *,
        generator: object | None = None,
    ) -> None:
        self._database = database
        self._artifact_store = artifact_store
        # Injectable so a unit test can supply a rendering double; defaults to the
        # real generator module (whose create_challenge is pure text rendering).
        self._generator = generator if generator is not None else _generator_module

    def materialize(self, definition_slug: str, version_no: int) -> ChallengeBuild:
        """Materialize the public artifact for ``(definition_slug, version_no)``.

        Raises :class:`LookupError` if the version does not exist and
        :class:`ValueError` if it is not ``published``. Idempotent: re-
        materializing the same version returns the existing content-addressed
        ``ChallengeBuild`` without writing a duplicate row or overwriting bytes.
        """
        with self._database.session_scope() as session:
            version = SqlAlchemyChallengeVersionRepository(session).get(
                definition_slug, version_no
            )
        if version is None:
            raise LookupError(
                f"challenge version not found: {definition_slug!r} v{version_no}"
            )
        if version.state != "published":
            raise ValueError(
                "only a published version can be materialized "
                f"(got state={version.state!r} for {definition_slug!r} v{version_no})"
            )

        spec = spec_from_dict(dict(version.spec))

        # Pure, deterministic TEXT rendering into a throwaway temp dir (see the
        # RENDER-vs-EXECUTE note in the module docstring). force=True because the
        # target is a fresh, empty temp path.
        with tempfile.TemporaryDirectory(prefix="ctfgen-materialize-") as tmp_dir:
            bundle_root = Path(tmp_dir) / "bundle"
            self._generator.create_challenge(
                output_dir=bundle_root,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                force=True,
                spec=spec,
            )
            public_files = _select_public_files(bundle_root)

        tar_bytes = _deterministic_tar(public_files)
        # The stored BYTES are addressed by the public bundle's content hash, so
        # two versions that render identical public output physically dedup to one
        # blob. The BUILD's identity (build_sha256, the row key) folds in the
        # version's full-spec identity (spec_sha256), so those two versions still
        # get DISTINCT build rows -- otherwise the idempotent get-or-return below
        # would misattribute version B's materialize to version A's existing row.
        # Re-materializing the SAME version is still idempotent (same spec_sha256
        # + same content -> same build_sha256).
        content_hash = hashlib.sha256(tar_bytes).hexdigest()
        build_sha256 = hashlib.sha256(
            f"{version.spec_sha256}:{content_hash}".encode()
        ).hexdigest()
        key = _storage_key(content_hash)

        manifest_bytes = public_files.get("public/manifest.json")
        public_manifest: dict[str, object] = (
            json.loads(manifest_bytes.decode("utf-8")) if manifest_bytes else {}
        )

        # Bytes FIRST: a crash after this but before the row leaves orphan bytes
        # (harmless, re-put identically next run), never a row citing absent bytes.
        # The store is content-addressed + immutable, so re-putting is a no-op.
        self._artifact_store.put(key, tar_bytes)

        build = ChallengeBuild(
            build_sha256=build_sha256,
            definition_slug=definition_slug,
            version_no=version_no,
            family=spec.family,
            seed=version.seed,
            spec_sha256=version.spec_sha256,
            generator_version=__version__,
            manifest=public_manifest,
            family_version=version.family_version,
            storage_uri=key,
        )

        try:
            with self._database.session_scope() as session:
                repo = SqlAlchemyChallengeBuildRepository(session)
                existing = repo.get(build_sha256)
                if existing is not None:
                    # Already materialized (same content address) -> idempotent.
                    return existing
                repo.add(build)
                stored = repo.get(build_sha256)
            assert stored is not None  # noqa: S101 - just inserted in this UoW
            return stored
        except IntegrityError:
            # A concurrent materialization of the identical content won the race
            # (duplicate build_sha256). The row now exists; return it.
            with self._database.session_scope() as session:
                stored = SqlAlchemyChallengeBuildRepository(session).get(build_sha256)
            if stored is None:
                raise
            return stored
