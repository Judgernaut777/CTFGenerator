"""Render a challenge version's FULL, buildable bundle for the worker-side
``build_challenge`` pipeline (``docs/architecture/build-challenge-worker-pipeline.md``).

RENDER vs EXECUTE (ADR-001), the same split ``BuildMaterializationService``
already established for the PUBLIC-only download artifact
--------------------------------------------------------------------------
Rendering a bundle is pure, deterministic TEXT generation --
:func:`ctf_generator.generator.create_challenge` only writes files; it never
runs Docker or the bundle's own scripts. That is legal on the control plane.
Building the Docker IMAGE from that bundle is NOT -- it stays the worker's job
(ADR-001), which is exactly why this module renders and packages but never
invokes ``docker``.

Why this is a SEPARATE module from ``materialization.py``
-----------------------------------------------------------
:class:`~ctf_generator.application.authoring.materialization.BuildMaterializationService`
strips a rendered bundle down to ``public/`` only -- the artifact it produces
is contestant-safe and is served through the public download endpoint. THIS
module keeps EVERY rendered file, including ``private/`` (the flag/solution),
``services/*`` (the vulnerable-by-construction application code), and any
``docker-compose.yml`` -- i.e. everything a worker needs to actually build the
challenge image. **This bundle must never be exposed through any contestant-
facing route.** It is only ever handed to an authenticated, ``artifacts:pull``-
scoped worker via :class:`~ctf_generator.application.execution.worker_build_service.WorkerBuildService`.

Also unlike ``BuildMaterializationService``, this module does not require the
version to be ``published`` (mirroring ``BuildService.trigger_build``, which
enqueues ``build_challenge`` for any existing version -- an author may want to
test-build a draft before publishing) and it does not persist a
``ChallengeBuild`` row or write to an :class:`ArtifactStore` -- it renders on
demand, at fetch time, so there is no additional storage of flag-bearing bytes
at rest on the control plane beyond the ephemeral render.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ctf_generator import generator as _generator_module
from ctf_generator.infrastructure.database.challenge_version_repository import (
    SqlAlchemyChallengeVersionRepository,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.spec_generator import spec_from_dict


@dataclass(frozen=True)
class FullBundle:
    """The rendered FULL bundle's bytes + its two content addresses. May embed
    the flag/solution -- NEVER log ``data``."""

    data: bytes
    bundle_sha256: str
    spec_sha256: str


def _deterministic_tar(files: dict[str, bytes]) -> bytes:
    """Package files into a byte-DETERMINISTIC USTAR archive (every
    non-deterministic field pinned: ``mtime=0``, ``uid=gid=0``, mode ``0644``,
    regular-file type, sorted name order) -- the same shape
    ``materialization._deterministic_tar`` uses, so the same bundle content
    always hashes to the same ``bundle_sha256``. Duplicated rather than shared
    to keep this module's blast radius independent of the already-tested public
    materialization path; both are small and stable."""
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


def _collect_all_files(bundle_root: Path) -> dict[str, bytes]:
    """Collect EVERY file in a rendered bundle (unlike materialization's
    ``public/``-only filter) as ``{relative_posix_path: bytes}``."""
    selected: dict[str, bytes] = {}
    for path in sorted(bundle_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(bundle_root).as_posix()
        selected[rel] = path.read_bytes()
    return selected


class FullBundleService:
    """Render -> content-address a version's FULL bundle, on demand. Owns no
    persistent storage; every call re-renders (rendering is deterministic and
    cheap -- pure text generation, no Docker)."""

    def __init__(self, database: Database, *, generator: object | None = None) -> None:
        self._database = database
        # Injectable so a unit test can supply a rendering double; defaults to
        # the real generator module (whose create_challenge is pure text
        # rendering -- see the module docstring's RENDER-vs-EXECUTE note).
        self._generator = generator if generator is not None else _generator_module

    def render(self, definition_slug: str, version_no: int) -> FullBundle:
        """Render the FULL bundle for ``(definition_slug, version_no)``.

        Raises :class:`LookupError` if the version does not exist. Unlike
        :meth:`BuildMaterializationService.materialize`, a draft version is
        accepted (mirrors ``BuildService.trigger_build``'s own contract)."""
        with self._database.session_scope() as session:
            version = SqlAlchemyChallengeVersionRepository(session).get(
                definition_slug, version_no
            )
        if version is None:
            raise LookupError(
                f"challenge version not found: {definition_slug!r} v{version_no}"
            )

        spec = spec_from_dict(dict(version.spec))

        # Pure, deterministic TEXT rendering into a throwaway temp dir -- see
        # the RENDER-vs-EXECUTE note in the module docstring. force=True
        # because the target is a fresh, empty temp path.
        with tempfile.TemporaryDirectory(prefix="ctfgen-fullbundle-") as tmp_dir:
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
            all_files = _collect_all_files(bundle_root)

        tar_bytes = _deterministic_tar(all_files)
        bundle_sha256 = hashlib.sha256(tar_bytes).hexdigest()
        return FullBundle(
            data=tar_bytes,
            bundle_sha256=bundle_sha256,
            spec_sha256=version.spec_sha256,
        )
