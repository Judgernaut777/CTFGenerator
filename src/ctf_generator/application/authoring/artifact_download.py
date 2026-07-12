"""Resolve a published challenge version's PUBLIC downloadable artifact.

``ArtifactDownloadService.resolve_public_artifact`` is the single application
seam the contestant download handlers (web slice 14c-2 route + JSON API route)
call: it maps a ``(definition_slug, version_no)`` to the in-memory bytes of the
version's MATERIALIZED public bundle (the 14c-1 tar, already private-stripped),
plus the metadata a handler needs to stream it -- filename, media type, length.

PUBLIC-ONLY + no-traversal, by construction
-------------------------------------------
The storage key is taken ONLY from the persisted
:class:`~ctf_generator.domain.authoring.models.ChallengeBuild.storage_uri` (which
:class:`~ctf_generator.application.authoring.materialization.BuildMaterializationService`
wrote when it materialized the PUBLIC bundle). A caller NEVER supplies a path or
key -- the download service takes only a slug + version and looks the key up in
the DB, so there is no traversal surface and no way to reach a private file.

Never raises on ordinary missing state
--------------------------------------
Returns ``None`` (never an exception) when the artifact is simply not available:

* the store is not configured (``artifact_store is None`` -- e.g.
  ``CTFGEN_ARTIFACT_ROOT`` unset), or
* no build has been materialized for the version, or
* the (materialized) build carries no ``storage_uri``, or
* the store holds no bytes for that key (or the key is somehow unreadable).

The handlers turn a ``None`` into a clean 404 / friendly page, never a 500. This
service performs NO authorization / tenancy -- the handlers do that BEFORE calling
here (competition-scoped read + published-in-this-competition).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ctf_generator.application.authoring.build_service import BuildService
from ctf_generator.application.jobs.service import JobService
from ctf_generator.domain.repositories import ArtifactStore
from ctf_generator.infrastructure.database.session import Database

_MEDIA_TYPE = "application/x-tar"
# Content-Disposition filename allowlist: strip anything outside this set so a
# filename can never carry CR/LF/quote/semicolon (no header injection / response
# splitting). The slug is a validated business id, but this is defense-in-depth.
_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def _sanitize_filename(definition_slug: str, version_no: int) -> str:
    """A safe ``<slug>-v<version_no>.tar`` download filename.

    ``version_no`` is an ``int`` (never attacker text). The slug is scrubbed to
    the ``[A-Za-z0-9._-]`` allowlist so no control character / quote / separator
    can reach the ``Content-Disposition`` header. A slug that scrubs to empty
    falls back to ``artifact`` so the filename is never degenerate."""
    safe_slug = _FILENAME_UNSAFE.sub("", definition_slug) or "artifact"
    return f"{safe_slug}-v{int(version_no)}.tar"


@dataclass(frozen=True)
class ArtifactDownload:
    """The bytes + streaming metadata of a resolved public artifact.

    A pure value object (no ORM row escapes): ``data`` is the materialized public
    tar, ``content_length`` is ``len(data)``, ``media_type`` is ``application/x-tar``,
    and ``filename`` is the sanitized attachment name.
    """

    filename: str
    media_type: str
    content_length: int
    data: bytes


class ArtifactDownloadService:
    """Look up a version's materialized PUBLIC build and load its bytes.

    Composes :class:`BuildService` (to find the build row + its ``storage_uri``)
    and an :class:`~ctf_generator.domain.repositories.ArtifactStore` (to load the
    bytes). ``artifact_store`` may be ``None`` (store unconfigured) -- every
    resolve then cleanly returns ``None`` rather than raising.
    """

    def __init__(
        self, database: Database, artifact_store: ArtifactStore | None
    ) -> None:
        self._artifact_store = artifact_store
        # BuildService owns the read UoW; the JobService collaborator is only used
        # by its trigger path (never reached here -- this service only reads).
        self._builds = BuildService(database, jobs=JobService(database))

    def resolve_public_artifact(
        self, definition_slug: str, version_no: int
    ) -> ArtifactDownload | None:
        """Resolve the public artifact bytes for ``(definition_slug, version_no)``.

        Returns ``None`` (never raises) for any missing state: no store, no
        materialized build, a build without a ``storage_uri``, or a key the store
        has no bytes for. The storage key is read ONLY from the DB build row -- a
        caller cannot influence it (no traversal)."""
        store = self._artifact_store
        if store is None:
            return None

        builds = self._builds.list_for_version(definition_slug, version_no)
        # Only a MATERIALIZED build (one that persisted its bytes) carries a
        # storage_uri; the rest are not downloadable. Deterministic pick: the
        # highest content address (there is no timestamp on a build, and the
        # content-addressed sha is stable), so the same version always resolves to
        # the same blob even if several materialized rows exist.
        materialized = sorted(
            (b for b in builds if b.storage_uri),
            key=lambda b: b.build_sha256,
        )
        if not materialized:
            return None
        storage_uri = materialized[-1].storage_uri
        assert storage_uri is not None  # noqa: S101 - filtered on truthy above

        try:
            data = store.get(storage_uri)
        except Exception:
            # A key from our own DB row is always store-valid; guard defensively so
            # a malformed/absent key is a clean "not available", never a 500.
            return None
        if data is None:
            return None

        return ArtifactDownload(
            filename=_sanitize_filename(definition_slug, version_no),
            media_type=_MEDIA_TYPE,
            content_length=len(data),
            data=data,
        )
