"""Parse + validate a ``build_challenge`` job's completion result (pure).

The worker's ``_do_build_challenge`` reports a result payload of the shape::

    {"definition_slug": str, "version_no": int, "bundle_sha256": str,
     "image_ref": str, "digest": str}

on the completed job. This module turns that (secret-free, reference-only)
payload into a validated :class:`BuildCompletion`, or ``None`` when the payload
is absent or carries no built image. Being ``None`` for a non-build completion is
the job-type gate: :meth:`WorkerJobService.complete` stays job-type-agnostic in
spirit -- it records the image side effects only when the result actually carries
one, rather than branching on ``job_type``.

Pure and host-testable: no DB, no Docker, no logging of the payload. Everything
here is a reference or a hash -- never a flag, seed, or secret -- so the parsed
value is safe to surface.
"""

from __future__ import annotations

from dataclasses import dataclass


def _nonempty_str(value: object) -> str | None:
    """Return the stripped string iff ``value`` is a non-blank str, else None."""
    if isinstance(value, str) and value.strip():
        return value
    return None


@dataclass(frozen=True)
class BuildCompletion:
    """A validated build-job completion carrying a runnable image reference.

    ``image_digest`` may be ``None`` when the build backend returned no digest:
    the worker-affinity cache keys on ``image_ref`` alone and is still written,
    but the version->image registry (which keys on the digest) is skipped for
    that completion -- a cache hit without a launchable registry mapping, which
    the caller treats accordingly.
    """

    definition_slug: str
    version_no: int
    image_ref: str
    bundle_sha256: str
    image_digest: str | None = None

    def __post_init__(self) -> None:
        if not (isinstance(self.definition_slug, str) and self.definition_slug):
            raise ValueError("definition_slug must be a non-empty str")
        if not (isinstance(self.version_no, int) and self.version_no >= 1):
            raise ValueError(f"version_no must be an int >= 1, got {self.version_no!r}")
        if not (isinstance(self.image_ref, str) and self.image_ref.strip()):
            raise ValueError("image_ref must be a non-empty str")
        if not (isinstance(self.bundle_sha256, str) and self.bundle_sha256):
            raise ValueError("bundle_sha256 must be a non-empty str")
        if self.image_digest is not None and not (
            isinstance(self.image_digest, str) and self.image_digest.strip()
        ):
            raise ValueError("image_digest, when present, must be a non-empty str")

    @property
    def has_image_digest(self) -> bool:
        """True iff a non-empty digest is present (i.e. the version->image
        registry row can be written for this completion)."""
        return self.image_digest is not None


def parse_build_completion(result_json: dict | None) -> BuildCompletion | None:
    """Interpret a job completion result as a build outcome, or ``None``.

    Returns ``None`` -- signalling 'not a build completion, no image side effects'
    -- when ``result_json`` is falsy or carries no non-blank ``image_ref``. When
    an ``image_ref`` is present, ``definition_slug``/``version_no``/
    ``bundle_sha256`` must also be present and well-typed (a build result always
    carries them); a malformed build result raises :class:`ValueError` rather than
    being silently dropped. ``digest`` is optional (mapped to
    ``image_digest``)."""
    if not result_json:
        return None
    image_ref = _nonempty_str(result_json.get("image_ref"))
    if image_ref is None:
        return None

    definition_slug = result_json.get("definition_slug")
    version_no = result_json.get("version_no")
    bundle_sha256 = result_json.get("bundle_sha256")
    if not isinstance(definition_slug, str) or not definition_slug:
        raise ValueError(
            "build completion carries an image_ref but no definition_slug"
        )
    if not isinstance(version_no, int):
        raise ValueError("build completion carries an image_ref but no int version_no")
    if not isinstance(bundle_sha256, str) or not bundle_sha256:
        raise ValueError("build completion carries an image_ref but no bundle_sha256")

    # ``digest`` is the worker's key for the built image's content address; keep
    # ``None`` (not "") when absent so the registry write is cleanly skipped.
    image_digest = _nonempty_str(result_json.get("digest"))

    return BuildCompletion(
        definition_slug=definition_slug,
        version_no=version_no,
        image_ref=image_ref,
        bundle_sha256=bundle_sha256,
        image_digest=image_digest,
    )
